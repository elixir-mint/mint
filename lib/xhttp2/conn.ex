defmodule XHTTP2.Conn do
  use Bitwise, skip_operators: true

  import XHTTP.Util
  import XHTTP2.Frame, except: [encode: 1, decode_next: 1]

  alias XHTTP2.{
    Conn,
    Frame,
    HPACK
  }

  require Logger

  @behaviour XHTTP.ConnBehaviour

  ## Constants

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @default_window_size 65_535
  @max_window_size 2_147_483_647

  @default_max_frame_size 16_384
  @valid_max_frame_size_range @default_max_frame_size..16_777_215
  ## Connection

  defstruct [
    # Transport things.
    :transport,
    :transport_state,

    # Host things.
    :hostname,
    :port,
    :scheme,

    # Connection state (open, closed, and so on).
    :state,

    # Fields of the connection.
    buffer: "",
    window_size: @default_window_size,
    encode_table: HPACK.new(4096),
    decode_table: HPACK.new(4096),

    # Queue for sent PING frames.
    ping_queue: :queue.new(),

    # Queue for sent SETTINGS frames.
    client_settings_queue: :queue.new(),

    # Stream-set-related things.
    next_stream_id: 3,
    streams: %{},
    open_stream_count: 0,
    ref_to_stream_id: %{},

    # SETTINGS-related things for server.
    enable_push: true,
    server_max_concurrent_streams: 100,
    initial_window_size: @default_window_size,
    max_frame_size: @default_max_frame_size,

    # SETTINGS-related things for client.
    client_max_frame_size: @default_max_frame_size,
    client_max_concurrent_streams: 100,

    # Headers being processed (when headers are split into multiple frames with CONTINUATIONS, all
    # the continuation frames must come one right after the other).
    headers_being_processed: nil,

    # Private store
    private: %{}
  ]

  ## Types

  @type scheme :: :http | :https | module()
  @type request_ref() :: XHTTP.ConnBehaviour.request_ref()
  @type tcp_message() :: XHTTP.ConnBehaviour.tcp_message()
  @type response() :: XHTTP.ConnBehaviour.response()
  @type status() :: XHTTP.ConnBehaviour.response()
  @type headers() :: XHTTP.ConnBehaviour.headers()
  @type settings() :: keyword()
  @type stream_id() :: pos_integer()

  @opaque t() :: %Conn{
            transport: module(),
            transport_state: XHTTP.Transport.state(),
            state: :open | :closed | :went_away,
            buffer: binary(),
            window_size: pos_integer(),
            encode_table: HPACK.Table.t(),
            decode_table: HPACK.Table.t(),
            ping_queue: :queue.queue(),
            client_settings_queue: :queue.queue(),
            next_stream_id: stream_id(),
            streams: %{optional(stream_id()) => map()},
            open_stream_count: non_neg_integer(),
            ref_to_stream_id: %{optional(reference()) => stream_id()},
            enable_push: boolean(),
            server_max_concurrent_streams: non_neg_integer(),
            initial_window_size: pos_integer(),
            max_frame_size: pos_integer(),
            headers_being_processed: {stream_id(), iodata(), boolean()} | nil
          }

  ## Public interface
  @spec connect(scheme(), String.t(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def connect(scheme, hostname, port, opts \\ []) do
    transport = scheme_to_transport(scheme)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(transport_opts())

    with {:ok, transport_state} <-
           connect_and_negotiate_protocol(hostname, port, transport, transport_opts),
         do: initiate(transport, transport_state, hostname, port, opts)
  end

  @impl true
  @spec transport_opts() :: Keyword.t()
  def transport_opts() do
    [alpn_advertised_protocols: ["h2"]]
  end

  @impl true
  @spec open?(t()) :: boolean()
  def open?(%Conn{state: state}), do: state == :open

  @impl true
  @spec request(
          t(),
          method :: atom | String.t(),
          path :: String.t(),
          headers(),
          body :: iodata() | nil | :stream
        ) ::
          {:ok, t(), request_ref()}
          | {:error, t(), term()}
  def request(%Conn{} = conn, method, path, headers, body \\ nil)
      when is_binary(method) and is_binary(path) and is_list(headers) do
    headers = [
      {":method", method},
      {":path", path},
      {":scheme", conn.scheme},
      {":authority", "#{conn.hostname}:#{conn.port}"}
      | headers
    ]

    {conn, stream_id, ref} = open_stream(conn)

    conn =
      case body do
        :stream ->
          send_headers(conn, stream_id, headers, [:end_headers])

        nil ->
          send_headers(conn, stream_id, headers, [:end_stream, :end_headers])

        _iodata ->
          # TODO: Optimize here by sending a single packet on the network.
          conn = send_headers(conn, stream_id, headers, [:end_headers])
          conn = send_data(conn, stream_id, body, [:end_stream])
          conn
      end

    {:ok, conn, ref}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @impl true
  @spec stream_request_body(t(), request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(%Conn{} = conn, ref, chunk) when is_reference(ref) do
    stream_id = Map.fetch!(conn.ref_to_stream_id, ref)

    conn =
      if chunk == :eof do
        send_data(conn, stream_id, "", [:end_stream])
      else
        send_data(conn, stream_id, chunk, [])
      end

    {:ok, conn}
  end

  @spec ping(t(), <<_::8>>) :: {:ok, t(), request_ref()} | {:error, t(), term()}
  def ping(%Conn{} = conn, payload \\ :binary.copy(<<0>>, 8))
      when byte_size(payload) == 8 do
    {conn, ref} = send_ping(conn, payload)
    {:ok, conn, ref}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @spec put_settings(t(), keyword()) :: {:ok, t()} | {:error, t(), reason :: term()}
  def put_settings(%Conn{} = conn, settings) when is_list(settings) do
    conn = send_settings(conn, settings)
    {:ok, conn}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @spec get_setting(t(), atom()) :: term()
  def get_setting(%Conn{} = conn, name) do
    case name do
      :enable_push -> conn.enable_push
      :max_concurrent_streams -> conn.server_max_concurrent_streams
      :initial_window_size -> conn.initial_window_size
      :max_frame_size -> conn.max_frame_size
    end
  end

  @impl true
  @spec stream(t(), tcp_message()) ::
          {:ok, t(), [response()]}
          | {:error, t(), term(), [response()]}
          | :unknown
  def stream(conn, message)

  def stream(
        %Conn{transport_state: transport_state} = conn,
        {error_tag, transport_state, reason}
      )
      when error_tag in [:tcp_error, :ssl_error] do
    {:error, %{conn | state: :closed}, reason, []}
  end

  def stream(%Conn{transport_state: transport_state} = conn, {closed_tag, transport_state})
      when closed_tag in [:tcp_closed, :ssl_closed] do
    {:error, %{conn | state: :closed}, :closed, []}
  end

  def stream(
        %Conn{transport: transport, transport_state: transport_state} = conn,
        {tag, transport_state, data}
      )
      when tag in [:tcp, :ssl] do
    {conn, responses} = handle_new_data(conn, conn.buffer <> data, [])
    _ = transport.setopts(transport_state, active: :once)
    {:ok, conn, Enum.reverse(responses)}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error, []}
    :throw, {:xhttp, conn, error, responses} -> {:error, conn, error, responses}
  end

  def stream(%Conn{transport: transport, transport_state: transport_state}, _message) do
    _ = transport.setopts(transport_state, active: :once)
    :unknown
  end

  @doc """
  Assigns a new private key and value in the connection.

  This storage is meant to be used to associate metadata with the connection,
  it can be useful when handling multiple connections.
  """
  @impl true
  @spec put_private(t(), atom(), term()) :: t()
  def put_private(%Conn{private: private} = conn, key, value) when is_atom(key) do
    %{conn | private: Map.put(private, key, value)}
  end

  @doc """
  Get a value from the private store.

  Also see `put_private/3`.
  """
  @impl true
  @spec get_private(t(), atom(), term()) :: term()
  def get_private(%Conn{private: private}, key, default \\ nil) when is_atom(key) do
    Map.get(private, key, default)
  end

  @doc """
  Delete a value in the private store.

  Also see `put_private/3`.
  """
  @impl true
  @spec delete_private(t(), atom()) :: t()
  def delete_private(%Conn{private: private} = conn, key) when is_atom(key) do
    %{conn | private: Map.delete(private, key)}
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  # SETTINGS parameters are not negotiated. We keep client settings and server settings separate.
  @doc false
  @impl true
  @spec initiate(
          module(),
          XHTTP.Transport.state(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def initiate(transport, transport_state, hostname, port, opts) do
    client_settings_params = Keyword.get(opts, :client_settings, [])
    validate_settings!(client_settings_params)

    conn = %Conn{
      hostname: hostname,
      port: port,
      transport: transport,
      transport_state: transport_state,
      scheme: Keyword.get(opts, :scheme, "https"),
      state: :open
    }

    with :ok <- inet_opts(transport, transport_state),
         client_settings = settings(stream_id: 0, params: client_settings_params),
         preface = [@connection_preface, Frame.encode(client_settings)],
         {:ok, transport_state} <- transport.send(transport_state, preface),
         conn = update_in(conn.client_settings_queue, &:queue.in(client_settings_params, &1)),
         {:ok, server_settings, buffer, transport_state} <-
           receive_server_settings(transport, transport_state),
         server_settings_ack =
           settings(stream_id: 0, params: [], flags: set_flag(:settings, :ack)),
         {:ok, transport_state} <-
           transport.send(transport_state, Frame.encode(server_settings_ack)),
         conn = put_in(conn.buffer, buffer),
         conn = put_in(conn.transport_state, transport_state),
         conn = apply_server_settings(conn, settings(server_settings, :params)),
         :ok <- transport.setopts(transport_state, active: :once) do
      {:ok, conn}
    else
      error ->
        transport.close(transport_state)
        error
    end
  end

  ## Helpers

  defp connect_and_negotiate_protocol(hostname, port, transport, transport_opts) do
    with {:ok, transport_state} <- transport.connect(hostname, port, transport_opts),
         {:ok, protocol} <- transport.negotiated_protocol(transport_state) do
      if protocol == "h2" do
        {:ok, transport_state}
      else
        {:error, {:bad_alpn_protocol, protocol}}
      end
    end
  end

  defp receive_server_settings(transport, transport_state) do
    case recv_next_frame(transport, transport_state, _buffer = "") do
      {:ok, settings(), _buffer, _transport_state} = result -> result
      {:ok, _frame, _buffer} -> {:error, :protocol_error}
      {:error, _reason} = error -> error
    end
  end

  defp recv_next_frame(transport, transport_state, buffer) do
    case Frame.decode_next(buffer, @default_max_frame_size) do
      {:ok, frame, rest} ->
        {:ok, frame, rest, transport_state}

      :more ->
        with {:ok, data, transport_state} <- transport.recv(transport_state, 0) do
          recv_next_frame(transport, transport_state, buffer <> data)
        end

      {:error, {kind, _info}} when kind in [:frame_size_error, :protocol_error] ->
        {:error, kind}
    end
  end

  defp open_stream(%Conn{server_max_concurrent_streams: mcs} = conn) do
    if conn.open_stream_count >= mcs do
      throw({:xhttp, conn, {:max_concurrent_streams_reached, mcs}})
    end

    stream = %{
      id: conn.next_stream_id,
      ref: make_ref(),
      state: :idle,
      window_size: conn.initial_window_size
    }

    conn = put_in(conn.streams[stream.id], stream)
    conn = put_in(conn.ref_to_stream_id[stream.ref], stream.id)
    conn = update_in(conn.next_stream_id, &(&1 + 2))
    {conn, stream.id, stream.ref}
  end

  defp send_headers(conn, stream_id, headers, enabled_flags) do
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:idle])

    headers = Enum.map(headers, fn {name, value} -> {:store_name, name, value} end)
    {hbf, conn} = get_and_update_in(conn.encode_table, &HPACK.encode(headers, &1))

    payload = headers_to_encoded_frames(conn, stream_id, hbf, enabled_flags)
    conn = send!(conn, payload)

    stream_state = if :end_stream in enabled_flags, do: :half_closed_local, else: :open

    conn = put_in(conn.streams[stream_id].state, stream_state)
    conn = update_in(conn.open_stream_count, &(&1 + 1))
    conn
  end

  defp headers_to_encoded_frames(conn, stream_id, hbf, enabled_flags) do
    if IO.iodata_length(hbf) > conn.max_frame_size do
      hbf
      |> IO.iodata_to_binary()
      |> split_payload_in_chunks(conn.max_frame_size)
      |> split_hbf_to_encoded_frames(stream_id, enabled_flags)
    else
      Frame.encode(
        headers(stream_id: stream_id, hbf: hbf, flags: set_flags(:headers, enabled_flags))
      )
    end
  end

  defp split_hbf_to_encoded_frames({[first_chunk | chunks], last_chunk}, stream_id, enabled_flags) do
    flags = set_flags(:headers, enabled_flags -- [:end_headers])
    first_frame = Frame.encode(headers(stream_id: stream_id, hbf: first_chunk, flags: flags))

    middle_frames =
      Enum.map(chunks, fn chunk ->
        Frame.encode(continuation(stream_id: stream_id, hbf: chunk))
      end)

    flags =
      if :end_headers in enabled_flags do
        set_flag(:continuation, :end_headers)
      else
        0x00
      end

    last_frame = Frame.encode(continuation(stream_id: stream_id, hbf: last_chunk, flags: flags))

    [first_frame, middle_frames, last_frame]
  end

  defp send_data(conn, stream_id, data, enabled_flags) do
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:open])

    data_size = IO.iodata_length(data)

    cond do
      data_size >= stream.window_size ->
        throw({:xhttp, conn, {:exceeds_stream_window_size, stream.window_size}})

      data_size >= conn.window_size ->
        throw({:xhttp, conn, {:exceeds_connection_window_size, conn.window_size}})

      data_size > conn.max_frame_size ->
        {chunks, last_chunk} =
          data
          |> IO.iodata_to_binary()
          |> split_payload_in_chunks(conn.max_frame_size)

        conn =
          Enum.reduce(chunks, conn, fn chunk, acc ->
            send_data(acc, stream_id, chunk, [])
          end)

        send_data(conn, stream_id, last_chunk, enabled_flags)

      true ->
        frame = data(stream_id: stream_id, flags: set_flags(:data, enabled_flags), data: data)
        conn = send!(conn, Frame.encode(frame))
        conn = update_in(conn.streams[stream_id].window_size, &(&1 - data_size))
        conn = update_in(conn.window_size, &(&1 - data_size))

        conn =
          if :end_stream in enabled_flags do
            put_in(conn.streams[stream_id].state, :half_closed_local)
          else
            conn
          end

        conn
    end
  end

  defp split_payload_in_chunks(binary, chunk_size),
    do: split_payload_in_chunks(binary, chunk_size, [])

  defp split_payload_in_chunks(chunk, chunk_size, acc) when byte_size(chunk) <= chunk_size do
    {Enum.reverse(acc), chunk}
  end

  defp split_payload_in_chunks(binary, chunk_size, acc) do
    <<chunk::size(chunk_size)-binary, rest::binary>> = binary
    split_payload_in_chunks(rest, chunk_size, [chunk | acc])
  end

  defp send_ping(conn, payload) do
    frame = Frame.ping(stream_id: 0, opaque_data: payload)
    conn = send!(conn, Frame.encode(frame))
    ref = make_ref()
    conn = update_in(conn.ping_queue, &:queue.in({ref, payload}, &1))
    {conn, ref}
  end

  defp send_settings(conn, settings) do
    validate_settings!(settings)
    frame = settings(stream_id: 0, params: settings)
    conn = send!(conn, Frame.encode(frame))
    conn = update_in(conn.client_settings_queue, &:queue.in(settings, &1))
    conn
  end

  defp validate_settings!(settings) do
    unless Keyword.keyword?(settings) do
      raise ArgumentError, "settings must be a keyword list"
    end

    Enum.each(settings, fn
      {:header_table_size, value} ->
        unless is_integer(value) do
          raise ArgumentError, ":header_table_size must be an integer, got: #{inspect(value)}"
        end

      {:enable_push, value} ->
        case value do
          true ->
            raise ArgumentError,
                  "push promises are not supported yet, so :enable_push must be false"

          false ->
            :ok

          _other ->
            raise ArgumentError, ":enable_push must be a boolean, got: #{inspect(value)}"
        end

      {:max_concurrent_streams, value} ->
        unless is_integer(value) do
          raise ArgumentError,
                ":max_concurrent_streams must be an integer, got: #{inspect(value)}"
        end

      {:initial_window_size, value} ->
        unless is_integer(value) and value <= @max_window_size do
          raise ArgumentError,
                ":initial_window_size must be an integer < #{@max_window_size}, " <>
                  "got: #{inspect(value)}"
        end

      {:max_frame_size, value} ->
        unless is_integer(value) and value in @valid_max_frame_size_range do
          raise ArgumentError,
                ":max_frame_size must be an integer in #{inspect(@valid_max_frame_size_range)}, " <>
                  "got: #{inspect(value)}"
        end

      {:max_header_list_size, value} ->
        unless is_integer(value) do
          raise ArgumentError, ":max_header_list_size must be an integer, got: #{inspect(value)}"
        end

      {name, _value} ->
        raise ArgumentError, "unknown setting parameter #{inspect(name)}"
    end)
  end

  ## Frame handling

  defp handle_new_data(%Conn{} = conn, data, responses) do
    case Frame.decode_next(data, conn.client_max_frame_size) do
      {:ok, frame, rest} ->
        Logger.debug(fn -> "Got frame: #{inspect(frame)}" end)
        assert_valid_frame(conn, frame)
        {conn, responses} = handle_frame(conn, frame, responses)
        handle_new_data(conn, rest, responses)

      :more ->
        {%{conn | buffer: data}, responses}

      {:error, :payload_too_big} ->
        # TODO: sometimes, this could be handled with RST_STREAM instead of a GOAWAY frame (for
        # example, if the payload of a DATA frame is too big).
        # http://httpwg.org/specs/rfc7540.html#rfc.section.4.2
        debug_data = "frame payload exceeds connection's max frame size"
        send_connection_error!(conn, :frame_size_error, debug_data)

      {:error, {:frame_size_error, frame}} ->
        debug_data = "error with size of frame: #{inspect(frame)}"
        send_connection_error!(conn, :frame_size_error, debug_data)

      {:error, {:protocol_error, info}} ->
        debug_data = "error when decoding frame: #{inspect(info)}"
        send_connection_error!(conn, :protocol_error, debug_data)
    end
  catch
    :throw, {:xhttp, conn, error} ->
      throw({:xhttp, conn, error, responses})
  end

  defp assert_valid_frame(conn, frame) do
    assert_frame_on_right_level(conn, elem(frame, 0), elem(frame, 1))
    assert_frame_doesnt_interrupt_header_streaming(conn, frame)
  end

  # http://httpwg.org/specs/rfc7540.html#HttpSequence
  defp assert_frame_doesnt_interrupt_header_streaming(conn, frame) do
    case {conn.headers_being_processed, frame} do
      {nil, continuation()} ->
        debug_data = "CONTINUATION received outside of headers streaming"
        send_connection_error!(conn, :protocol_error, debug_data)

      {nil, _frame} ->
        :ok

      {{stream_id, _, _}, continuation(stream_id: stream_id)} ->
        :ok

      _other ->
        debug_data = "headers are streaming but got a frame that is not related to that"
        send_connection_error!(conn, :protocol_error, debug_data)
    end
  end

  stream_level_frames = [:data, :headers, :priority, :rst_stream, :push_promise, :continuation]
  connection_level_frames = [:settings, :ping, :goaway]

  defp assert_frame_on_right_level(conn, frame, 0)
       when frame in unquote(stream_level_frames) do
    debug_data = "frame #{frame} not allowed at the connection level (stream_id = 0)"
    send_connection_error!(conn, :protocol_error, debug_data)
  end

  defp assert_frame_on_right_level(conn, frame, stream_id)
       when frame in unquote(connection_level_frames) and stream_id != 0 do
    debug_data = "frame #{frame} only allowed at the connection level"
    send_connection_error!(conn, :protocol_error, debug_data)
  end

  defp assert_frame_on_right_level(_conn, _frame, _stream_id) do
    :ok
  end

  defp handle_frame(conn, data() = frame, resps), do: handle_data(conn, frame, resps)

  defp handle_frame(conn, headers() = frame, resps), do: handle_headers(conn, frame, resps)

  defp handle_frame(conn, priority() = frame, resps), do: handle_priority(conn, frame, resps)

  defp handle_frame(conn, rst_stream() = frame, resps), do: handle_rst_stream(conn, frame, resps)

  defp handle_frame(conn, settings() = frame, resps), do: handle_settings(conn, frame, resps)

  # TODO: implement PUSH_PROMISE
  defp handle_frame(_, push_promise(), _resps), do: raise("PUSH_PROMISE handling not implemented")

  defp handle_frame(conn, Frame.ping() = frame, resps), do: handle_ping(conn, frame, resps)

  defp handle_frame(conn, goaway() = frame, resps), do: handle_goaway(conn, frame, resps)

  defp handle_frame(conn, window_update() = frame, resps),
    do: handle_window_update(conn, frame, resps)

  defp handle_frame(conn, continuation() = frame, resps),
    do: handle_continuation(conn, frame, resps)

  # DATA

  defp handle_data(conn, frame, responses) do
    data(stream_id: stream_id, flags: flags, data: data, padding: padding) = frame
    stream = fetch_stream!(conn, stream_id)

    assert_stream_in_state(conn, stream, [:open, :half_closed_local])

    conn = refill_client_windows(conn, stream_id, byte_size(data) + byte_size(padding || ""))

    responses = [{:data, stream.ref, data} | responses]

    if flag_set?(flags, :data, :end_stream) do
      conn = put_in(conn.streams[stream_id].state, :half_closed_remote)
      conn = update_in(conn.open_stream_count, &(&1 - 1))
      {conn, [{:done, stream.ref} | responses]}
    else
      {conn, responses}
    end
  end

  defp refill_client_windows(conn, stream_id, data_size) do
    connection_frame = window_update(stream_id: 0, window_size_increment: data_size)
    stream_frame = window_update(stream_id: stream_id, window_size_increment: data_size)
    send!(conn, [Frame.encode(connection_frame), Frame.encode(stream_frame)])
  end

  # HEADERS

  defp handle_headers(conn, frame, responses) do
    headers(stream_id: stream_id, flags: flags, hbf: hbf) = frame
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:open, :half_closed_local])
    end_stream? = flag_set?(flags, :headers, :end_stream)

    if flag_set?(flags, :headers, :end_headers) do
      decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?)
    else
      conn = put_in(conn.headers_being_processed, {stream_id, hbf, end_stream?})
      {conn, responses}
    end
  end

  defp decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?) do
    case decode_hbf(conn, hbf) do
      {:ok, status, headers, conn} ->
        responses = [{:headers, stream.ref, headers}, {:status, stream.ref, status} | responses]

        if end_stream? do
          conn = put_in(conn.streams[stream.id].state, :half_closed_remote)
          conn = update_in(conn.open_stream_count, &(&1 - 1))
          {conn, [{:done, stream.ref} | responses]}
        else
          {conn, responses}
        end

      # http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.6
      {:error, :missing_status_header, conn} ->
        conn = close_stream!(conn, stream.id, :protocol_error)
        reason = {:protocol_error, :missing_status_header}
        responses = [{:error, stream.ref, reason} | responses]
        {conn, responses}
    end
  end

  defp decode_hbf(conn, hbf) do
    case HPACK.decode(hbf, conn.decode_table) do
      {:ok, headers, decode_table} ->
        conn = put_in(conn.decode_table, decode_table)

        case headers do
          [{":status", status} | headers] -> {:ok, String.to_integer(status), headers, conn}
          _other -> {:error, :missing_status_header, conn}
        end

      {:error, reason} ->
        debug_data = "unable to decode headers: #{inspect(reason)}"
        send_connection_error!(conn, :compression_error, debug_data)
    end
  end

  # PRIORITY

  defp handle_priority(conn, frame, responses) do
    Logger.warn(fn -> "Ignoring PRIORITY frame: #{inspect(frame)}" end)
    {conn, responses}
  end

  # RST_STREAM

  defp handle_rst_stream(conn, frame, responses) do
    rst_stream(stream_id: stream_id, error_code: error_code) = frame
    stream = fetch_stream!(conn, stream_id)
    conn = put_in(conn.streams[stream_id].state, :closed)
    {conn, [{:error, stream.ref, {:rst_stream, error_code}} | responses]}
  end

  # SETTINGS

  defp handle_settings(conn, frame, responses) do
    settings(flags: flags, params: params) = frame

    if flag_set?(flags, :settings, :ack) do
      {{:value, params}, conn} = get_and_update_in(conn.client_settings_queue, &:queue.out/1)
      conn = apply_client_settings(conn, params)
      {conn, responses}
    else
      conn = apply_server_settings(conn, params)
      frame = settings(flags: set_flag(:settings, :ack), params: [])
      conn = send!(conn, Frame.encode(frame))
      {conn, responses}
    end
  end

  defp apply_server_settings(conn, server_settings) do
    Enum.reduce(server_settings, conn, fn
      {:header_table_size, header_table_size}, conn ->
        update_in(conn.encode_table, &HPACK.resize(&1, header_table_size))

      {:enable_push, enable_push?}, conn ->
        put_in(conn.enable_push, enable_push?)

      {:max_concurrent_streams, max_concurrent_streams}, conn ->
        put_in(conn.server_max_concurrent_streams, max_concurrent_streams)

      {:initial_window_size, initial_window_size}, conn ->
        if initial_window_size > @max_window_size do
          debug_data = "INITIAL_WINDOW_SIZE setting parameter is too big"
          send_connection_error!(conn, :flow_control_error, debug_data)
        end

        update_initial_window_size(conn, initial_window_size)

      {:max_frame_size, max_frame_size}, conn ->
        if max_frame_size not in @valid_max_frame_size_range do
          debug_data = "MAX_FRAME_SIZE setting parameter outside of allowed range"
          send_connection_error!(conn, :protocol_error, debug_data)
        end

        put_in(conn.max_frame_size, max_frame_size)

      {:max_header_list_size, max_header_list_size}, conn ->
        Logger.debug(fn ->
          "Ignoring MAX_HEADERS_LIST_SIZE parameter with value #{max_header_list_size}"
        end)

        conn
    end)
  end

  defp apply_client_settings(conn, client_settings) do
    Enum.reduce(client_settings, conn, fn
      {:max_frame_size, value}, conn ->
        put_in(conn.client_max_frame_size, value)

      {:max_concurrent_streams, value}, conn ->
        put_in(conn.client_max_concurrent_streams, value)
    end)
  end

  defp update_initial_window_size(conn, new_iws) do
    diff = new_iws - conn.initial_window_size

    conn =
      update_in(conn.streams, fn streams ->
        for {stream_id, stream} <- streams,
            stream.state in [:open, :half_closed_remote],
            into: streams do
          window_size = stream.window_size + diff

          if window_size > @max_window_size do
            debug_data = "INITIAL_WINDOW_SIZE setting parameter makes some window sizes too big"
            send_connection_error!(conn, :flow_control_error, debug_data)
          end

          {stream_id, %{stream | window_size: window_size}}
        end
      end)

    put_in(conn.initial_window_size, new_iws)
  end

  # PING

  defp handle_ping(conn, Frame.ping() = frame, responses) do
    Frame.ping(flags: flags, opaque_data: opaque_data) = frame

    if flag_set?(flags, :ping, :ack) do
      handle_ping_ack(conn, opaque_data, responses)
    else
      ack = Frame.ping(stream_id: 0, flags: set_flag(:ping, :ack), opaque_data: opaque_data)
      conn = send!(conn, Frame.encode(ack))
      {conn, responses}
    end
  end

  defp handle_ping_ack(conn, opaque_data, responses) do
    case :queue.out(conn.ping_queue) do
      {{:value, {ref, ^opaque_data}}, ping_queue} ->
        conn = put_in(conn.ping_queue, ping_queue)
        {conn, [{:pong, ref} | responses]}

      {{:value, _}, _} ->
        Logger.error("Received PING ack that doesn't match next PING request in the queue")
        throw({:xhttp, conn, :protocol_error, responses})

      {:empty, _ping_queue} ->
        Logger.error("Received PING ack but no PING requests had been sent")
        throw({:xhttp, conn, :protocol_error, responses})
    end
  end

  # GOAWAY

  defp handle_goaway(conn, frame, responses) do
    goaway(
      last_stream_id: last_stream_id,
      error_code: error_code,
      debug_data: debug_data
    ) = frame

    unprocessed_stream_ids = Enum.filter(conn.streams, fn {id, _} -> id > last_stream_id end)

    {conn, responses} =
      Enum.reduce(unprocessed_stream_ids, {conn, responses}, fn {id, stream}, {conn, responses} ->
        conn = update_in(conn.streams, &Map.delete(&1, id))
        conn = update_in(conn.open_stream_count, &(&1 - 1))
        conn = update_in(conn.ref_to_stream_id, &Map.delete(&1, stream.ref))
        conn = put_in(conn.state, :went_away)
        response = {:error, stream.ref, {:goaway, error_code, debug_data}}
        {conn, [response | responses]}
      end)

    {conn, responses}
  end

  # WINDOW_UPDATE

  defp handle_window_update(
         conn,
         window_update(stream_id: 0, window_size_increment: wsi),
         responses
       ) do
    case conn.window_size do
      ws when ws + wsi > @max_window_size ->
        send_connection_error!(conn, :flow_control_error, "window size too big")

      ws ->
        conn = put_in(conn.window_size, ws)
        {conn, responses}
    end
  end

  defp handle_window_update(
         conn,
         window_update(stream_id: stream_id, window_size_increment: wsi),
         responses
       ) do
    stream = fetch_stream!(conn, stream_id)

    case conn.streams[stream_id].window_size do
      ws when ws + wsi > @max_window_size ->
        conn = close_stream!(conn, stream_id, :flow_control_error)
        {conn, [{:error, stream.ref, :flow_control_error} | responses]}

      ws ->
        conn = put_in(conn.streams[stream_id].window_size, ws + wsi)
        {conn, responses}
    end
  end

  # CONTINUATION

  defp handle_continuation(conn, frame, responses) do
    continuation(stream_id: stream_id, flags: flags, hbf: hbf_chunk) = frame
    stream = fetch_stream!(conn, stream_id)

    {^stream_id, hbf_acc, end_stream?} = conn.headers_being_processed

    if flag_set?(flags, :continuation, :end_headers) do
      hbf = IO.iodata_to_binary([hbf_acc, hbf_chunk])
      decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?)
    else
      conn = put_in(conn.headers_being_processed, {stream_id, [hbf_acc, hbf_chunk], end_stream?})
      {conn, responses}
    end
  end

  ## General helpers

  defp send_connection_error!(conn, error_code, debug_data) do
    frame =
      goaway(stream_id: 0, last_stream_id: 2, error_code: error_code, debug_data: debug_data)

    conn = send!(conn, Frame.encode(frame))
    {:ok, transport_state} = conn.transport.close(conn.transport_state)
    conn = put_in(conn.state, :closed)
    conn = put_in(conn.transport_state, transport_state)
    throw({:xhttp, conn, error_code})
  end

  defp close_stream!(conn, stream_id, error_code) do
    frame = rst_stream(stream_id: stream_id, error_code: error_code)
    conn = send!(conn, Frame.encode(frame))
    put_in(conn.streams[stream_id].state, :closed)
  end

  defp fetch_stream!(conn, stream_id) do
    case Map.fetch(conn.streams, stream_id) do
      {:ok, stream} -> stream
      :error -> throw({:xhttp, conn, {:stream_not_found, stream_id}})
    end
  end

  defp assert_stream_in_state(conn, %{state: state}, expected_states) do
    if state not in expected_states do
      throw({:xhttp, conn, {:stream_not_in_expected_state, expected_states, state}})
    end
  end

  defp send!(%Conn{transport: transport, transport_state: transport_state} = conn, bytes) do
    case transport.send(transport_state, bytes) do
      {:ok, transport_state} -> put_in(conn.transport_state, transport_state)
      {:error, :closed} -> throw({:xhttp, %{conn | state: :closed}, :closed})
      {:error, reason} -> throw({:xhttp, conn, reason})
    end
  end
end
