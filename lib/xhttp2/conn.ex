defmodule XHTTP2.Conn do
  use Bitwise, skip_operators: true

  import XHTTP2.Frame, except: [encode: 1, decode_next: 1]

  alias XHTTP2.{
    Frame,
    HPACK
  }

  require Logger

  ## Constants

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @default_window_size 65_535
  @max_window_size 2_147_483_647

  @default_max_frame_size 16_384
  @valid_max_frame_size_range @default_max_frame_size..16_777_215

  @forced_transport_opts [
    packet: :raw,
    mode: :binary,
    active: false,
    alpn_advertised_protocols: ["h2"]
  ]

  ## Connection

  defstruct [
    # Transport things.
    :transport,
    :socket,

    # Host things.
    :hostname,
    :port,
    :scheme,

    # Connection state (open, closed, and so on).
    :state,

    # Settings set from the user.
    :client_settings,

    # Fields of the connection.
    buffer: "",
    window_size: @default_window_size,
    encode_table: HPACK.new(4096),
    decode_table: HPACK.new(4096),

    # Queue for sent PING frames.
    ping_queue: :queue.new(),

    # Stream-set-related things.
    next_stream_id: 3,
    streams: %{},
    open_stream_count: 0,
    ref_to_stream_id: %{},

    # SETTINGS-related things.
    enable_push: true,
    server_max_concurrent_streams: 100,
    initial_window_size: @default_window_size,
    max_frame_size: @default_max_frame_size,

    # Headers being processed (when headers are split into multiple frames with CONTINUATIONS, all
    # the continuation frames must come one right after the other).
    headers_being_processed: nil
  ]

  ## Types

  @type settings() :: Keyword.t()
  @type request_id() :: reference()
  @type stream_id() :: pos_integer()

  @opaque t() :: %__MODULE__{
            transport: module(),
            socket: term(),
            state: :open | :closed | :went_away,
            client_settings: settings(),
            buffer: binary(),
            window_size: pos_integer(),
            encode_table: HPACK.Table.t(),
            decode_table: HPACK.Table.t(),
            ping_queue: :queue.queue(),
            next_stream_id: stream_id(),
            streams: %{optional(stream_id()) => map()},
            open_stream_count: non_neg_integer(),
            ref_to_stream_id: %{optional(reference()) => stream_id()},
            enable_push: boolean(),
            server_max_concurrent_streams: non_neg_integer(),
            initial_window_size: pos_integer(),
            max_frame_size: pos_integer()
          }

  ## Public interface

  @spec connect(String.t(), :inet.port_number(), Keyword.t()) :: {:ok, t()} | {:error, term()}
  def connect(hostname, port, opts \\ []) do
    transport = Keyword.get(opts, :transport, :ssl)
    scheme = Keyword.get(opts, :scheme, "https")

    if transport not in [:gen_tcp, :ssl] do
      raise ArgumentError,
            "the :transport option must be either :gen_tcp or :ssl, got: #{inspect(transport)}"
    end

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@forced_transport_opts)

    with {:ok, socket} <-
           connect_and_negotiate_protocol(hostname, port, transport, transport_opts),
         :ok <- set_inet_opts(transport, socket),
         {:ok, conn} <- initiate_connection(transport, socket, opts) do
      conn = %{conn | hostname: hostname, port: port, scheme: scheme}
      {:ok, conn}
    else
      {:error, reason} ->
        {:error, {:connect, reason}}
    end
  end

  @spec open?(t()) :: boolean()
  def open?(%__MODULE__{state: state}), do: state == :open

  @spec request(t(), String.t(), String.t(), list(), iodata() | nil) ::
          {:ok, t(), request_id()} | {:error, t(), term()}
  def request(%__MODULE__{} = conn, method, path, headers, body \\ nil)
      when is_binary(method) and is_binary(path) and is_list(headers) do
    headers = [
      {":method", method},
      {":path", path},
      {":scheme", conn.scheme},
      {":authority", "#{conn.hostname}:#{conn.port}"}
      | headers
    ]

    {conn, stream_id, ref} = open_stream(conn)

    if body do
      # TODO: Optimize here by sending a single packet on the network.
      conn = send_headers(conn, stream_id, headers, [:end_headers])
      conn = send_data(conn, stream_id, body, [:end_stream])
      {:ok, conn, ref}
    else
      conn = send_headers(conn, stream_id, headers, [:end_stream, :end_headers])
      {:ok, conn, ref}
    end
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @spec ping(t(), <<_::8>>) :: {:ok, t(), request_id()} | {:error, t(), term()}
  def ping(%__MODULE__{} = conn, payload \\ :binary.copy(<<0>>, 8)) when byte_size(payload) == 8 do
    {conn, ref} = send_ping(conn, payload)
    {:ok, conn, ref}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @spec stream(t(), term()) ::
          {:ok, t(), [response]}
          | {:error, t(), reason :: term(), [response]}
          | :unknown
        when response: term()
  def stream(conn, message)

  def stream(%__MODULE__{socket: socket} = conn, {error_tag, socket, reason})
      when error_tag in [:tcp_error, :ssl_error] do
    {:error, %{conn | state: :closed}, reason, []}
  end

  def stream(%__MODULE__{socket: socket} = conn, {closed_tag, socket})
      when closed_tag in [:tcp_closed, :ssl_closed] do
    {:error, %{conn | state: :closed}, :closed, []}
  end

  def stream(%__MODULE__{socket: socket} = conn, {tag, socket, data}) when tag in [:tcp, :ssl] do
    {conn, responses} = handle_new_data(conn, conn.buffer <> data, [])
    {:ok, conn, Enum.reverse(responses)}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error, []}
    :throw, {:xhttp, conn, error, responses} -> {:error, conn, error, responses}
  end

  def stream(%__MODULE__{}, _message) do
    :unknown
  end

  ## Helpers

  defp connect_and_negotiate_protocol(hostname, port, transport, transport_opts) do
    with {:ok, socket} <- transport.connect(String.to_charlist(hostname), port, transport_opts),
         {:ok, protocol} <- transport.negotiated_protocol(socket) do
      if protocol == "h2" do
        {:ok, socket}
      else
        {:error, {:bad_alpn_protocol, protocol}}
      end
    end
  end

  defp set_inet_opts(transport, socket) do
    inet = transport_to_inet(transport)

    with {:ok, opts} <- inet.getopts(socket, [:sndbuf, :recbuf, :buffer]) do
      buffer =
        Keyword.fetch!(opts, :buffer)
        |> max(Keyword.fetch!(opts, :sndbuf))
        |> max(Keyword.fetch!(opts, :recbuf))

      inet.setopts(socket, buffer: buffer)
    end
  end

  defp transport_to_inet(:gen_tcp), do: :inet
  defp transport_to_inet(:ssl), do: :ssl

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  # SETTINGS parameters are not negotiated. We keep client settings and server settings separate.
  defp initiate_connection(transport, socket, opts) do
    client_settings_params = Keyword.get(opts, :client_settings, [])
    client_settings = settings(stream_id: 0, params: client_settings_params)
    server_settings_ack = settings(stream_id: 0, params: [], flags: set_flag(:settings, :ack))

    with :ok <- transport.send(socket, [@connection_preface, Frame.encode(client_settings)]),
         {:ok, server_settings, buffer} <- receive_server_settings(transport, socket),
         :ok <- transport.send(socket, Frame.encode(server_settings_ack)) do
      conn =
        %__MODULE__{
          state: :open,
          transport: transport,
          socket: socket,
          buffer: buffer
        }
        |> apply_server_settings(settings(server_settings, :params))

      with {:ok, conn} <- receive_client_settings_ack(conn, client_settings_params),
           :ok <- transport_to_inet(transport).setopts(socket, active: true),
           do: {:ok, conn}
    end
  end

  defp receive_server_settings(transport, socket) do
    case recv_next_frame(transport, socket, _buffer = "") do
      {:ok, settings(), _buffer} = result -> result
      {:ok, _frame, _buffer} -> {:error, :protocol_error}
      {:error, _reason} = error -> error
    end
  end

  defp receive_client_settings_ack(%__MODULE__{} = conn, client_settings) do
    case recv_next_frame(conn.transport, conn.socket, conn.buffer) do
      {:ok, settings(flags: flags), buffer} ->
        if flag_set?(flags, :settings, :ack) do
          {:ok, %{conn | client_settings: client_settings, buffer: buffer}}
        else
          {:error, :protocol_error}
        end

      {:ok, window_update(stream_id: 0, window_size_increment: wsi), buffer} ->
        # TODO: handle window size increments that are too big.
        conn = update_in(conn.window_size, &(&1 + wsi))
        receive_client_settings_ack(%{conn | buffer: buffer}, client_settings)

      {:ok, window_update(), _buffer} ->
        {:error, :protocol_error}

      {:ok, goaway() = frame, _buffer} ->
        {:error, {:goaway, frame}}

      {:error, _reason} = error ->
        error
    end
  end

  defp recv_next_frame(transport, socket, buffer) do
    case Frame.decode_next(buffer) do
      {:ok, _frame, _rest} = result ->
        result

      {:error, {:malformed_frame, _}} ->
        with {:ok, data} <- transport.recv(socket, 0) do
          recv_next_frame(transport, socket, buffer <> data)
        end

      {:error, _reason} ->
        {:error, :protocol_error}
    end
  end

  defp open_stream(%__MODULE__{server_max_concurrent_streams: mcs} = conn) do
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
    assert_stream_in_state!(stream, :idle)

    headers = Enum.map(headers, fn {name, value} -> {:store_name, name, value} end)
    {hbf, encode_table} = HPACK.encode(headers, conn.encode_table)
    frame = headers(stream_id: stream_id, hbf: hbf, flags: set_flags(:headers, enabled_flags))
    transport_send!(conn, Frame.encode(frame))

    stream_state = if :end_stream in enabled_flags, do: :half_closed_local, else: :open

    conn = put_in(conn.streams[stream_id].state, stream_state)
    conn = put_in(conn.encode_table, encode_table)
    conn = update_in(conn.open_stream_count, &(&1 + 1))
    conn
  end

  defp send_data(conn, stream_id, data, enabled_flags) do
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state!(stream, :open)

    data_size = byte_size(data)

    cond do
      data_size >= stream.window_size ->
        throw({:xhttp, conn, {:exceeds_stream_window_size, stream.window_size}})

      data_size >= conn.window_size ->
        throw({:xhttp, conn, {:exceeds_connection_window_size, conn.window_size}})

      true ->
        frame = data(stream_id: stream_id, flags: set_flags(:data, enabled_flags), data: data)
        transport_send!(conn, Frame.encode(frame))
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

  defp send_ping(conn, payload) do
    frame = Frame.ping(stream_id: 0, opaque_data: payload)
    transport_send!(conn, Frame.encode(frame))
    ref = make_ref()
    conn = update_in(conn.ping_queue, &:queue.in({ref, payload}, &1))
    {conn, ref}
  end

  ## Frame handling

  defp handle_new_data(%__MODULE__{} = conn, data, responses) do
    case Frame.decode_next(data) do
      {:ok, frame, rest} ->
        Logger.debug(fn -> "Got frame: #{inspect(frame)}" end)
        assert_valid_frame!(conn, frame)
        {conn, responses} = handle_frame(conn, frame, responses)
        handle_new_data(conn, rest, responses)

      {:error, {:malformed_frame, _}} ->
        {%{conn | buffer: data}, responses}

      {:error, _reason} ->
        conn = put_in(conn.state, :closed)
        # TODO: sometimes this should be FRAME_SIZE_ERROR.
        throw({:xhttp, conn, :protocol_error, responses})
    end
  catch
    :throw, {:xhttp, conn, error} ->
      throw({:xhttp, conn, error, responses})
  end

  defp assert_valid_frame!(conn, frame) do
    if conn.headers_being_processed && not match?(continuation(), frame) do
      debug_data = "headers are streaming but got a non-CONTINUATION frame"
      send_connection_error!(conn, :protocol_error, debug_data)
    end
  end

  defp handle_frame(conn, data() = frame, resps), do: handle_data(conn, frame, resps)

  defp handle_frame(conn, headers() = frame, resps), do: handle_headers(conn, frame, resps)

  # TODO: implement PRIORITY
  defp handle_frame(_, priority(), _resps), do: raise("PRIORITY handling not implemented")

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
    # TODO: refill window_size here.

    data(stream_id: stream_id, flags: flags, data: data) = frame
    stream = fetch_stream!(conn, stream_id)

    if stream.state not in [:open, :half_closed_local] do
      raise "don't know how to handle DATA on streams with state #{inspect(stream.state)}"
    end

    responses = [{:data, stream.ref, data} | responses]

    if flag_set?(flags, :data, :end_stream) do
      conn = put_in(conn.streams[stream_id].state, :half_closed_remote)
      conn = update_in(conn.open_stream_count, &(&1 - 1))
      {conn, [{:done, stream.ref} | responses]}
    else
      {conn, responses}
    end
  end

  # HEADERS

  defp handle_headers(conn, frame, responses) do
    headers(stream_id: stream_id, flags: flags, hbf: hbf) = frame
    stream = fetch_stream!(conn, stream_id)

    end_headers? = flag_set?(flags, :headers, :end_headers)
    end_stream? = flag_set?(flags, :headers, :end_stream)

    if stream.state not in [:open, :half_closed_local] do
      raise "don't know how to handle HEADERS on streams with state #{inspect(stream.state)}"
    end

    {conn, responses} =
      if end_headers? do
        decode_headers!(conn, responses, stream, hbf)
      else
        conn = put_in(conn.headers_being_processed, {stream_id, hbf, end_stream?})
        {conn, responses}
      end

    stream_ref = stream.ref

    # TODO: make this horror better.
    {conn, responses} =
      cond do
        match?([{:closed, ^stream_ref, _} | _], responses) ->
          {conn, responses}

        end_stream? and end_headers? ->
          conn = put_in(conn.streams[stream_id].state, :half_closed_remote)
          conn = update_in(conn.open_stream_count, &(&1 - 1))
          {conn, [{:done, stream.ref} | responses]}

        true ->
          {conn, responses}
      end

    {conn, responses}
  end

  defp decode_headers!(conn, responses, stream, hbf) do
    case HPACK.decode(hbf, conn.decode_table) do
      {:ok, [{":status", status} | headers], decode_table} ->
        conn = put_in(conn.decode_table, decode_table)
        {conn, [{:headers, stream.ref, headers}, {:status, stream.ref, status} | responses]}

      {:ok, _headers, decode_table} ->
        conn = put_in(conn.decode_table, decode_table)

        # http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.6
        frame = rst_stream(stream_id: stream.id, error_code: :protocol_error)
        transport_send!(conn, Frame.encode(frame))
        conn = put_in(conn.streams[stream.id].state, :closed)
        {conn, [{:closed, stream.ref, {:protocol_error, :missing_status_header}} | responses]}

      {:error, reason} ->
        debug_data = "unable to decode headers: #{inspect(reason)}"
        send_connection_error!(conn, :compression_error, debug_data)
    end
  end

  # RST_STREAM

  defp handle_rst_stream(
         conn,
         rst_stream(stream_id: stream_id, error_code: error_code),
         responses
       ) do
    stream = fetch_stream!(conn, stream_id)
    conn = put_in(conn.streams[stream_id].state, :closed)
    {conn, [{:closed, stream.ref, {:rst_stream, error_code}} | responses]}
  end

  # SETTINGS

  defp handle_settings(conn, frame, responses) do
    settings(flags: flags, params: params) = frame

    if flag_set?(flags, :settings, :ack) do
      # TODO: handle this.
      raise "don't know how to handle SETTINGS acks yet"
    else
      conn = apply_server_settings(conn, params)
      ack = settings(flags: set_flag(:settings, :ack))
      transport_send!(conn, Frame.encode(ack))
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

        # TODO: update open streams
        put_in(conn.initial_window_size, initial_window_size)

      {:max_frame_size, max_frame_size}, conn ->
        if max_frame_size not in @valid_max_frame_size_range do
          debug_data = "MAX_FRAME_SIZE setting parameter outside of allowed range"
          send_connection_error!(conn, :protocol_error, debug_data)
        end

        # TODO: put this into effect
        put_in(conn.max_frame_size, max_frame_size)

      {:max_header_list_size, max_header_list_size}, conn ->
        Logger.warn(fn ->
          "Ignoring MAX_HEADERS_LIST_SIZE parameter with value #{max_header_list_size}"
        end)

        conn
    end)
  end

  # PING

  defp handle_ping(conn, Frame.ping(flags: flags, opaque_data: opaque_data), responses) do
    if flag_set?(flags, :ping, :ack) do
      handle_ping_ack(conn, opaque_data, responses)
    else
      ack = Frame.ping(stream_id: 0, flags: set_flag(:ping, :ack), opaque_data: opaque_data)
      transport_send!(conn, Frame.encode(ack))
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
    goaway(last_stream_id: last_stream_id, error_code: error_code, debug_data: debug_data) = frame

    unprocessed_stream_ids = Enum.filter(conn.streams, fn {id, _} -> id > last_stream_id end)

    {conn, responses} =
      Enum.reduce(unprocessed_stream_ids, {conn, responses}, fn {id, stream}, {conn, responses} ->
        conn = update_in(conn.streams, &Map.delete(&1, id))
        conn = update_in(conn.open_stream_count, &(&1 - 1))
        conn = update_in(conn.ref_to_stream_id, &Map.delete(&1, stream.ref))
        conn = put_in(conn.state, :went_away)
        response = {:closed, stream.ref, {:goaway, error_code, debug_data}}
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
        frame = rst_stream(stream_id: stream_id, error_code: :flow_control_error)
        transport_send!(conn, Frame.encode(frame))
        {conn, [{:closed, stream.ref, :flow_control_error} | responses]}

      ws ->
        conn = put_in(conn.streams[stream_id].window_size, ws + wsi)
        {conn, responses}
    end
  end

  # CONTINUATION

  defp handle_continuation(conn, frame, responses) do
    continuation(stream_id: stream_id, flags: flags, hbf: hbf) = frame
    stream = fetch_stream!(conn, stream_id)

    case conn.headers_being_processed do
      {^stream_id, hbf_acc, end_stream?} ->
        end_headers? = flag_set?(flags, :continuation, :end_headers)

        {conn, responses} =
          if end_headers? do
            decode_headers!(conn, responses, stream, hbf_acc <> hbf)
          else
            conn = put_in(conn.headers_being_processed, {stream_id, hbf_acc <> hbf, end_stream?})
            {conn, responses}
          end

        if end_stream? and end_headers? do
          {conn, [{:done, stream.ref} | responses]}
        else
          {conn, responses}
        end

      _other ->
        debug_data = "CONTINUATION received outside of headers streaming"
        send_connection_error!(conn, :protocol_error, debug_data)
    end
  end

  ## General helpers

  defp send_connection_error!(conn, error_code, debug_data) do
    frame =
      goaway(stream_id: 0, last_stream_id: 2, error_code: error_code, debug_data: debug_data)

    transport_send!(conn, Frame.encode(frame))
    conn.transport.close(conn.socket)
    conn = put_in(conn.state, :closed)
    throw({:xhttp, conn, error_code})
  end

  defp fetch_stream!(conn, stream_id) do
    case Map.fetch(conn.streams, stream_id) do
      {:ok, stream} -> stream
      :error -> throw({:xhttp, {:stream_not_found, stream_id}})
    end
  end

  defp assert_stream_in_state!(%{state: state}, expected_state) do
    if state != expected_state do
      throw({:xhttp, {:"stream_not_in_#{expected_state}_state", state}})
    end
  end

  defp transport_send!(%__MODULE__{transport: transport, socket: socket}, bytes) do
    case transport.send(socket, bytes) do
      :ok -> :ok
      {:error, reason} -> throw({:xhttp, reason})
    end
  end
end
