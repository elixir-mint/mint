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
    max_frame_size: 16_384
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

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@forced_transport_opts)

    with {:ok, socket} <-
           connect_and_negotiate_protocol(hostname, port, transport, transport_opts),
         :ok <- set_inet_opts(transport, socket),
         {:ok, conn} <- initiate_connection(transport, socket, opts) do
      {:ok, conn}
    else
      {:error, reason} ->
        {:error, {:connect, reason}}
    end
  end

  @spec open?(t()) :: boolean()
  def open?(%__MODULE__{state: state}), do: state == :open

  @spec request(t(), list()) :: {:ok, t(), request_id()} | {:error, t(), term()}
  def request(%__MODULE__{} = conn, headers) when is_list(headers) do
    {conn, stream_id, ref} = open_stream(conn)
    conn = send_headers(conn, stream_id, headers, [:end_stream, :end_headers])
    {:ok, conn, ref}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @spec request(t(), list(), iodata()) :: {:ok, t(), request_id()} | {:error, t(), term()}
  def request(%__MODULE__{} = conn, headers, body) when is_list(headers) do
    {conn, stream_id, ref} = open_stream(conn)
    # TODO: Optimize here by sending a single packet on the network.
    conn = send_headers(conn, stream_id, headers, [:end_headers])
    conn = send_data(conn, stream_id, body, [:end_stream])
    {:ok, conn, ref}
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

  def stream(conn, message)

  def stream(%__MODULE__{socket: socket} = conn, {error_tag, socket, reason})
      when error_tag in [:tcp_error, :ssl_error] do
    {:error, %{conn | state: :closed}, reason}
  end

  def stream(%__MODULE__{socket: socket} = conn, {closed_tag, socket})
      when closed_tag in [:tcp_close, :ssl_close] do
    {:error, %{conn | state: :closed}, :closed}
  end

  def stream(%__MODULE__{socket: socket} = conn, {tag, socket, data}) when tag in [:tcp, :ssl] do
    with {:ok, conn, responses} <- handle_new_data(conn, conn.buffer <> data, []),
         do: {:ok, conn, Enum.reverse(responses)}
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
  defp transport_to_inet(other), do: other

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

      {:error, _reason} = error ->
        error
    end
  end

  defp handle_new_data(%__MODULE__{} = conn, data, responses) do
    case Frame.decode_next(data) do
      {:ok, frame, rest} ->
        Logger.debug(fn -> "Got frame: #{inspect(frame)}" end)

        with {:ok, conn, responses} <- handle_frame(conn, frame, responses),
             do: handle_new_data(conn, rest, responses)

      {:error, {:malformed_frame, _}} ->
        {:ok, %{conn | buffer: data}, responses}

      {:error, _reason} = error ->
        error
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
        # TODO: update open streams
        # TODO: check that the iws is under the @max_window_size
        put_in(conn.initial_window_size, initial_window_size)

      {:max_frame_size, max_frame_size}, conn ->
        put_in(conn.max_frame_size, max_frame_size)

      {:max_header_list_size, max_header_list_size}, conn ->
        # TODO: handle this
        conn
    end)
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

    conn = put_in(conn.encode_table, encode_table)
    conn = put_in(conn.streams[stream_id].state, :open)
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

  # DATA
  defp handle_frame(conn, data() = frame, responses) do
    data(stream_id: stream_id, flags: flags, data: data) = frame
    stream = fetch_stream!(conn, stream_id)

    if stream.state != :open do
      raise "don't know how to handle DATA on streams with state #{inspect(stream.state)}"
    end

    responses = [{:data, stream.ref, data} | responses]

    if flag_set?(flags, :data, :end_stream) do
      conn = put_in(conn.streams[stream_id].state, :half_closed_remote)
      conn = update_in(conn.open_stream_count, &(&1 - 1))
      {:ok, conn, [{:done, stream.ref} | responses]}
    else
      {:ok, conn, responses}
    end
  end

  # HEADERS
  defp handle_frame(conn, headers() = frame, responses) do
    headers(stream_id: stream_id, flags: flags, hbf: hbf) = frame
    stream = fetch_stream!(conn, stream_id)

    if stream.state != :open do
      raise "don't know how to handle HEADERS on streams with state #{inspect(stream.state)}"
    end

    {conn, responses} =
      if flag_set?(flags, :headers, :end_headers) do
        {conn, status, headers} = decode_headers!(conn, hbf)
        {conn, [{:headers, stream.ref, headers}, {:status, stream.ref, status} | responses]}
      else
        raise "END_HEADERS not set is not supported yet"
      end

    {conn, responses} =
      if flag_set?(flags, :headers, :end_stream) do
        conn = put_in(conn.streams[stream_id].state, :half_closed_remote)
        conn = update_in(conn.open_stream_count, &(&1 - 1))
        {conn, [{:done, stream.ref} | responses]}
      else
        {conn, responses}
      end

    {:ok, conn, responses}
  end

  # TODO: implement PRIORITY
  defp handle_frame(_conn, priority(), _responses) do
    raise "PRIORITY handling not implemented"
  end

  # TODO: implement RST_STREAM
  defp handle_frame(_conn, rst_stream(), _responses) do
    raise "RST_STREAM handling not implemented"
  end

  # TODO: implement SETTINGS
  defp handle_frame(_conn, settings(), _responses) do
    raise "SETTINGS handling not implemented"
  end

  # TODO: implement PUSH_PROMISE
  defp handle_frame(_conn, push_promise(), _responses) do
    raise "PUSH_PROMISE handling not implemented"
  end

  # PING
  defp handle_frame(conn, Frame.ping(flags: flags, opaque_data: opaque_data), responses) do
    if flag_set?(flags, :ping, :ack) do
      case :queue.out(conn.ping_queue) do
        {{:value, {ref, ^opaque_data}}, ping_queue} ->
          conn = put_in(conn.ping_queue, ping_queue)
          {:ok, conn, [{:pong, ref} | responses]}

        {{:value, _}, _} ->
          # TODO: handle this properly.
          raise "non-matching PING"

        {:empty, _ping_queue} ->
          # TODO: handle this properly.
          raise "no pings had been sent"
      end
    else
      ack_ping = Frame.ping(stream_id: 0, flags: set_flag(:ping, :ack), opaque_data: opaque_data)
      transport_send!(conn, Frame.encode(ack_ping))
      {:ok, conn, responses}
    end
  end

  # GOAWAY
  defp handle_frame(conn, goaway() = frame, responses) do
    goaway(last_stream_id: last_stream_id, error_code: error_code, debug_data: debug_data) = frame

    unprocessed_stream_ids = Enum.filter(conn.streams, fn {id, _} -> id > last_stream_id end)

    {responses, conn} =
      Enum.reduce(unprocessed_stream_ids, {conn, responses}, fn {id, stream}, {conn, responses} ->
        conn = update_in(conn.streams, &Map.delete(&1, id))
        conn = update_in(conn.open_streams, &(&1 - 1))
        conn = update_in(conn.ref_to_stream_id, &Map.delete(&1, stream.ref))
        conn = put_in(conn.state, :went_away)
        response = {:closed, stream.ref, {:goaway, error_code, debug_data}}
        {[response | responses], conn}
      end)

    {:ok, conn, responses}
  end

  # WINDOW_UPDATE
  defp handle_frame(conn, window_update() = frame, responses) do
    case frame do
      window_update(stream_id: 0, window_size_increment: wsi) ->
        case increment_window_size(conn, :connection, wsi) do
          {:ok, conn} -> {:ok, conn, responses}
          {:error, conn} -> {:error, conn, :flow_control_error}
        end

      # TODO: handle this frame not existing.
      window_update(stream_id: stream_id, window_size_increment: wsi) ->
        case increment_window_size(conn, {:stream, stream_id}, wsi) do
          {:ok, conn} ->
            {:ok, conn, responses}

          {:error, conn} ->
            frame = rst_stream(stream_id: stream_id, error_code: :flow_control_error)
            transport_send!(conn, Frame.encode(frame))
            %{ref: ref} = fetch_stream!(conn, stream_id)
            {:ok, conn, [{:closed, ref, :flow_control_error} | responses]}
        end
    end
  end

  # TODO: implement CONTINUATION
  defp handle_frame(_conn, continuation(), _responses) do
    raise "CONTINUATION handling not implemented"
  end

  defp decode_headers!(%__MODULE__{} = conn, hbf) do
    case HPACK.decode(hbf, conn.decode_table) do
      {:ok, [{":status", status} | headers], decode_table} ->
        conn = put_in(conn.decode_table, decode_table)
        {conn, status, headers}

      # TODO: handle this properly
      {:ok, headers, decode_table} ->
        raise ":status header is missing"

      {:error, _reason} ->
        debug_data = "unable to decode headers"
        frame = goaway(last_stream_id: 2, error_code: :compression_error, debug_data: debug_data)
        transport_send!(conn, Frame.encode(frame))
        transport_close!(conn)
        throw({:xhttp, conn, :compression_error})
    end
  end

  defp increment_window_size(conn, :connection, wsi) do
    case conn.window_size do
      ws when ws + wsi > @max_window_size -> {:error, conn}
      ws -> {:ok, %{conn | window_size: ws}}
    end
  end

  defp increment_window_size(conn, {:stream, stream_id}, wsi) do
    case conn.streams[stream_id].window_size do
      ws when ws + wsi > @max_window_size -> {:error, conn}
      ws -> {:ok, put_in(conn.streams[stream_id].window_size, ws + wsi)}
    end
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

  defp transport_close!(%__MODULE__{transport: transport, socket: socket}) do
    transport.close(socket)
  end
end
