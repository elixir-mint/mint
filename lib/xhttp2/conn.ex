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

  @default_client_settings [
    header_table_size: 4096,
    enable_push: true,
    max_concurrent_streams: 100,
    initial_window_size: 65_535,
    max_frame_size: 16_384
  ]

  @default_window_size 65_535

  @forced_transport_opts [
    packet: :raw,
    mode: :binary,
    active: false,
    alpn_advertised_protocols: ["h2"]
  ]

  ## Connection

  defstruct [
    :transport,
    :socket,
    :state,
    :server_settings,
    :client_settings,
    next_stream_id: 3,
    streams: %{},
    open_streams: 0,
    window_size: @default_window_size,
    initial_window_size: @default_window_size,
    encode_table: HPACK.new(4096),
    decode_table: HPACK.new(4096),
    buffer: ""
  ]

  ## Types

  @type settings() :: Keyword.t()

  @opaque t() :: %__MODULE__{
            transport: module(),
            socket: term(),
            state: :open | :closed,
            server_settings: settings(),
            client_settings: settings(),
            buffer: binary()
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

  @doc """
  TODO
  """
  @spec open?(t()) :: boolean()
  def open?(%__MODULE__{state: state}), do: state == :open

  @doc """
  TODO
  """
  @spec read_server_settings(t()) :: settings()
  def read_server_settings(%__MODULE__{server_settings: server_settings}) do
    server_settings
  end

  @doc """
  TODO
  """
  @spec request(t(), list()) :: {:ok, t(), request_ref :: term()} | {:error, term()}
  def request(%__MODULE__{} = conn, headers) when is_list(headers) do
    with {:ok, conn, stream_id} <- open_stream(conn),
         Logger.debug(fn -> "Opened stream #{stream_id}" end),
         {:ok, conn} <- send_headers(conn, stream_id, headers, [:end_stream, :end_headers]),
         Logger.debug(fn -> "Sent headers: #{inspect(headers)}" end),
         do: {:ok, conn, stream_id}
  end

  defp open_stream(%__MODULE__{} = conn) do
    max_concurrent_streams = conn.server_settings[:max_concurrent_streams]

    if conn.open_streams >= max_concurrent_streams do
      {:error, {:max_concurrent_streams_reached, max_concurrent_streams}}
    else
      stream = %{
        state: :idle,
        id: conn.next_stream_id
      }

      conn = put_in(conn.streams[stream.id], stream)
      conn = update_in(conn.next_stream_id, &(&1 + 2))
      {:ok, conn, stream.id}
    end
  end

  defp send_headers(conn, stream_id, headers, enabled_flags) do
    case Map.fetch(conn.streams, stream_id) do
      {:ok, %{state: :idle} = stream} ->
        headers = Enum.map(headers, fn {name, value} -> {:store_name, name, value} end)
        {hbf, encode_table} = HPACK.encode(headers, conn.encode_table)

        frame = frame_headers(stream_id: stream_id, hbf: hbf)

        flags =
          Enum.reduce(enabled_flags, frame_headers(frame, :flags), fn flag_name, acc ->
            set_flag(acc, :frame_headers, flag_name)
          end)

        frame = frame_headers(frame, flags: flags)

        # TODO: handle failure in sending.
        :ok = conn.transport.send(conn.socket, Frame.encode(frame))

        stream = %{stream | state: :open}
        conn = put_in(conn.encode_table, encode_table)
        conn = put_in(conn.streams[stream_id], stream)
        conn = update_in(conn.open_streams, &(&1 + 1))
        {:ok, conn}

      {:ok, %{state: state}} ->
        {:error, {:stream_not_in_idle_state, state}}

      :error ->
        {:error, :stream_not_found}
    end
  end

  @doc """
  TODO
  """
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
    client_settings_params =
      Keyword.merge(@default_client_settings, Keyword.get(opts, :client_settings, []))

    client_settings = frame_settings(stream_id: 0, params: client_settings_params)

    server_settings_ack =
      frame_settings(
        stream_id: 0,
        params: [],
        flags: set_flag(:frame_settings, :ack)
      )

    with :ok <- transport.send(socket, [@connection_preface, Frame.encode(client_settings)]),
         {:ok, server_settings, buffer} <- receive_server_settings(transport, socket),
         :ok <- transport.send(socket, Frame.encode(server_settings_ack)) do
      conn = %__MODULE__{
        state: :open,
        transport: transport,
        socket: socket,
        buffer: buffer,
        server_settings: frame_settings(server_settings, :params)
      }

      with {:ok, conn} <- receive_client_settings_ack(conn, client_settings_params),
           :ok <- transport_to_inet(transport).setopts(socket, active: true),
           do: {:ok, conn}
    end
  end

  defp receive_server_settings(transport, socket) do
    case recv_next_frame(transport, socket, _buffer = "") do
      {:ok, frame_settings(), _buffer} = result -> result
      {:ok, _frame, _buffer} -> {:error, :protocol_error}
      {:error, _reason} = error -> error
    end
  end

  defp receive_client_settings_ack(%__MODULE__{} = conn, client_settings) do
    case recv_next_frame(conn.transport, conn.socket, conn.buffer) do
      {:ok, frame_settings(flags: flags), buffer} ->
        if flag_set?(flags, :frame_settings, :ack) do
          {:ok, %{conn | client_settings: client_settings, buffer: buffer}}
        else
          {:error, :protocol_error}
        end

      {:ok, frame_window_update(stream_id: 0, window_size_increment: wsi), buffer} ->
        # TODO: handle window size increments that are too big.
        conn = update_in(conn.window_size, &(&1 + wsi))
        receive_client_settings_ack(%{conn | buffer: buffer}, client_settings)

      {:ok, frame_window_update(), _buffer} ->
        {:error, :protocol_error}

      {:ok, frame_goaway() = frame, _buffer} ->
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
        with {:ok, conn, responses} <- handle_frame(conn, frame, responses),
             do: handle_new_data(conn, rest, responses)

      {:error, {:malformed_frame, _}} ->
        {:ok, %{conn | buffer: data}, responses}

      {:error, _reason} = error ->
        error
    end
  end

  ## Frame handling

  # Returns: {:ok, conn, responses} | {:error, reason}
  defp handle_frame(%__MODULE__{} = conn, frame_headers() = frame, responses) do
    Logger.debug(fn -> "Got HEADERS frame: #{inspect(frame)}" end)
    frame_headers(stream_id: stream_id, flags: flags, hbf: hbf) = frame

    case Map.fetch(conn.streams, stream_id) do
      {:ok, %{state: :open} = stream} ->
        {conn, responses} =
          if flag_set?(flags, :frame_headers, :end_headers) do
            # TODO: handle bad decoding
            {:ok, conn, headers} = decode_headers(conn, hbf)
            {conn, [{:headers, stream_id, headers} | responses]}
          else
            raise "END_HEADERS not set is not supported yet"
          end

        {conn, responses} =
          if flag_set?(flags, :frame_headers, :end_stream) do
            stream = %{stream | state: :half_closed_remote}
            conn = put_in(conn.streams[stream_id], stream)
            conn = update_in(conn.open_streams, &(&1 - 1))
            {conn, [{:done, stream_id} | responses]}
          else
            {conn, responses}
          end

        {:ok, conn, responses}

      {:ok, %{state: state}} ->
        raise "don't know how to handle HEADERS on streams with state #{inspect(state)}"

      :error ->
        {:error, :protocol_error}
    end
  end

  defp handle_frame(%__MODULE__{} = conn, frame_data() = frame, responses) do
    # TODO: maybe send WINDOW_UPDATE to refill size here.
    Logger.debug(fn -> "Got DATA frame: #{inspect(frame)}" end)
    frame_data(stream_id: stream_id, flags: flags, data: data) = frame

    case Map.fetch(conn.streams, stream_id) do
      {:ok, %{state: :open} = stream} ->
        responses = [{:data, stream_id, data} | responses]

        if flag_set?(flags, :frame_data, :end_stream) do
          stream = %{stream | state: :half_closed_remote}
          conn = put_in(conn.streams[stream_id], stream)
          conn = update_in(conn.open_streams, &(&1 - 1))
          {:ok, conn, [{:done, stream_id} | responses]}
        else
          {:ok, conn, responses}
        end

      {:ok, %{state: state}} ->
        raise "don't know how to handle DATA on streams with state #{inspect(state)}"

      :error ->
        {:error, :protocol_error}
    end
  end

  defp handle_frame(%__MODULE__{}, frame, _responses) do
    Logger.error(fn -> "Got a frame that I don't know how to handle: #{inspect(frame)}" end)
    raise "unhandleable frame"
  end

  defp decode_headers(%__MODULE__{} = conn, hbf) do
    case HPACK.decode(hbf, conn.decode_table) do
      {:ok, headers, decode_table} ->
        {:ok, conn, %{conn | decode_table: decode_table}}

      # TODO: embellish this error
      {:error, _reason} = error ->
        error
    end
  end
end
