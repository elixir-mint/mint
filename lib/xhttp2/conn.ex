defmodule XHTTP2.Conn do
  use Bitwise, skip_operators: true

  import XHTTP2.Frame, except: [encode: 1, decode_next: 1]

  alias XHTTP2.Frame

  require Logger

  defstruct [
    :socket,
    :state,
    :server_settings,
    :client_settings,
    buffer: ""
  ]

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @default_client_settings [
    header_table_size: 4096,
    enable_push: true,
    max_concurrent_streams: 100,
    initial_window_size: 65_535,
    max_frame_size: 16_384
  ]

  @forced_transport_opts [
    packet: :raw,
    mode: :binary,
    active: false,
    alpn_advertised_protocols: ["h2"]
  ]

  ## Public interface

  def connect(hostname, port, opts \\ []) do
    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@forced_transport_opts)

    with {:ok, socket} <- connect_and_negotiate_protocol(hostname, port, transport_opts),
         :ok <- set_inet_opts(socket),
         {:ok, conn} <- initiate_connection(socket, opts) do
      {:ok, conn}
    end
  end

  def open?(%__MODULE__{state: state}), do: state == :open

  ## Helpers

  defp connect_and_negotiate_protocol(hostname, port, transport_opts) do
    with {:ok, socket} <- :ssl.connect(String.to_charlist(hostname), port, transport_opts),
         {:ok, protocol} <- :ssl.negotiated_protocol(socket) do
      if protocol == "h2" do
        {:ok, socket}
      else
        {:error, {:bad_alpn_protocol, protocol}}
      end
    end
  end

  defp set_inet_opts(socket) do
    with {:ok, opts} <- :ssl.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = Keyword.fetch!(opts, :buffer),
         sndbuf = Keyword.fetch!(opts, :sndbuf),
         recbuf = Keyword.fetch!(opts, :recbuf),
         buffer = buffer |> max(sndbuf) |> max(recbuf),
         :ok <- :ssl.setopts(socket, buffer: buffer),
         do: :ok
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  # SETTINGS parameters are not negotiated. We keep client settings and server settings separate.
  defp initiate_connection(socket, opts) do
    client_settings_params =
      Keyword.merge(@default_client_settings, Keyword.get(opts, :client_settings, []))

    client_settings = frame_settings(stream_id: 0, params: client_settings_params)

    server_settings_ack =
      frame_settings(
        stream_id: 0,
        params: [],
        flags: set_flag(:frame_settings, :ack)
      )

    with :ok <- :ssl.send(socket, [@connection_preface, Frame.encode(client_settings)]),
         {:ok, server_settings, buffer} <- receive_server_settings(socket),
         :ok <- :ssl.send(socket, Frame.encode(server_settings_ack)),
         {:ok, buffer} <- receive_client_settings_ack(socket, buffer),
         :ok <- :ssl.setopts(socket, active: true) do
      conn = %__MODULE__{
        state: :open,
        socket: socket,
        buffer: buffer,
        client_settings: client_settings_params,
        server_settings: frame_settings(server_settings, :params)
      }

      {:ok, conn}
    end
  end

  defp receive_server_settings(socket) do
    case recv_next_frame(socket, _buffer = "") do
      {:ok, frame_settings(), _buffer} = result -> result
      {:ok, _frame, _buffer} -> {:error, :protocol_error}
      {:error, _reason} = error -> error
    end
  end

  defp receive_client_settings_ack(socket, buffer) do
    case recv_next_frame(socket, buffer) do
      {:ok, frame_settings(flags: flags), buffer} ->
        if flag_set?(flags, :frame_settings, :ack) do
          {:ok, buffer}
        else
          {:error, :protocol_error}
        end

      {:ok, frame_window_update() = frame, buffer} ->
        # TODO: handle this frame.
        Logger.warn(fn ->
          "Received a WINDOW_UPDATE while waiting for client SETTINGS ack: #{inspect(frame)}"
        end)

        receive_client_settings_ack(socket, buffer)

      {:ok, frame_goaway() = frame, _buffer} ->
        {:error, {:goaway, frame}}

      {:error, _reason} = error ->
        error
    end
  end

  defp recv_next_frame(socket, buffer) do
    case Frame.decode_next(buffer) do
      {:ok, _frame, _rest} = result ->
        result

      {:error, {:malformed_frame, _}} ->
        with {:ok, data} <- :ssl.recv(socket, 0) do
          recv_next_frame(socket, buffer <> data)
        end

      {:error, _reason} = error ->
        error
    end
  end
end
