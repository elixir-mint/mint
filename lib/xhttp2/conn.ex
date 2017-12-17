defmodule XHTTP2.Conn do
  use Bitwise, skip_operators: true

  import XHTTP2.Frame, except: [encode: 1, decode_next: 1]

  alias XHTTP2.Frame

  require Logger

  defstruct [
    :transport,
    :socket,
    :state,
    :server_settings,
    :client_settings,
    buffer: ""
  ]

  @type settings() :: Keyword.t()

  @opaque t() :: %__MODULE__{
            transport: module(),
            socket: term(),
            state: atom(),
            server_settings: settings(),
            client_settings: settings(),
            buffer: binary()
          }

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
    end
  end

  @spec open?(t()) :: boolean()
  def open?(%__MODULE__{state: state}), do: state == :open

  @spec read_server_settings(t()) :: settings()
  def read_server_settings(%__MODULE__{server_settings: server_settings}) do
    server_settings
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
         :ok <- transport.send(socket, Frame.encode(server_settings_ack)),
         {:ok, buffer} <- receive_client_settings_ack(transport, socket, buffer),
         :ok <- transport_to_inet(transport).setopts(socket, active: true) do
      conn = %__MODULE__{
        state: :open,
        transport: transport,
        socket: socket,
        buffer: buffer,
        client_settings: client_settings_params,
        server_settings: frame_settings(server_settings, :params)
      }

      {:ok, conn}
    end
  end

  defp receive_server_settings(transport, socket) do
    case recv_next_frame(transport, socket, _buffer = "") do
      {:ok, frame_settings(), _buffer} = result -> result
      {:ok, _frame, _buffer} -> {:error, :protocol_error}
      {:error, _reason} = error -> error
    end
  end

  defp receive_client_settings_ack(transport, socket, buffer) do
    case recv_next_frame(transport, socket, buffer) do
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

        receive_client_settings_ack(transport, socket, buffer)

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
end
