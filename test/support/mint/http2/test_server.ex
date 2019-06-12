defmodule Mint.HTTP2.TestServer do
  import ExUnit.Assertions

  alias Mint.{HTTP2, HTTP2.Frame, HTTP2.HPACK}

  defstruct [:socket, :encode_table, :decode_table]

  @ssl_opts [
    mode: :binary,
    packet: :raw,
    active: false,
    reuseaddr: true,
    next_protocols_advertised: ["h2"],
    alpn_preferred_protocols: ["h2"],
    certfile: Path.absname("../certificate.pem", __DIR__),
    keyfile: Path.absname("../key.pem", __DIR__)
  ]

  @spec connect(keyword(), keyword()) :: {Mint.HTTP2.t(), %__MODULE__{}}
  def connect(options, server_settings) do
    ref = make_ref()
    parent = self()

    task = Task.async(fn -> start_socket_and_accept(parent, ref, server_settings) end)
    assert_receive {^ref, port}, 100

    assert {:ok, conn} = HTTP2.connect(:https, "localhost", port, options)
    assert %HTTP2{} = conn

    {:ok, server_socket} = Task.await(task)

    # SETTINGS here.
    conn =
      if options[:mode] == :passive do
        assert {:ok, %HTTP2{} = conn, []} = HTTP2.recv(conn, 0, 100)
        conn
      else
        assert_receive message, 100
        assert {:ok, %HTTP2{} = conn, []} = HTTP2.stream(conn, message)
        conn
      end

    :ok = :ssl.setopts(server_socket, active: true)

    server = %__MODULE__{
      socket: server_socket,
      encode_table: HPACK.new(4096),
      decode_table: HPACK.new(4096)
    }

    {conn, server}
  end

  @spec recv_next_frames(%__MODULE__{}, pos_integer()) :: [frame :: term(), ...]
  def recv_next_frames(%__MODULE__{} = server, frame_count) when frame_count > 0 do
    recv_next_frames(server, frame_count, [], "")
  end

  defp recv_next_frames(_server, 0, frames, buffer) do
    if buffer == "" do
      Enum.reverse(frames)
    else
      flunk("Expected no more data, got: #{inspect(buffer)}")
    end
  end

  defp recv_next_frames(%{socket: server_socket} = server, n, frames, buffer) do
    assert_receive {:ssl, ^server_socket, data}, 100
    decode_next_frames(server, n, frames, buffer <> data)
  end

  defp decode_next_frames(_server, 0, frames, buffer) do
    if buffer == "" do
      Enum.reverse(frames)
    else
      flunk("Expected no more data, got: #{inspect(buffer)}")
    end
  end

  defp decode_next_frames(server, n, frames, data) do
    case Frame.decode_next(data) do
      {:ok, frame, rest} ->
        decode_next_frames(server, n - 1, [frame | frames], rest)

      :more ->
        recv_next_frames(server, n, frames, data)

      other ->
        flunk("Error decoding frame: #{inspect(other)}")
    end
  end

  @spec encode_frames(%__MODULE__{}, [frame :: term(), ...]) :: {%__MODULE__{}, binary()}
  def encode_frames(%__MODULE__{} = server, frames) when is_list(frames) and frames != [] do
    import Mint.HTTP2.Frame, only: [headers: 1]

    {data, server} =
      Enum.map_reduce(frames, server, fn
        {frame_type, stream_id, headers, flags}, server
        when frame_type in [:headers, :push_promise] ->
          {server, hbf} = encode_headers(server, headers)
          flags = Frame.set_flags(frame_type, flags)
          frame = headers(stream_id: stream_id, hbf: hbf, flags: flags)
          {Frame.encode(frame), server}

        frame, server ->
          {Frame.encode(frame), server}
      end)

    {server, IO.iodata_to_binary(data)}
  end

  @spec encode_headers(%__MODULE__{}, Mint.Types.headers()) :: {%__MODULE__{}, hbf :: binary()}
  def encode_headers(%__MODULE__{} = server, headers) when is_list(headers) do
    headers = for {name, value} <- headers, do: {:store_name, name, value}
    {hbf, encode_table} = HPACK.encode(headers, server.encode_table)
    server = put_in(server.encode_table, encode_table)
    {server, IO.iodata_to_binary(hbf)}
  end

  @spec decode_headers(%__MODULE__{}, binary()) :: {%__MODULE__{}, Mint.Types.headers()}
  def decode_headers(%__MODULE__{} = server, hbf) when is_binary(hbf) do
    assert {:ok, headers, decode_table} = HPACK.decode(hbf, server.decode_table)
    server = put_in(server.decode_table, decode_table)
    {server, headers}
  end

  @spec get_socket(%__MODULE__{}) :: :ssl.sslsocket()
  def get_socket(server) do
    server.socket
  end

  defp start_socket_and_accept(parent, ref, server_settings) do
    {:ok, listen_socket} = :ssl.listen(0, @ssl_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    send(parent, {ref, port})

    # Let's accept a new connection.
    {:ok, socket} = :ssl.transport_accept(listen_socket)
    :ok = :ssl.ssl_accept(socket)

    :ok = perform_http2_handshake(socket, server_settings)

    # We transfer ownership of the socket to the parent so that this task can die.
    :ok = :ssl.controlling_process(socket, parent)
    {:ok, socket}
  end

  connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  defp perform_http2_handshake(socket, server_settings) do
    import Mint.HTTP2.Frame, only: [settings: 1]

    no_flags = Frame.set_flags(:settings, [])
    ack_flags = Frame.set_flags(:settings, [:ack])

    # First we get the connection preface.
    {:ok, unquote(connection_preface) <> rest} = :ssl.recv(socket, 0, 100)

    # Then we get a SETTINGS frame.
    assert {:ok, frame, ""} = Frame.decode_next(rest)
    assert settings(flags: ^no_flags, params: _params) = frame

    # We reply with our SETTINGS.
    :ok = :ssl.send(socket, Frame.encode(settings(params: server_settings)))

    # We get the SETTINGS ack.
    {:ok, data} = :ssl.recv(socket, 0, 100)
    assert {:ok, frame, ""} = Frame.decode_next(data)
    assert settings(flags: ^ack_flags, params: []) = frame

    # We send the SETTINGS ack back.
    :ok = :ssl.send(socket, Frame.encode(settings(flags: ack_flags, params: [])))

    :ok
  end
end
