defmodule XHTTP2.Server do
  import XHTTP2.Frame

  alias XHTTP2.{HPACK, Frame}

  @state %{
    socket: nil,
    encode_table: HPACK.new(4096),
    decode_table: HPACK.new(4096)
  }
  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @certificate Path.absname("certificate.pem", __DIR__)
  @key Path.absname("key.pem", __DIR__)

  def start() do
    {:ok, listen_socket} =
      :ssl.listen(
        0,
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        next_protocols_advertised: ["h2"],
        alpn_preferred_protocols: ["h2"],
        certfile: @certificate,
        keyfile: @key
      )

    spawn_link(fn -> loop(listen_socket) end)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    {:ok, port}
  end

  defp loop(listen_socket) do
    {:ok, socket} = :ssl.transport_accept(listen_socket)
    :ok = :ssl.ssl_accept(socket)

    pid =
      spawn_link(fn ->
        :ok = handshake(socket)
        :ok = :ssl.setopts(socket, active: true)
        handle_client(%{@state | socket: socket})
      end)

    :ok = :ssl.controlling_process(socket, pid)

    loop(listen_socket)
  end

  defp handshake(socket) do
    {:ok, @connection_preface <> rest} = :ssl.recv(socket, 0, 100)
    {:ok, settings(stream_id: 0, flags: 0x00), ""} = Frame.decode_next(rest)

    settings = settings(stream_id: 0, flags: 0x00, params: [])
    :ok = :ssl.send(socket, Frame.encode(settings))

    {:ok, packet} = :ssl.recv(socket, 0, 100)
    {:ok, settings(stream_id: 0, flags: 0x01), ""} = Frame.decode_next(packet)

    settings = settings(stream_id: 0, flags: 0x01, params: [])
    :ok = :ssl.send(socket, Frame.encode(settings))
  end

  defp handle_client(%{socket: socket} = state) do
    receive do
      {:ssl, ^socket, packet} ->
        {:ok, frame, ""} = Frame.decode_next(packet)
        state = handle_frame(state, frame)
        handle_client(state)

      {:ssl_closed, ^socket} ->
        :ok

      {:ssl_error, ^socket, _reason} ->
        :ok

      other ->
        raise "got unexpected message: #{inspect(other)}"
    end
  end

  defp handle_frame(state, headers(hbf: hbf, stream_id: stream_id)) do
    {:ok, headers, decode_table} = HPACK.decode(hbf, state.decode_table)
    state = put_in(state.decode_table, decode_table)
    handle_request(state, stream_id, get_req_header(headers, ":path"), headers)
  end

  defp handle_frame(state, goaway()) do
    :ssl.close(state.socket)
    state
  end

  defp handle_request(state, _stream_id, "/", _) do
    state
  end

  defp handle_request(state, stream_id, "/server-sends-rst-stream", _) do
    frame = rst_stream(stream_id: stream_id, error_code: :protocol_error)
    :ok = :ssl.send(state.socket, Frame.encode(frame))
    state
  end

  defp handle_request(state, _stream_id, "/server-sends-goaway", _) do
    frame =
      goaway(
        stream_id: 0,
        last_stream_id: 3,
        error_code: :protocol_error,
        debug_data: "debug data"
      )

    :ok = :ssl.send(state.socket, Frame.encode(frame))
    :ok = :ssl.close(state.socket)
    %{state | socket: nil}
  end

  defp handle_request(state, stream_id, "/split-headers-into-continuation", _) do
    headers = [
      {:store_name, ":status", "200"},
      {:store_name, "foo", "bar"},
      {:store_name, "baz", "bong"}
    ]

    {hbf, _encode_table} = HPACK.encode(headers, state.encode_table)

    <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)

    # TODO: update encode table

    frame1 = headers(stream_id: stream_id, hbf: hbf1)
    :ok = :ssl.send(state.socket, Frame.encode(frame1))

    frame2 = continuation(stream_id: stream_id, hbf: hbf2)
    :ok = :ssl.send(state.socket, Frame.encode(frame2))

    frame3 = continuation(stream_id: stream_id, hbf: hbf3, flags: 0x04)
    :ok = :ssl.send(state.socket, Frame.encode(frame3))

    state
  end

  defp handle_request(state, stream_id, "/server-sends-badly-encoded-hbf", _) do
    frame =
      headers(
        stream_id: stream_id,
        hbf: "not a good hbf",
        flags: set_flag(:headers, :end_headers)
      )

    :ok = :ssl.send(state.socket, Frame.encode(frame))
    state
  end

  defp handle_request(state, stream_id, "/server-sends-continuation-outside-headers-streaming", _) do
    frame = continuation(stream_id: stream_id, hbf: "hbf")
    :ok = :ssl.send(state.socket, Frame.encode(frame))
    state
  end

  defp handle_request(state, stream_id, "/server-sends-frame-while-streaming-headers", _) do
    # Headers are streaming but we send a non-CONTINUATION frame.
    headers = headers(stream_id: stream_id, hbf: "hbf")
    data = data(stream_id: stream_id, data: "some data")
    :ok = :ssl.send(state.socket, [Frame.encode(headers), Frame.encode(data)])
    state
  end

  defp get_req_header(headers, header) do
    {^header, value} = List.keyfind(headers, header, 0)
    value
  end
end
