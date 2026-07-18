defmodule Mint.TunnelProxyServer do
  # A minimal HTTPS CONNECT proxy: it terminates TLS, accepts a CONNECT
  # request, connects to the requested host, and then blindly relays bytes
  # in both directions. The head of each CONNECT request is sent to the
  # process that started the server as {server_ref, :connect, head}.

  @socket_opts [
    mode: :binary,
    packet: :raw,
    active: false,
    reuseaddr: true
  ]

  @cert_opts [
    certfile: Path.absname("certificate.pem", __DIR__),
    keyfile: Path.absname("key.pem", __DIR__)
  ]

  def start(cert_opts \\ @cert_opts) do
    {:ok, listen_socket} = :ssl.listen(0, @socket_opts ++ cert_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    server_ref = make_ref()
    parent = self()

    spawn_link(fn -> loop(listen_socket, parent, server_ref) end)

    {:ok, port, server_ref}
  end

  defp loop(listen_socket, parent, server_ref) do
    case :ssl.transport_accept(listen_socket) do
      {:ok, socket} ->
        case :ssl.handshake(socket, 10_000) do
          {:ok, socket} ->
            handler = spawn_link(fn -> handle_connection(parent, server_ref) end)
            :ok = :ssl.controlling_process(socket, handler)
            send(handler, {:socket, socket})

          {:error, _reason} ->
            :ok
        end

        loop(listen_socket, parent, server_ref)

      {:error, :closed} ->
        :ok
    end
  end

  defp handle_connection(parent, server_ref) do
    socket =
      receive do
        {:socket, socket} -> socket
      end

    head = recv_until_blank_line(socket, "")
    send(parent, {server_ref, :connect, head})

    [request_line, _rest] = String.split(head, "\r\n", parts: 2)
    ["CONNECT", authority, _version] = String.split(request_line, " ")
    [host, port] = String.split(authority, ":")

    {:ok, tcp_socket} =
      :gen_tcp.connect(String.to_charlist(host), String.to_integer(port),
        mode: :binary,
        active: true
      )

    :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\n\r\n")
    :ok = :ssl.setopts(socket, active: true)
    relay(socket, tcp_socket)
    send(parent, {server_ref, :closed})
  end

  defp recv_until_blank_line(socket, buffer) do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :ssl.recv(socket, 0, 10_000)
      recv_until_blank_line(socket, buffer <> data)
    end
  end

  defp relay(ssl_socket, tcp_socket) do
    receive do
      {:ssl, ^ssl_socket, data} ->
        _ = :gen_tcp.send(tcp_socket, data)
        relay(ssl_socket, tcp_socket)

      {:tcp, ^tcp_socket, data} ->
        _ = :ssl.send(ssl_socket, data)
        relay(ssl_socket, tcp_socket)

      {:ssl_closed, ^ssl_socket} ->
        :gen_tcp.close(tcp_socket)

      {:tcp_closed, ^tcp_socket} ->
        :ssl.close(ssl_socket)

      {:ssl_error, ^ssl_socket, _reason} ->
        :gen_tcp.close(tcp_socket)

      {:tcp_error, ^tcp_socket, _reason} ->
        :ssl.close(ssl_socket)
    end
  end
end
