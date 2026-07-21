defmodule Mint.TunnelProxyConnectTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.HTTP

  # Offline tests for the CONNECT request TunnelProxy uses to establish a
  # tunnel. They use a local TCP server as the proxy and inspect the raw bytes
  # it receives, so they need no live proxy or internet connection. They live
  # in their own module (rather than in tunnel_proxy_test.exs) so they run in
  # the default suite instead of being excluded by that module's `:proxy` tag.

  @cert_opts [
    certfile: Path.absname("../support/mint/certificate.pem", __DIR__),
    keyfile: Path.absname("../support/mint/key.pem", __DIR__)
  ]

  test "tunnels through a proxy that sends content-length: 0 in the CONNECT response" do
    origin_port = start_tls_origin()

    {proxy_port, proxy_ref} =
      start_connect_proxy("HTTP/1.1 200 Connection established\r\ncontent-length: 0\r\n\r\n")

    assert {:ok, conn} =
             HTTP.connect(:https, "localhost", origin_port,
               proxy: {:http, "localhost", proxy_port, []},
               transport_opts: [verify: :verify_none]
             )

    assert_receive {^proxy_ref, :connect, head}, 2000
    assert head =~ "CONNECT localhost:#{origin_port} HTTP/1.1\r\n"

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)
    assert [{:status, ^request, 200}, {:headers, ^request, _headers} | rest] = responses
    assert merge_body(rest, request) == "hello"
  end

  test "IPv6 address targets produce a bracketed CONNECT authority" do
    {proxy_port, proxy_ref} = start_capturing_proxy()

    assert {:error, _reason} =
             HTTP.connect(:https, "::1", 443, proxy: {:http, "localhost", proxy_port, []})

    assert_receive {^proxy_ref, :connect, head}, 2000
    assert head =~ "CONNECT [::1]:443 HTTP/1.1\r\n"
  end

  # Starts a one-shot CONNECT proxy that accepts a single connection, reports
  # the raw CONNECT request head to the test process, replies with the given
  # response, and then blindly relays bytes to the requested host.
  defp start_connect_proxy(connect_response) do
    test_pid = self()
    ref = make_ref()

    {:ok, listen_socket} =
      :gen_tcp.listen(0, mode: :binary, packet: :raw, active: false, reuseaddr: true)

    {:ok, port} = :inet.port(listen_socket)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen_socket)
      head = recv_request_head(socket)
      send(test_pid, {ref, :connect, head})

      [request_line, _rest] = String.split(head, "\r\n", parts: 2)
      ["CONNECT", authority, _version] = String.split(request_line, " ")
      [host, origin_port] = String.split(authority, ":")

      {:ok, origin_socket} =
        :gen_tcp.connect(String.to_charlist(host), String.to_integer(origin_port),
          mode: :binary,
          active: true
        )

      :ok = :gen_tcp.send(socket, connect_response)
      :ok = :inet.setopts(socket, active: true)
      relay(socket, origin_socket)
    end)

    {port, ref}
  end

  # Starts a one-shot server that accepts a single connection, reports the raw
  # request head to the test process, and closes the connection.
  defp start_capturing_proxy do
    test_pid = self()
    ref = make_ref()

    {:ok, listen_socket} =
      :gen_tcp.listen(0, mode: :binary, packet: :raw, active: false, reuseaddr: true)

    {:ok, port} = :inet.port(listen_socket)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen_socket)
      send(test_pid, {ref, :connect, recv_request_head(socket)})
      :gen_tcp.close(socket)
      :gen_tcp.close(listen_socket)
    end)

    {port, ref}
  end

  defp start_tls_origin do
    socket_opts = [mode: :binary, packet: :raw, active: false, reuseaddr: true]
    {:ok, listen_socket} = :ssl.listen(0, socket_opts ++ @cert_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)

    spawn_link(fn ->
      {:ok, socket} = :ssl.transport_accept(listen_socket)
      {:ok, socket} = :ssl.handshake(socket, 10_000)
      _request = recv_ssl_request_head(socket)
      :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")

      receive do
        :stop -> :ok
      end
    end)

    port
  end

  defp recv_request_head(socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 2000)
      recv_request_head(socket, buffer <> data)
    end
  end

  defp recv_ssl_request_head(socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :ssl.recv(socket, 0, 2000)
      recv_ssl_request_head(socket, buffer <> data)
    end
  end

  defp relay(client_socket, origin_socket) do
    receive do
      {:tcp, ^client_socket, data} ->
        _ = :gen_tcp.send(origin_socket, data)
        relay(client_socket, origin_socket)

      {:tcp, ^origin_socket, data} ->
        _ = :gen_tcp.send(client_socket, data)
        relay(client_socket, origin_socket)

      {:tcp_closed, ^client_socket} ->
        :gen_tcp.close(origin_socket)

      {:tcp_closed, ^origin_socket} ->
        :gen_tcp.close(client_socket)

      {:tcp_error, ^client_socket, _reason} ->
        :gen_tcp.close(origin_socket)

      {:tcp_error, ^origin_socket, _reason} ->
        :gen_tcp.close(client_socket)
    end
  end
end
