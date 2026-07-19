defmodule Mint.UnsafeProxyOptsTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.{HTTP, TransportError}

  # Offline tests for how connect options are split in forward-proxy mode: the
  # proxy connection is configured by the options in the :proxy tuple, while
  # the options given to Mint.HTTP.connect/4 describe the target. They use
  # local TCP/TLS servers as the proxy, so they need no live proxy or internet
  # connection.

  @cert_opts [
    certfile: Path.absname("../support/mint/certificate.pem", __DIR__),
    keyfile: Path.absname("../support/mint/key.pem", __DIR__)
  ]

  @tag :capture_log
  test "target transport options are not used for the proxy connection" do
    {proxy_port, _proxy_ref} = start_tls_proxy(@cert_opts)

    assert {:error, %TransportError{}} =
             HTTP.connect(:http, "example.com", 80,
               proxy: {:https, "localhost", proxy_port, []},
               transport_opts: [verify: :verify_none]
             )
  end

  test "proxy transport options are used for the proxy connection" do
    {proxy_port, proxy_ref} = start_tls_proxy(@cert_opts)

    assert {:ok, conn} =
             HTTP.connect(:http, "example.com", 80,
               proxy: {:https, "localhost", proxy_port, [transport_opts: [verify: :verify_none]]}
             )

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert_receive {^proxy_ref, :request, head}, 2000
    assert head =~ "GET http://example.com/ HTTP/1.1\r\n"

    assert {:ok, _conn, responses} = receive_stream(conn)
    assert [{:status, ^request, 200}, {:headers, ^request, _headers} | rest] = responses
    assert merge_body(rest, request) == "ok"
  end

  test "the target :hostname option is not used to verify the proxy certificate" do
    %{server_config: server_config, client_config: client_config} = pkix_test_chain()
    {proxy_port, proxy_ref} = start_tls_proxy(server_config)

    assert {:ok, conn} =
             HTTP.connect(:http, "example.com", 80,
               proxy:
                 {:https, "localhost", proxy_port,
                  [transport_opts: [cacerts: client_config[:cacerts]]]},
               hostname: "wrong.example"
             )

    # The :hostname option still overrides the target identity in the request.
    assert {:ok, _conn, _request} = HTTP.request(conn, "GET", "/", [], nil)
    assert_receive {^proxy_ref, :request, head}, 2000
    assert head =~ "GET http://wrong.example/ HTTP/1.1\r\n"
  end

  test ":proxy_headers are taken from the connect options" do
    {proxy_port, proxy_ref} = start_tcp_proxy()

    assert {:ok, conn} =
             HTTP.connect(:http, "example.com", 80,
               proxy: {:http, "localhost", proxy_port, []},
               proxy_headers: [{"proxy-authorization", "Basic dGVzdDpwYXNzd29yZA=="}]
             )

    assert {:ok, _conn, _request} = HTTP.request(conn, "GET", "/", [], nil)
    assert_receive {^proxy_ref, :request, head}, 2000
    assert head =~ "proxy-authorization: Basic dGVzdDpwYXNzd29yZA==\r\n"
  end

  # Starts a one-shot TLS server that accepts a single connection, reports the
  # raw request head to the test process, and replies with a canned response.
  defp start_tls_proxy(ssl_opts) do
    test_pid = self()
    ref = make_ref()
    socket_opts = [mode: :binary, packet: :raw, active: false, reuseaddr: true]
    {:ok, listen_socket} = :ssl.listen(0, socket_opts ++ ssl_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)

    spawn_link(fn ->
      {:ok, socket} = :ssl.transport_accept(listen_socket)

      case :ssl.handshake(socket, 10_000) do
        {:ok, socket} ->
          send(test_pid, {ref, :request, recv_ssl_request_head(socket)})
          :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")

          receive do
            :stop -> :ok
          end

        {:error, _reason} ->
          :ok
      end
    end)

    {port, ref}
  end

  # Same as start_tls_proxy/1, but plain TCP.
  defp start_tcp_proxy do
    test_pid = self()
    ref = make_ref()

    {:ok, listen_socket} =
      :gen_tcp.listen(0, mode: :binary, packet: :raw, active: false, reuseaddr: true)

    {:ok, port} = :inet.port(listen_socket)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen_socket)
      send(test_pid, {ref, :request, recv_tcp_request_head(socket)})
      :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")

      receive do
        :stop -> :ok
      end
    end)

    {port, ref}
  end

  defp recv_ssl_request_head(socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :ssl.recv(socket, 0, 2000)
      recv_ssl_request_head(socket, buffer <> data)
    end
  end

  defp recv_tcp_request_head(socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 2000)
      recv_tcp_request_head(socket, buffer <> data)
    end
  end

  defp pkix_test_chain do
    san_extension = {:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"localhost"]}
    cert_opts = [digest: :sha256, key: {:rsa, 2048, 17}]

    :public_key.pkix_test_data(%{
      server_chain: %{
        root: cert_opts,
        intermediates: [],
        peer: cert_opts ++ [extensions: [san_extension]]
      },
      client_chain: %{
        root: cert_opts,
        intermediates: [],
        peer: cert_opts
      }
    })
  end
end
