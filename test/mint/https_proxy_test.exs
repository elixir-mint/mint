defmodule Mint.HTTPSProxyTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers
  import Mint.HTTP2.Frame, only: [settings: 1, ping: 1]

  alias Mint.{HTTP, HTTP2, TransportError}
  alias Mint.HTTP2.Frame
  alias Mint.HTTP2.TestServer
  alias Mint.TunnelProxyServer

  @cert_opts [
    certfile: Path.absname("../support/mint/certificate.pem", __DIR__),
    keyfile: Path.absname("../support/mint/key.pem", __DIR__)
  ]

  describe "HTTPS proxies for HTTPS connections" do
    test "HTTP/1 request through the tunnel" do
      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start()
      {:ok, origin_port, origin_ref} = start_http1_origin()

      assert {:ok, conn} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port, [transport_opts: [verify: :verify_none]]},
                 transport_opts: [verify: :verify_none]
               )

      assert HTTP.protocol(conn) == :http1

      assert_receive {^proxy_ref, :connect, head}, 1000
      assert head =~ "CONNECT localhost:#{origin_port} HTTP/1.1\r\n"

      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
      assert_receive {^origin_ref, :origin_request, origin_request}, 1000
      assert origin_request =~ "GET / HTTP/1.1\r\n"

      assert {:ok, _conn, responses} = receive_stream(conn)
      assert [{:status, ^request, 200}, {:headers, ^request, _headers} | rest] = responses
      assert merge_body(rest, request) == "hello"
    end

    test "HTTP/1 forced through the :protocols option" do
      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start()
      {:ok, origin_port, origin_ref} = start_http1_origin()

      assert {:ok, conn} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port, [transport_opts: [verify: :verify_none]]},
                 transport_opts: [verify: :verify_none],
                 protocols: [:http1]
               )

      assert HTTP.protocol(conn) == :http1
      assert_receive {^proxy_ref, :connect, _head}, 1000

      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
      assert_receive {^origin_ref, :origin_request, _origin_request}, 1000

      assert {:ok, _conn, responses} = receive_stream(conn)
      assert [{:status, ^request, 200}, {:headers, ^request, _headers} | rest] = responses
      assert merge_body(rest, request) == "hello"
    end

    test "HTTP/2 negotiated through ALPN in the tunnel" do
      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start()
      {:ok, origin_port, server_socket_task} = TestServer.listen_and_accept()

      assert {:ok, conn} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port, [transport_opts: [verify: :verify_none]]},
                 transport_opts: [verify: :verify_none]
               )

      assert HTTP.protocol(conn) == :http2
      assert_receive {^proxy_ref, :connect, _head}, 1000

      {conn, server_socket} = exchange_server_settings(conn, server_socket_task)

      assert {:ok, conn, ping_ref} = HTTP2.ping(conn)
      server = TestServer.new(server_socket)
      assert [ping(opaque_data: opaque_data)] = TestServer.recv_next_frames(server, 1)

      ping_ack_flags = Frame.set_flags(:ping, [:ack])
      ping_ack = ping(flags: ping_ack_flags, opaque_data: opaque_data)
      :ok = :ssl.send(server_socket, Frame.encode(ping_ack))

      client_socket = HTTP.get_socket(conn)
      assert_receive {:ssl, ^client_socket, _data} = message, 1000
      assert {:ok, _conn, [{:pong, ^ping_ref}]} = HTTP.stream(conn, message)
    end

    test "HTTP/2 forced through the :protocols option" do
      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start()
      {:ok, origin_port, server_socket_task} = TestServer.listen_and_accept()

      assert {:ok, conn} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port, [transport_opts: [verify: :verify_none]]},
                 transport_opts: [verify: :verify_none],
                 protocols: [:http2]
               )

      assert HTTP.protocol(conn) == :http2
      assert_receive {^proxy_ref, :connect, _head}, 1000

      {_conn, _server_socket} = exchange_server_settings(conn, server_socket_task)
    end

    test "verifies the host certificate through the tunnel" do
      %{server_config: server_config, client_config: client_config} = pkix_test_chain()

      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start(server_config)
      {:ok, origin_port, _origin_ref} = start_http1_origin(server_config)

      assert {:ok, conn} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port,
                    [transport_opts: [cacerts: client_config[:cacerts]]]},
                 transport_opts: [cacerts: client_config[:cacerts]]
               )

      assert_receive {^proxy_ref, :connect, _head}, 1000

      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)
      assert [{:status, ^request, 200}, {:headers, ^request, _headers} | rest] = responses
      assert merge_body(rest, request) == "hello"
    end

    @tag :capture_log
    test "fails when the host certificate is not trusted" do
      %{server_config: server_config, client_config: client_config} = pkix_test_chain()

      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start(server_config)
      {:ok, origin_port, _origin_ref} = start_http1_origin()

      assert {:error, %TransportError{reason: reason}} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port,
                    [transport_opts: [cacerts: client_config[:cacerts]]]},
                 transport_opts: [cacerts: client_config[:cacerts]]
               )

      assert {:tls_alert, _alert} = reason

      # The tunnel to the proxy must be torn down when the nested handshake fails.
      assert_receive {^proxy_ref, :connect, _head}, 1000
      assert_receive {^proxy_ref, :closed}, 1000
    end

    @tag :capture_log
    test "returns an error when the TLS handshake inside the tunnel fails" do
      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start()
      {:ok, origin_port} = start_garbage_origin()

      assert {:error, %TransportError{reason: reason}} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port, [transport_opts: [verify: :verify_none]]},
                 transport_opts: [verify: :verify_none]
               )

      refute match?(%TransportError{}, reason)

      # The tunnel to the proxy must be torn down when the nested handshake fails.
      assert_receive {^proxy_ref, :connect, _head}, 1000
      assert_receive {^proxy_ref, :closed}, 1000
    end

    test ":cb_info in transport options cannot override the tunnel transport" do
      {:ok, proxy_port, proxy_ref} = TunnelProxyServer.start()
      {:ok, origin_port, _origin_ref} = start_http1_origin()

      assert {:ok, conn} =
               HTTP.connect(:https, "localhost", origin_port,
                 proxy:
                   {:https, "localhost", proxy_port, [transport_opts: [verify: :verify_none]]},
                 transport_opts: [
                   verify: :verify_none,
                   cb_info: {:gen_tcp, :tcp, :tcp_closed, :tcp_error}
                 ]
               )

      assert HTTP.open?(conn)
      assert_receive {^proxy_ref, :connect, _head}, 1000
    end
  end

  # Completes the connection setup like a real server would: receives the
  # client preface, sends the server SETTINGS and the ack of the client
  # SETTINGS, and waits for the client to ack the server SETTINGS.
  defp exchange_server_settings(conn, server_socket_task) do
    settings_ack_flags = Frame.set_flags(:settings, [:ack])

    {:ok, server_socket} = Task.await(server_socket_task)
    assert :ok = TestServer.perform_http2_handshake(server_socket)

    :ok =
      :ssl.send(server_socket, [
        Frame.encode(settings(params: [])),
        Frame.encode(settings(flags: settings_ack_flags, params: []))
      ])

    client_socket = HTTP.get_socket(conn)
    assert_receive {:ssl, ^client_socket, _data} = message, 1000
    assert {:ok, conn, []} = HTTP.stream(conn, message)

    {:ok, data} = :ssl.recv(server_socket, 0, 1000)
    assert {:ok, frame, ""} = Frame.decode_next(data)
    assert settings(flags: ^settings_ack_flags, params: []) = frame

    :ok = :ssl.setopts(server_socket, active: true)

    {conn, server_socket}
  end

  defp start_http1_origin(cert_opts \\ @cert_opts) do
    socket_opts = [mode: :binary, packet: :raw, active: false, reuseaddr: true]
    {:ok, listen_socket} = :ssl.listen(0, socket_opts ++ cert_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    parent = self()
    ref = make_ref()

    spawn_link(fn ->
      {:ok, socket} = :ssl.transport_accept(listen_socket)

      case :ssl.handshake(socket, 10_000) do
        {:ok, socket} ->
          request = recv_until_blank_line(socket, "")
          send(parent, {ref, :origin_request, request})
          :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")

          receive do
            :stop -> :ok
          end

        {:error, _reason} ->
          :ok
      end
    end)

    {:ok, port, ref}
  end

  defp start_garbage_origin do
    {:ok, listen_socket} = :gen_tcp.listen(0, mode: :binary, active: false)
    {:ok, port} = :inet.port(listen_socket)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen_socket)
      {:ok, _client_hello} = :gen_tcp.recv(socket, 0, 10_000)
      :ok = :gen_tcp.send(socket, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
      :gen_tcp.close(socket)
    end)

    {:ok, port}
  end

  defp recv_until_blank_line(socket, buffer) do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :ssl.recv(socket, 0, 10_000)
      recv_until_blank_line(socket, buffer <> data)
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
