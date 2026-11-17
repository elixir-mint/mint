defmodule Mint.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.{TransportError, HTTP, HttpBin, TestCertificates, TLSTestServer}

  describe "protocol selection" do
    test "SSL - select HTTP1" do
      assert {:ok, conn} =
               HTTP.connect(:https, HttpBin.host(), HttpBin.https_port(),
                 transport_opts: HttpBin.https_transport_opts(),
                 protocols: [:http1]
               )

      assert conn.__struct__ == Mint.HTTP1
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/bytes/1", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [
               {:status, ^request, 200},
               {:headers, ^request, _},
               {:data, ^request, <<_>>},
               {:done, ^request}
             ] = responses
    end

    test "SSL - select HTTP2" do
      assert {:ok, conn} =
               HTTP.connect(:https, HttpBin.host(), HttpBin.https_port(),
                 transport_opts: HttpBin.https_transport_opts()
               )

      assert conn.__struct__ == Mint.HTTP2
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/bytes/1", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [
               {:status, ^request, 200},
               {:headers, ^request, _},
               {:data, ^request, <<_>>},
               {:done, ^request}
             ] = responses
    end
  end

  describe "ssl certificate verification" do
    @tag :capture_log
    test "bad certificate" do
      %{server_config: server_config} = TestCertificates.pkix_test_chain()
      {:ok, port} = TLSTestServer.start(server_config)

      assert {:error, %TransportError{reason: reason}} =
               HTTP.connect(
                 :https,
                 "localhost",
                 port,
                 transport_opts: [log_alert: false, reuse_sessions: false]
               )

      # OTP 21.3 changes the format of SSL errors. Let's support both ways for now.
      assert reason == {:tls_alert, ~c"unknown ca"} or
               match?({:tls_alert, {:unknown_ca, _}}, reason)

      assert {:ok, _conn} =
               HTTP.connect(
                 :https,
                 "localhost",
                 port,
                 transport_opts: [verify: :verify_none]
               )
    end

    @tag :capture_log
    test "bad hostname" do
      %{server_config: server_config, client_config: client_config} =
        TestCertificates.pkix_test_chain(hostname: "wrong.host.example")

      {:ok, port} = TLSTestServer.start(server_config)

      assert {:error, %TransportError{reason: reason}} =
               HTTP.connect(
                 :https,
                 "localhost",
                 port,
                 transport_opts: [
                   cacerts: client_config[:cacerts],
                   log_alert: false,
                   reuse_sessions: false
                 ]
               )

      # OTP 21.3 changes the format of SSL errors. OTP 29 reports a hostname
      # mismatch as a "bad certificate" alert instead of "handshake failure".
      # Support all the variants.
      assert reason == {:tls_alert, ~c"handshake failure"} or
               match?({:tls_alert, {:handshake_failure, _}}, reason) or
               match?({:tls_alert, {:bad_certificate, _}}, reason)

      assert {:ok, _conn} =
               HTTP.connect(
                 :https,
                 "localhost",
                 port,
                 transport_opts: [verify: :verify_none]
               )
    end
  end

  describe "partial chain handling" do
    # The server sends an intermediate signed by an expired root. The client
    # trusts both the expired root and a second root with the intermediate's
    # key, the way Let's Encrypt's ISRG Root X1 was cross-signed by the
    # expired DST Root CA X3.
    test "intermediate cross-signed by an expired root" do
      key = {:rsa, 2048, 17}
      today = Date.utc_today()
      expired = {Date.to_erl(Date.add(today, -30)), Date.to_erl(Date.add(today, -1))}
      san_extension = {:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"localhost"]}

      expired_root =
        :public_key.pkix_test_root_cert(~c"Expired Root",
          key: key,
          validity: expired,
          digest: :sha256
        )

      cross_signed_key = :public_key.generate_key(key)

      trusted_root =
        :public_key.pkix_test_root_cert(~c"Trusted Root", key: cross_signed_key, digest: :sha256)

      %{server_config: server_config} =
        :public_key.pkix_test_data(%{
          server_chain: %{
            root: expired_root,
            intermediates: [[key: cross_signed_key, digest: :sha256]],
            peer: [key: key, digest: :sha256, extensions: [san_extension]]
          },
          client_chain: %{root: [key: key], intermediates: [], peer: [key: key]}
        })

      {:ok, port} = TLSTestServer.start(server_config)

      assert {:ok, _conn} =
               HTTP.connect(:https, "localhost", port,
                 transport_opts: [
                   cacerts: [expired_root.cert, trusted_root.cert],
                   reuse_sessions: false
                 ]
               )
    end
  end

  describe "proxy" do
    @describetag :proxy

    test "200 response - http://httpbin.org" do
      assert {:ok, conn} =
               HTTP.connect(:http, HttpBin.proxy_host(), HttpBin.http_port(),
                 proxy: {:http, "localhost", HttpBin.proxy_port(), []}
               )

      assert conn.__struct__ == Mint.UnsafeProxy
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)
      assert merge_body(responses, request) =~ "httpbin"
    end

    test "200 response - https://httpbin.org" do
      assert {:ok, conn} =
               HTTP.connect(:https, HttpBin.proxy_host(), HttpBin.https_port(),
                 proxy: {:http, "localhost", HttpBin.proxy_port(), []},
                 transport_opts: HttpBin.https_transport_opts()
               )

      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)
      assert merge_body(responses, request) =~ "httpbin.org"
    end

    test "200 response with explicit http2 - https://httpbin.org" do
      assert {:ok, conn} =
               HTTP.connect(:https, HttpBin.proxy_host(), HttpBin.https_port(),
                 proxy: {:http, "localhost", HttpBin.proxy_port(), []},
                 protocols: [:http2],
                 transport_opts: HttpBin.https_transport_opts()
               )

      assert conn.__struct__ == Mint.HTTP2
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/user-agent", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)
      assert merge_body(responses, request) =~ "mint/"
    end

    test "200 response without explicit http2 - https://httpbin.org" do
      assert {:ok, conn} =
               HTTP.connect(:https, HttpBin.proxy_host(), HttpBin.https_port(),
                 proxy: {:http, "localhost", HttpBin.proxy_port(), []},
                 protocols: [:http1, :http2],
                 transport_opts: HttpBin.https_transport_opts()
               )

      assert conn.__struct__ == Mint.HTTP2
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/user-agent", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)
      assert merge_body(responses, request) =~ "mint/"
    end
  end

  describe "information from connection's socket" do
    test "TLSv1.2" do
      %{server_config: server_config, client_config: client_config} =
        TestCertificates.pkix_test_chain()

      {:ok, port} = TLSTestServer.start([versions: [:"tlsv1.2"]] ++ server_config)

      assert {:ok, conn} =
               HTTP.connect(
                 :https,
                 "localhost",
                 port,
                 transport_opts: [keep_secrets: true, cacerts: client_config[:cacerts]]
               )

      assert socket = Mint.HTTP.get_socket(conn)

      if Mint.Core.Transport.SSL.ssl_version() >= [10, 2] do
        assert {:ok, [{:keylog, _keylog_items}]} = :ssl.connection_information(socket, [:keylog])
      else
        assert {:ok, [{:protocol, _protocol}]} = :ssl.connection_information(socket, [:protocol])
      end
    end
  end

  describe "force TLS v1.3 only" do
    test "connects with only TLS 1.3 versions and ciphers" do
      if Mint.Core.Transport.SSL.ssl_version() >= [10, 2] do
        %{server_config: server_config, client_config: client_config} =
          TestCertificates.pkix_test_chain()

        {:ok, port} = TLSTestServer.start(server_config)
        ciphers = :ssl.filter_cipher_suites(:ssl.cipher_suites(:all, :"tlsv1.3"), [])

        opts = [
          transport_opts: [
            versions: [:"tlsv1.3"],
            ciphers: ciphers,
            cacerts: client_config[:cacerts]
          ]
        ]

        assert {:ok, _conn} = HTTP.connect(:https, "localhost", port, opts)
      else
        :ok
      end
    end
  end
end
