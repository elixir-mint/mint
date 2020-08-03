defmodule Mint.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.{TransportError, HTTP}

  @port_http1_http 8101
  @port_http1_https 8102
  @port_http2_https 8202

  describe "https with HTTP1" do
    @describetag :integration

    test "SSL - select HTTP1" do
      assert {:ok, conn} =
               HTTP.connect(
                 :https,
                 "localhost",
                 @port_http1_https,
                 transport_opts: [verify: :verify_none]
               )

      assert conn.__struct__ == Mint.HTTP1
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)

      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [
               {:status, ^request, 200},
               {:headers, ^request, _},
               {:data, ^request, data},
               {:done, ^request}
             ] = responses

      assert data != nil
    end

    @tag :capture_log
    test "SSL - fail to select HTTP2" do
      assert {:error, %TransportError{reason: :protocol_not_negotiated}} =
               HTTP.connect(:https, "localhost", @port_http1_https,
                 protocols: [:http2],
                 transport_opts: [reuse_sessions: false, verify: :verify_none]
               )
    end
  end

  describe "https with HTTP2" do
    @describetag :integration

    test "SSL - select HTTP1" do
      assert {:ok, conn} =
               HTTP.connect(
                 :https,
                 "localhost",
                 @port_http2_https,
                 transport_opts: [verify: :verify_none],
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
               HTTP.connect(
                 :https,
                 "localhost",
                 @port_http2_https,
                 transport_opts: [verify: :verify_none]
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
    @describetag :integration

    test "bad certificate - badssl.com" do
      assert {:error, %TransportError{reason: reason}} =
               HTTP.connect(
                 :https,
                 "untrusted-root.badssl.com",
                 443,
                 transport_opts: [log_alert: false, log_level: :error, reuse_sessions: false]
               )

      # OTP 21.3 changes the format of SSL errors. Let's support both ways for now.
      assert reason == {:tls_alert, 'unknown ca'} or
               match?({:tls_alert, {:unknown_ca, _}}, reason)

      assert {:ok, _conn} =
               HTTP.connect(
                 :https,
                 "untrusted-root.badssl.com",
                 443,
                 transport_opts: [verify: :verify_none]
               )
    end

    test "bad hostname - badssl.com" do
      assert {:error, %TransportError{reason: reason}} =
               HTTP.connect(
                 :https,
                 "wrong.host.badssl.com",
                 443,
                 transport_opts: [log_alert: false, log_level: :error, reuse_sessions: false]
               )

      # OTP 21.3 changes the format of SSL errors. Let's support both ways for now.
      assert reason == {:tls_alert, 'handshake failure'} or
               match?({:tls_alert, {:handshake_failure, _}}, reason)

      assert {:ok, _conn} =
               HTTP.connect(
                 :https,
                 "wrong.host.badssl.com",
                 443,
                 transport_opts: [verify: :verify_none]
               )
    end
  end

  describe "proxy http1" do
    @describetag :proxy

    test "200 response with tcp http1" do
      assert {:ok, conn} =
               HTTP.connect(:http, local_addr(), @port_http1_http,
                 proxy: {:http, "localhost", 8888, []}
               )

      assert conn.__struct__ == Mint.UnsafeProxy
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)

      assert merge_body(responses, request) =~ "Hello world!"
    end

    test "200 response with ssl http1" do
      assert {:ok, conn} =
               HTTP.connect(:https, local_addr(), @port_http1_https,
                 proxy: {:http, "localhost", 8888, []},
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)
      assert merge_body(responses, request) =~ "Hello world!"
    end
  end

  describe "proxy http2" do
    @describetag :proxy

    test "200 response with explicit http2" do
      assert {:ok, conn} =
               HTTP.connect(:https, local_addr(), @port_http2_https,
                 proxy: {:http, "localhost", 8888, []},
                 protocols: [:http2],
                 transport_opts: [verify: :verify_none]
               )

      assert conn.__struct__ == Mint.HTTP2
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/reqinfo", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)
      assert merge_body(responses, request) =~ "Protocol: HTTP/2"
    end

    test "200 response without explicit http2" do
      assert {:ok, conn} =
               HTTP.connect(:https, local_addr(), @port_http2_https,
                 proxy: {:http, "localhost", 8888, []},
                 protocols: [:http1, :http2],
                 transport_opts: [verify: :verify_none]
               )

      assert conn.__struct__ == Mint.HTTP2
      assert {:ok, conn, request} = HTTP.request(conn, "GET", "/reqinfo", [], nil)
      assert {:ok, _conn, responses} = receive_stream(conn)

      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert is_list(headers)
      assert merge_body(responses, request) =~ "Protocol: HTTP/2"
    end
  end
end
