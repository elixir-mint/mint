defmodule Mint.HTTP1.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.{TransportError, HTTP1, HttpBin}

  describe "local httpbin" do
    test "200 response" do
      assert {:ok, conn} = HTTP1.connect(:http, "localhost", 8080)
      assert {:ok, conn, request} = HTTP1.request(conn, "GET", "/", [], nil)
      assert {:ok, conn, responses} = receive_stream(conn)

      assert conn.buffer == ""
      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, headers} = headers
      assert get_header(headers, "connection") == ["keep-alive"]
      assert merge_body(responses, request) =~ "httpbin"
    end

    test "POST body" do
      assert {:ok, conn} = HTTP1.connect(:http, "localhost", 8080)
      assert {:ok, conn, request} = HTTP1.request(conn, "POST", "/post", [], "BODY")
      assert {:ok, conn, responses} = receive_stream(conn)

      assert conn.buffer == ""
      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, _} = headers
      assert merge_body(responses, request) =~ ~s("BODY")
    end

    test "POST body streaming" do
      headers = [{"content-length", "4"}]
      assert {:ok, conn} = HTTP1.connect(:http, "localhost", 8080)
      assert {:ok, conn, request} = HTTP1.request(conn, "POST", "/post", headers, :stream)
      assert {:ok, conn} = HTTP1.stream_request_body(conn, request, "BO")
      assert {:ok, conn} = HTTP1.stream_request_body(conn, request, "DY")
      assert {:ok, conn} = HTTP1.stream_request_body(conn, request, :eof)
      assert {:ok, conn, responses} = receive_stream(conn)

      assert conn.buffer == ""
      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, _} = headers
      assert merge_body(responses, request) =~ ~s("BODY")
    end

    test "pipelining" do
      assert {:ok, conn} = HTTP1.connect(:http, "localhost", 8080)
      assert {:ok, conn, request1} = HTTP1.request(conn, "GET", "/", [], nil)
      assert {:ok, conn, request2} = HTTP1.request(conn, "GET", "/", [], nil)
      assert {:ok, conn, request3} = HTTP1.request(conn, "GET", "/", [], nil)
      assert {:ok, conn, request4} = HTTP1.request(conn, "GET", "/", [], nil)

      assert {:ok, conn, [_status, _headers | responses1]} = receive_stream(conn)
      assert {:ok, conn, [_status, _headers | responses2]} = receive_stream(conn)
      assert {:ok, conn, [_status, _headers | responses3]} = receive_stream(conn)
      assert {:ok, _conn, [_status, _headers | responses4]} = receive_stream(conn)

      assert merge_body(responses1, request1) =~ "A simple HTTP Request &amp; Response Service"

      assert merge_body(responses2, request2) =~ "A simple HTTP Request &amp; Response Service"

      assert merge_body(responses3, request3) =~ "A simple HTTP Request &amp; Response Service"

      assert merge_body(responses4, request4) =~ "A simple HTTP Request &amp; Response Service"
    end

    test "chunked with no chunks" do
      assert {:ok, conn} = HTTP1.connect(:http, "localhost", 8080)
      assert {:ok, conn, request} = HTTP1.request(conn, "GET", "/stream-bytes/0", [], nil)

      assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

      assert byte_size(merge_body(responses, request)) == 0
    end

    test "chunked with single chunk" do
      assert {:ok, conn} = HTTP1.connect(:http, "localhost", 8080)

      assert {:ok, conn, request} =
               HTTP1.request(conn, "GET", "/stream-bytes/1024?chunk_size=1024", [], nil)

      assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

      assert byte_size(merge_body(responses, request)) == 1024
    end

    test "chunked with multiple chunks" do
      assert {:ok, conn} = HTTP1.connect(:http, "localhost", 8080)

      assert {:ok, conn, request} =
               HTTP1.request(conn, "GET", "/stream-bytes/1024?chunk_size=100", [], nil)

      assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

      assert byte_size(merge_body(responses, request)) == 1024
    end
  end

  describe "twitter.com" do
    test "timeout with http" do
      assert {:error, %TransportError{reason: :timeout}} =
               HTTP1.connect(:http, "twitter.com", 80, transport_opts: [timeout: 0])
    end

    test "timeout with https" do
      assert {:error, %TransportError{reason: :timeout}} =
               HTTP1.connect(:https, "twitter.com", 443, transport_opts: [timeout: 0])
    end
  end

  describe "httpbin.org" do
    test "keep alive" do
      assert {:ok, conn} =
               HTTP1.connect(:https, HttpBin.host(), HttpBin.https_port(),
                 transport_opts: HttpBin.https_transport_opts()
               )

      assert {:ok, conn, request} = HTTP1.request(conn, "GET", "/", [], nil)
      assert {:ok, conn, responses} = receive_stream(conn)

      assert conn.buffer == ""
      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, _} = headers
      assert merge_body(responses, request) =~ "Other Utilities"

      assert {:ok, conn} =
               HTTP1.connect(:https, HttpBin.host(), HttpBin.https_port(),
                 transport_opts: HttpBin.https_transport_opts()
               )

      assert {:ok, conn, request} = HTTP1.request(conn, "GET", "/", [], nil)
      assert {:ok, conn, responses} = receive_stream(conn)

      assert conn.buffer == ""
      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, _} = headers
      assert merge_body(responses, request) =~ "Other Utilities"
    end

    test "SSL with missing CA cacertfile" do
      assert {:error, %TransportError{reason: reason}} =
               HTTP1.connect(
                 :https,
                 HttpBin.host(),
                 HttpBin.https_port(),
                 transport_opts: [
                   cacertfile: "test/support/empty_cacerts.pem",
                   log_alert: false,
                   reuse_sessions: false
                 ]
               )

      # OTP 21.3 changes the format of SSL errors. Let's support both ways for now.
      assert reason == {:tls_alert, ~c"unknown ca"} or
               match?({:tls_alert, {:unknown_ca, _}}, reason),
             "expecter reason to look like {:tls_alert, _}, got: #{inspect(reason)}"
    end

    test "SSL, path, long body" do
      assert {:ok, conn} =
               HTTP1.connect(:https, HttpBin.host(), HttpBin.https_port(),
                 transport_opts: HttpBin.https_transport_opts()
               )

      assert {:ok, conn, request} = HTTP1.request(conn, "GET", "/bytes/50000", [], nil)
      assert {:ok, conn, responses} = receive_stream(conn)

      assert conn.buffer == ""
      assert [status, headers | responses] = responses
      assert {:status, ^request, 200} = status
      assert {:headers, ^request, _} = headers
      assert byte_size(merge_body(responses, request)) == 50000
    end

    test "SSL with missing CA cacerts" do
      assert {:error, %TransportError{reason: reason}} =
               HTTP1.connect(
                 :https,
                 "localhost",
                 8443,
                 transport_opts: [cacerts: [], log_alert: false, reuse_sessions: false]
               )

      # OTP 21.3 changes the format of SSL errors. Let's support both ways for now.
      # Newer OTP versions treat empty list for `cacerts` as if the option was not set
      assert reason == {:tls_alert, ~c"unknown ca"} or
               match?({:tls_alert, {:unknown_ca, _}}, reason) or
               reason == {:options, {:cacertfile, []}} or :closed
    end
  end

  describe "badssl.com" do
    @describetag :requires_internet_connection

    @tag :capture_log
    test "SSL with bad certificate" do
      assert {:error, %TransportError{reason: reason}} =
               HTTP1.connect(:https, "untrusted-root.badssl.com", 443,
                 transport_opts: [log_alert: false, reuse_sessions: false]
               )

      # OTP 21.3 changes the format of SSL errors. Let's support both ways for now.
      assert reason == {:tls_alert, ~c"unknown ca"} or
               match?({:tls_alert, {:unknown_ca, _}}, reason)

      assert {:ok, _conn} =
               HTTP1.connect(:https, "untrusted-root.badssl.com", 443,
                 transport_opts: [verify: :verify_none]
               )
    end

    @tag :capture_log
    test "SSL with bad hostname" do
      assert {:error, %TransportError{reason: reason}} =
               HTTP1.connect(:https, "wrong.host.badssl.com", 443,
                 transport_opts: [log_alert: false, reuse_sessions: false]
               )

      # OTP 21.3 changes the format of SSL errors. Let's support both ways for now.
      assert reason == {:tls_alert, ~c"handshake failure"} or
               match?({:tls_alert, {:handshake_failure, _}}, reason)

      assert {:ok, _conn} =
               HTTP1.connect(:https, "wrong.host.badssl.com", 443,
                 transport_opts: [verify: :verify_none]
               )
    end
  end
end
