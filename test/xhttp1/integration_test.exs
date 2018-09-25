defmodule XHTTP1.IntegrationTest do
  use ExUnit.Case, async: true
  import XHTTP1.TestHelpers
  alias XHTTP1.Conn

  @moduletag :integration

  test "200 response - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, transport: XHTTP.Transport.TCP)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert get_header(headers, "connection") == ["keep-alive"]
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "ssl, path, long body - httpbin.org" do
    assert {:ok, conn} =
             Conn.connect(
               "httpbin.org",
               443,
               transport: XHTTP.Transport.SSL,
               transport_opts: [cacertfile: "test/support/cacerts.pem"]
             )

    assert {:ok, conn, request} = Conn.request(conn, "GET", "/bytes/50000", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, _} = headers
    assert byte_size(merge_body(responses, request)) == 50000
  end

  test "keep alive - httpbin.org" do
    assert {:ok, conn} =
             Conn.connect(
               "httpbin.org",
               443,
               transport: XHTTP.Transport.SSL,
               transport_opts: [cacertfile: "test/support/cacerts.pem"]
             )

    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "Other Utilities"

    assert {:ok, conn} =
             Conn.connect(
               "httpbin.org",
               443,
               transport: XHTTP.Transport.SSL,
               transport_opts: [cacertfile: "test/support/cacerts.pem"]
             )

    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "Other Utilities"
  end

  test "POST body - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, transport: XHTTP.Transport.TCP)
    assert {:ok, conn, request} = Conn.request(conn, "POST", "/post", [], "BODY")
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ ~s("BODY")
  end

  test "POST body streaming - httpbin.org" do
    headers = [{"content-length", "4"}]
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, transport: XHTTP.Transport.TCP)
    assert {:ok, conn, request} = Conn.request(conn, "POST", "/post", headers, :stream)
    assert {:ok, conn} = Conn.stream_request_body(conn, request, "BO")
    assert {:ok, conn} = Conn.stream_request_body(conn, request, "DY")
    assert {:ok, conn} = Conn.stream_request_body(conn, request, :eof)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ ~s("BODY")
  end

  test "pipelining - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, transport: XHTTP.Transport.TCP)
    assert {:ok, conn, request1} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, request2} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, request3} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, request4} = Conn.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status, _headers | responses1]} = receive_stream(conn)
    assert {:ok, conn, [_status, _headers | responses2]} = receive_stream(conn)
    assert {:ok, conn, [_status, _headers | responses3]} = receive_stream(conn)
    assert {:ok, _conn, [_status, _headers | responses4]} = receive_stream(conn)

    assert merge_body(responses1, request1) =~ "A simple HTTP Request &amp; Response Service"

    assert merge_body(responses2, request2) =~ "A simple HTTP Request &amp; Response Service"

    assert merge_body(responses3, request3) =~ "A simple HTTP Request &amp; Response Service"

    assert merge_body(responses4, request4) =~ "A simple HTTP Request &amp; Response Service"
  end

  # TODO: Figure out what is happening here. Server is responding without
  # content-length or transfer-encoding headers, this means we should read body
  # until connection is closed by server. We timeout in this test but curl
  # returns immediately, so somehow curl knows much earlier that the body is
  # zero length.
  # $ curl -vv httpbin.org/stream-bytes/0
  @tag :skip
  test "chunked no chunks - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, transport: XHTTP.Transport.TCP)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/stream-bytes/0", [], nil)

    assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

    assert byte_size(merge_body(responses, request)) == 1024
  end

  test "chunked single chunk - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, transport: XHTTP.Transport.TCP)

    assert {:ok, conn, request} =
             Conn.request(conn, "GET", "/stream-bytes/1024?chunk_size=1024", [], nil)

    assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

    assert byte_size(merge_body(responses, request)) == 1024
  end

  test "chunked multiple chunks - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, transport: XHTTP.Transport.TCP)

    assert {:ok, conn, request} =
             Conn.request(conn, "GET", "/stream-bytes/1024?chunk_size=100", [], nil)

    assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

    assert byte_size(merge_body(responses, request)) == 1024
  end

  test "ssl, bad certificate - badssl.com" do
    assert {:error, {:tls_alert, 'unknown ca'}} =
             Conn.connect(
               "untrusted-root.badssl.com",
               443,
               transport: XHTTP.Transport.SSL,
               transport_opts: [cacertfile: "test/support/cacerts.pem", log_alert: false]
             )

    assert {:ok, _conn} =
             Conn.connect(
               "untrusted-root.badssl.com",
               443,
               transport: XHTTP.Transport.SSL,
               transport_opts: [verify: :verify_none]
             )
  end

  test "ssl, bad hostname - badssl.com" do
    assert {:error, {:tls_alert, 'handshake failure'}} =
             Conn.connect(
               "wrong.host.badssl.com",
               443,
               transport: XHTTP.Transport.SSL,
               transport_opts: [cacertfile: "test/support/cacerts.pem", log_alert: false]
             )

    assert {:ok, _conn} =
             Conn.connect(
               "wrong.host.badssl.com",
               443,
               transport: XHTTP.Transport.SSL,
               transport_opts: [verify: :verify_none]
             )
  end
end
