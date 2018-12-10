defmodule XHTTP.TunnelProxyTest do
  use ExUnit.Case, async: true
  import XHTTP1.TestHelpers

  @moduletag :proxy

  test "200 response - http://httpbin.org" do
    assert {:ok, conn} =
             XHTTP.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:http, "httpbin.org", 80, []}
             )

    assert {:ok, conn, request} = XHTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "200 response - https://httpbin.org" do
    assert {:ok, conn} =
             XHTTP.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, "httpbin.org", 443, []}
             )

    assert {:ok, conn, request} = XHTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "200 response with explicit http2 - https://http2.golang.org" do
    assert {:ok, conn} =
             XHTTP.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, "http2.golang.org", 443, [protocols: [:http2]]}
             )

    assert {:ok, conn, request} = XHTTP.request(conn, "GET", "/reqinfo", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "Protocol: HTTP/2.0"
  end

  test "200 response without explicit http2 - https://http2.golang.org" do
    assert {:ok, conn} =
             XHTTP.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, "http2.golang.org", 443, [protocols: [:http1, :http2]]}
             )

    assert {:ok, conn, request} = XHTTP.request(conn, "GET", "/reqinfo", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "Protocol: HTTP/2.0"
  end
end
