defmodule XHTTP.TunnelProxyConnTest do
  use ExUnit.Case, async: true
  import XHTTP1.TestHelpers
  alias XHTTPN.Conn, as: Conn

  @moduletag :proxy

  test "200 response - http://httpbin.org" do
    assert {:ok, conn} =
             XHTTP.TunnelProxyConn.connect(
               {:http, "localhost", 8888, []},
               {:http, "httpbin.org", 80, []}
             )

    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "200 response - https://httpbin.org" do
    assert {:ok, conn} =
             XHTTP.TunnelProxyConn.connect(
               {:http, "localhost", 8888, []},
               {:https, "httpbin.org", 443, []}
             )

    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "httpbin"
  end
end
