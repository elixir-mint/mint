defmodule XHTTP.UnsafeProxyTest do
  use ExUnit.Case, async: true
  import XHTTP1.TestHelpers
  alias XHTTP.UnsafeProxyConn, as: Conn

  @moduletag :proxy

  test "200 response - http://httpbin.org" do
    assert {:ok, conn} =
             Conn.connect(XHTTP1.Conn, {:http, "localhost", 8888}, {:http, "httpbin.org", 80})

    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "httpbin"
  end
end
