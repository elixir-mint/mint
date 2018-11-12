defmodule XHTTP1.ProxyTest do
  use ExUnit.Case, async: true
  import XHTTP1.TestHelpers
  alias XHTTP1.Conn

  @moduletag :proxy

  test "200 response - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80, proxy: {"localhost", 8888})
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "httpbin"
  end
end
