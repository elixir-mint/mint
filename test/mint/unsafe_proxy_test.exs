defmodule Mint.UnsafeProxyTest do
  use ExUnit.Case, async: true
  import Mint.HTTP1.TestHelpers
  alias Mint.UnsafeProxy

  @moduletag :proxy

  test "200 response - http://httpbin.org" do
    assert {:ok, conn} =
             UnsafeProxy.connect({:http, "localhost", 8888}, {:http, "httpbin.org", 80})

    assert {:ok, conn, request} = UnsafeProxy.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert merge_body(responses, request) =~ "httpbin"
  end
end
