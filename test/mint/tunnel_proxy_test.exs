defmodule Mint.TunnelProxyTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.HTTP

  @moduletag :proxy

  test "200 response - http://httpbin.org" do
    # Ensure we only match relevant messages
    send(self(), {:tcp, :not_my_socket, "DATA"})

    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:http, "httpbin.org", 80, []}
             )

    assert conn.__struct__ == Mint.HTTP1
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
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, "httpbin.org", 443, []}
             )

    assert conn.__struct__ == Mint.HTTP1
    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "407 response - proxy authentication test" do
    assert {:error, %Mint.HTTPError{reason: {:proxy, {:unexpected_status, 407}}}} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8889, []},
               {:https, "httpbin.org", 443, []}
             )
  end

  test "401 response - proxy authentication test" do
    invalid_auth64 = Base.encode64("test:password1")

    assert {:error, %Mint.HTTPError{reason: {:proxy, {:unexpected_status, 401}}}} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8889,
                [headers: [{"proxy-authorization", "basic #{invalid_auth64}"}]]},
               {:https, "httpbin.org", 443, []}
             )
  end

  test "200 response - proxy authentication test" do
    auth64 = Base.encode64("test:password")

    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8889,
                [headers: [{"proxy-authorization", "basic #{auth64}"}]]},
               {:https, "httpbin.org", 443, []}
             )

    assert conn.__struct__ == Mint.HTTP1
    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "200 response with explicit http2 - https://http2.golang.org" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, "http2.golang.org", 443, [protocols: [:http2]]}
             )

    assert conn.__struct__ == Mint.HTTP2
    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/reqinfo", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "Protocol: HTTP/2.0"
  end

  test "200 response without explicit http2 - https://http2.golang.org" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, "http2.golang.org", 443, [protocols: [:http1, :http2]]}
             )

    assert conn.__struct__ == Mint.HTTP2
    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/reqinfo", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "Protocol: HTTP/2.0"
  end

  @tag :skip
  test "do not support nested HTTPS connections - https://httpbin.org" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:https, "localhost", 8888, []},
               {:https, "httpbin.org", 443, []}
             )

    assert conn.__struct__ == Mint.HTTP1
    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end
end
