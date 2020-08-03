defmodule Mint.TunnelProxyTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.HTTP

  @moduletag :proxy

  @port_http1_http 8101
  @port_http1_https 8102
  @port_http2_https 8202

  test "200 response - tcp http1" do
    # Ensure we only match relevant messages
    send(self(), {:tcp, :not_my_socket, "DATA"})

    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:http, local_addr(), @port_http1_http, []}
             )

    assert conn.__struct__ == Mint.HTTP1
    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "Hello world!"
  end

  test "200 response - ssl http1" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, local_addr(), @port_http1_https, [transport_opts: [verify: :verify_none]]}
             )

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "Hello world!"
  end

  test "407 response - proxy with missing authentication" do
    assert {:error, %Mint.HTTPError{reason: {:proxy, {:unexpected_status, 407}}}} =
             Mint.HTTP.connect(:https, local_addr(), @port_http2_https,
               proxy: {:http, "localhost", 8889, []},
               transport_opts: [verify: :verify_none]
             )
  end

  test "401 response - proxy with invalid authentication" do
    invalid_auth64 = Base.encode64("test:wrong_password")

    assert {:error, %Mint.HTTPError{reason: {:proxy, {:unexpected_status, 401}}}} =
             Mint.HTTP.connect(:https, local_addr(), @port_http2_https,
               proxy: {:http, "localhost", 8889, []},
               proxy_headers: [{"proxy-authorization", "basic #{invalid_auth64}"}]
             )
  end

  test "200 response - proxy with valid authentication" do
    auth64 = Base.encode64("test:password")

    assert {:ok, conn} =
             Mint.HTTP.connect(:https, local_addr(), @port_http1_https,
               proxy: {:http, "localhost", 8889, []},
               proxy_headers: [{"proxy-authorization", "basic #{auth64}"}],
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

  test "200 response with explicit http2" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, local_addr(), @port_http2_https,
                [
                  protocols: [:http2],
                  transport_opts: [verify: :verify_none]
                ]}
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
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, local_addr(), @port_http2_https,
                [protocols: [:http1, :http2], transport_opts: [verify: :verify_none]]}
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

  @tag :skip
  test "do not support nested HTTPS connections" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:https, "localhost", 8888, []},
               {:https, local_addr(), @port_http2_https,
                [
                  transport_opts: [verify: :verify_none]
                ]}
             )

    assert conn.__struct__ == Mint.HTTP1
    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "Hello world!"
  end
end
