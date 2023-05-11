defmodule Mint.TunnelProxyTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.TestHelpers

  alias Mint.HTTP
  alias Mint.HttpBin

  @moduletag :proxy
  @moduletag :requires_internet_connection

  test "200 response - http://httpbin.org" do
    # Ensure we only match relevant messages
    send(self(), {:tcp, :not_my_socket, "DATA"})

    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:http, HttpBin.proxy_host(), HttpBin.http_port(), []}
             )

    assert conn.__struct__ == Mint.HTTP1

    assert [{"proxy-agent", <<"tinyproxy/", _version::binary>>}] =
             Mint.HTTP1.get_proxy_headers(conn)

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
               {:https, HttpBin.proxy_host(), HttpBin.https_port(),
                transport_opts: HttpBin.https_transport_opts()}
             )

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "407 response - proxy with missing authentication" do
    assert {:error, %Mint.HTTPError{reason: {:proxy, {:unexpected_status, 407}}}} =
             Mint.HTTP.connect(:https, HttpBin.proxy_host(), HttpBin.https_port(),
               proxy: {:http, "localhost", 8889, []},
               transport_opts: HttpBin.https_transport_opts()
             )
  end

  test "401 response - proxy with invalid authentication" do
    invalid_auth64 = Base.encode64("test:wrong_password")

    assert {:error, %Mint.HTTPError{reason: {:proxy, {:unexpected_status, 401}}}} =
             Mint.HTTP.connect(:https, HttpBin.proxy_host(), HttpBin.https_port(),
               proxy: {:http, "localhost", 8889, []},
               proxy_headers: [{"proxy-authorization", "basic #{invalid_auth64}"}],
               transport_opts: HttpBin.https_transport_opts()
             )
  end

  test "200 response - proxy with valid authentication" do
    auth64 = Base.encode64("test:password")

    assert {:ok, conn} =
             Mint.HTTP.connect(:https, HttpBin.proxy_host(), HttpBin.https_port(),
               proxy: {:http, "localhost", 8889, []},
               proxy_headers: [{"proxy-authorization", "basic #{auth64}"}],
               transport_opts: HttpBin.https_transport_opts()
             )

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "200 response with explicit http2 - https://httpbin.org" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, HttpBin.proxy_host(), HttpBin.https_port(),
                [protocols: [:http2], transport_opts: HttpBin.https_transport_opts()]}
             )

    assert conn.__struct__ == Mint.HTTP2

    assert [{"proxy-agent", <<"tinyproxy/", _version::binary>>}] =
             Mint.HTTP2.get_proxy_headers(conn)

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/user-agent", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "mint/"
  end

  test "200 response without explicit http2 - https://httpbin.org" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:http, "localhost", 8888, []},
               {:https, HttpBin.proxy_host(), HttpBin.https_port(),
                [protocols: [:http1, :http2], transport_opts: HttpBin.https_transport_opts()]}
             )

    assert conn.__struct__ == Mint.HTTP2

    assert [{"proxy-agent", <<"tinyproxy/", _version::binary>>}] =
             Mint.HTTP.get_proxy_headers(conn)

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/user-agent", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "mint/"
  end

  @tag :skip
  test "do not support nested HTTPS connections - https://httpbin.org" do
    assert {:ok, conn} =
             Mint.TunnelProxy.connect(
               {:https, "localhost", 8888, []},
               {:https, HttpBin.proxy_host(), HttpBin.https_port(),
                [transport_opts: HttpBin.https_transport_opts()]}
             )

    assert conn.__struct__ == Mint.HTTP1

    assert [{"proxy-agent", <<"tinyproxy/", _version::binary>>}] =
             Mint.HTTP.get_proxy_headers(conn)

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end
end
