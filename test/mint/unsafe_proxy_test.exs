defmodule Mint.UnsafeProxyTest do
  use ExUnit.Case, async: true
  import Mint.HTTP1.TestHelpers
  alias Mint.UnsafeProxy
  alias Mint.HTTP

  @moduletag :proxy
  @moduletag :requires_internet_connection

  test "200 response - http://httpbin.org" do
    assert {:ok, conn} =
             UnsafeProxy.connect({:http, "localhost", 8888}, {:http, "httpbin.org", 80})

    assert {:ok, conn, request} = UnsafeProxy.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)

    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "407 response - proxy with missing authentication" do
    assert {:ok, conn} =
             HTTP.connect(:http, "httpbin.org", 80, proxy: {:http, "localhost", 8889, []})

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)
    assert [status, _headers | _responses] = responses
    assert {:status, ^request, 407} = status
  end

  test "401 response - proxy with invalid authentication" do
    invalid_auth64 = Base.encode64("test:wrong_password")

    assert {:ok, conn} =
             HTTP.connect(:http, "httpbin.org", 80,
               proxy: {:http, "localhost", 8889, []},
               proxy_headers: [{"proxy-authorization", "basic #{invalid_auth64}"}]
             )

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)
    assert [status, _headers | _responses] = responses
    assert {:status, ^request, 401} = status
  end

  test "200 response - proxy with valid authentication" do
    auth64 = Base.encode64("test:password")

    assert {:ok, conn} =
             HTTP.connect(:http, "httpbin.org", 80,
               proxy: {:http, "localhost", 8889, []},
               proxy_headers: [{"proxy-authorization", "basic #{auth64}"}]
             )

    assert {:ok, conn, request} = HTTP.request(conn, "GET", "/", [], nil)
    assert {:ok, _conn, responses} = receive_stream(conn)
    assert [status, headers | responses] = responses
    assert {:status, ^request, 200} = status
    assert {:headers, ^request, headers} = headers
    assert is_list(headers)
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "Mint.HTTP.protocol/1 on an unsafe proxy connection" do
    assert {:ok, %UnsafeProxy{} = conn} =
             UnsafeProxy.connect({:http, "localhost", 8888}, {:http, "httpbin.org", 80})

    assert Mint.HTTP.protocol(conn) == :http1
  end

  # Regression for #371
  test "Mint.HTTP.is_connection_message/2 works with unsafe proxy connections" do
    import Mint.HTTP, only: [is_connection_message: 2]

    assert {:ok, %UnsafeProxy{state: %{socket: socket}} = conn} =
             UnsafeProxy.connect({:http, "localhost", 8888}, {:http, "httpbin.org", 80})

    assert is_connection_message(conn, {:tcp, socket, "foo"}) == true
    assert is_connection_message(conn, {:tcp_closed, socket}) == true
    assert is_connection_message(conn, {:tcp_error, socket, :nxdomain}) == true

    assert is_connection_message(conn, {:tcp, :not_a_socket, "foo"}) == false
    assert is_connection_message(conn, {:tcp_closed, :not_a_socket}) == false

    assert is_connection_message(_conn = %UnsafeProxy{}, {:tcp, socket, "foo"}) == false

    # If the first argument is not a connection struct, we return false.
    assert is_connection_message(%{socket: socket}, {:tcp, socket, "foo"}) == false
    assert is_connection_message(%URI{}, {:tcp, socket, "foo"}) == false
  end
end
