defmodule HTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP2.TestHelpers

  alias Mint.HTTP2
  alias Mint.HttpBin

  @moduletag :requires_internet_connection

  setup context do
    transport_opts =
      if Mint.Core.Transport.SSL.ssl_version() >= [10, 2] do
        [{:versions, [:"tlsv1.2", :"tlsv1.3"]}]
      else
        []
      end

    case Map.fetch(context, :connect) do
      {:ok, {host, port}} ->
        extra_transport_opts = Map.get(context, :transport_opts, [])

        assert {:ok, %HTTP2{} = conn} =
                 HTTP2.connect(:https, host, port,
                   transport_opts: transport_opts ++ extra_transport_opts
                 )

        [conn: conn]

      :error ->
        []
    end
  end

  test "TCP - nghttp2.org" do
    assert {:ok, %HTTP2{} = conn} = HTTP2.connect(:http, "nghttp2.org", 80)

    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/httpbin/", [], nil)

    # For some reason, on OTP 26+ we get an SSL message sneaking in here. Instead of going
    # crazy trying to debug it, for now let's just swallow it.
    if System.otp_release() >= "26" do
      assert_receive {:ssl, _socket, _data}, 1000
    end

    assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

    assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
    assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

    assert status == 200
    assert is_list(headers)

    assert conn.buffer == ""
    assert HTTP2.open?(conn)
  end

  describe "httpbin.org" do
    @describetag connect: {HttpBin.host(), HttpBin.https_port()},
                 transport_opts: HttpBin.https_transport_opts()

    test "GET /user-agent", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/user-agent", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, 200},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data =~ "mint/"

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /image/png", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/image/png", [], nil)
      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, headers},
               {:data, ^ref, data1},
               {:data, ^ref, data2},
               {:done, ^ref}
             ] = responses

      assert is_list(headers)
      assert is_binary(data1)
      assert is_binary(data2)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "ping", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  describe "twitter.com" do
    @moduletag connect: {"twitter.com", 443}
    @browser_user_agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"

    test "ping", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} =
               HTTP2.request(conn, "GET", "/", [{"user-agent", @browser_user_agent}], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
      assert status in [200, 302]

      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert is_list(headers)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  describe "facebook.com" do
    @describetag connect: {"facebook.com", 443}

    test "ping", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status == 301
      assert is_list(headers)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  describe "nghttp2.org/httpbin" do
    @describetag connect: {"nghttp2.org", 443}

    test "ping", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/httpbin/", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status == 200
      assert is_list(headers)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  describe "robynthinks.wordpress.com" do
    @describetag connect: {"robynthinks.wordpress.com", 443}

    test "GET /feed/ - regression for #171", %{conn: conn} do
      # Using non-downcased header meant that HPACK wouldn't find it in the
      # static built-in headers table and so it wouldn't encode it correctly.
      headers = [{"If-Modified-Since", "Wed, 26 May 2019 07:43:40 GMT"}]
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/feed/", headers, nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, _headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status in [200, 304]

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  describe "www.shopify.com" do
    @describetag connect: {"www.shopify.com", 443}

    if List.to_integer(:erlang.system_info(:otp_release)) < 23 do
      @tag :skip
    end

    # Informational responses were the issue.s
    # https://github.com/elixir-mint/mint/issues/349
    test "GET / with specific User-Agent header - regression for #349", %{conn: conn} do
      assert %HTTP2{} = conn

      assert {:ok, %HTTP2{} = conn, ref} =
               HTTP2.request(conn, "GET", "/", [{"user-agent", "curl/7.68.0"}], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      case responses do
        [
          {:status, ^ref, informational_status},
          {:headers, ^ref, informational_headers},
          {:status, ^ref, status},
          {:headers, ^ref, headers}
          | rest
        ] ->
          assert informational_status == 103
          assert {"link", _} = List.keyfind(informational_headers, "link", 0)
          assert status == 200
          assert is_list(headers) and length(headers) > 0

          assert Enum.count(rest, &match?({:data, ^ref, _data}, &1)) >= 1
          assert List.last(rest) == {:done, ref}

        [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] ->
          assert status == 200
          assert is_list(headers) and length(headers) > 0
          assert Enum.count(rest, &match?({:data, ^ref, _data}, &1)) >= 1
          assert List.last(rest) == {:done, ref}

        _other ->
          flunk(
            "Unexpected responses. Expected status + headers + data, or informational " <>
              "response + status + headers + data, got:\n#{inspect(responses, pretty: true)}"
          )
      end

      assert HTTP2.open?(conn)
    end
  end

  # TODO: certificate verification; badssl.com does not seem to support HTTP2
end
