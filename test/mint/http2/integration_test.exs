defmodule HTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP2.TestHelpers

  alias Mint.HTTP2

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
        assert {:ok, %HTTP2{} = conn} =
                 HTTP2.connect(:https, host, port, transport_opts: transport_opts)

        [conn: conn]

      :error ->
        []
    end
  end

  test "TCP - nghttp2.org" do
    assert {:ok, %HTTP2{} = conn} = HTTP2.connect(:http, "nghttp2.org", 80)

    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/httpbin/", [], nil)

    assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

    assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
    assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

    assert status == 200
    assert is_list(headers)

    assert conn.buffer == ""
    assert HTTP2.open?(conn)
  end

  describe "httpbin.org" do
    @describetag connect: {"httpbin.org", 443}

    test "GET /user-agent", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/user-agent", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, 200},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:data, ^req_id, ""},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data =~ "mint/"

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  describe "http2.golang.org" do
    @describetag skip: """
                 http2.golang.org has been decommisioned.
                 Re-enable these tests  in the future if we figure out a test server that supports
                 a similar set of features.
                 """

    test "GET /clockstream", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/clockstream", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:status, ^req_id, 200}, {:headers, ^req_id, _headers} | rest] = responses

      conn =
        if rest != [] do
          assert [{:data, ^req_id, data}] = rest
          assert data =~ "# ~1KB of junk to force browsers to start rendering immediately"
          conn
        else
          assert_receive message, 5000
          assert {:ok, %HTTP2{} = conn, responses} = HTTP2.stream(conn, message)
          assert [{:data, ^req_id, data}] = responses
          assert data =~ "# ~1KB of junk to force browsers to start rendering immediately"
          conn
        end

      assert_receive message, 5000
      assert {:ok, %HTTP2{} = conn, responses} = HTTP2.stream(conn, message)
      assert [{:data, ^req_id, data}] = responses
      assert data =~ ~r/\A\d{4}-\d{2}-\d{2}/

      assert HTTP2.open?(conn)
    end

    test "PUT /ECHO", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} =
               HTTP2.request(conn, "PUT", "/ECHO", [], "hello world")

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, 200},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:data, ^req_id, ""},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data == "HELLO WORLD"

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /file/gopher.png", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/file/gopher.png", [], nil)
      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, headers},
               {:data, ^ref, data1},
               {:data, ^ref, data2},
               {:data, ^ref, data3},
               {:done, ^ref}
             ] = responses

      assert is_list(headers)
      assert is_binary(data1)
      assert is_binary(data2)
      assert is_binary(data3)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "ping", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /serverpush", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/serverpush", [], nil)
      assert {:ok, %HTTP2{} = _conn, responses} = receive_stream(conn)

      # TODO: improve this test by improving receive_stream/1.
      assert [
               {:push_promise, ^req_id, _promised_req_id1, _headers1},
               {:push_promise, ^req_id, _promised_req_id2, _headers2},
               {:push_promise, ^req_id, _promised_req_id3, _headers3},
               {:push_promise, ^req_id, _promised_req_id4, _headers4} | _
             ] = responses
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

      assert [{:status, ^ref, 200}, {:headers, ^ref, headers} | rest] = responses
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

  defp stream_messages_until_response(conn) do
    assert_receive message, 1000

    case HTTP2.stream(conn, message) do
      {:ok, %HTTP2{} = conn, [:settings]} ->
        stream_messages_until_response(conn)

      {:ok, %HTTP2{} = conn, [:settings_ack]} ->
        stream_messages_until_response(conn)

      {:ok, %HTTP2{} = conn, [:settings, :settings_ack | rest]} ->
        {:ok, %HTTP2{} = conn, rest}

      {:ok, %HTTP2{} = conn, []} ->
        stream_messages_until_response(conn)

      other ->
        other
    end
  end

  # TODO: certificate verification; badssl.com does not seem to support HTTP2
end
