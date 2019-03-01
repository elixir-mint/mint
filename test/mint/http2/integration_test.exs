defmodule HTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP2.TestHelpers

  alias Mint.HTTP2

  @moduletag :integration

  setup context do
    case context.connect do
      {host, port} ->
        assert {:ok, %HTTP2{} = conn} = HTTP2.connect(:https, host, port)
        [conn: conn]

      _other ->
        []
    end
  end

  describe "http2.golang.org" do
    @describetag connect: {"http2.golang.org", 443}

    test "GET /reqinfo", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/reqinfo", [])

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, 200},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data =~ "Method: GET"

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /clockstream", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/clockstream", [])

      assert {:ok, %HTTP2{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:status, ^req_id, 200}, {:headers, ^req_id, _headers}] = responses

      assert_receive message, 5000
      assert {:ok, %HTTP2{} = conn, responses} = HTTP2.stream(conn, message)
      assert [{:data, ^req_id, data}] = responses
      assert data =~ "# ~1KB of junk to force browsers to start rendering immediately"

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
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/file/gopher.png", [])
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
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/serverpush", [])
      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

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

    test "ping", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [])

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
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [])

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
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/httpbin/", [])

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status == 200
      assert is_list(headers)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  defp stream_messages_until_response(conn) do
    assert_receive message, 1000

    case HTTP2.stream(conn, message) do
      {:ok, %HTTP2{} = conn, []} -> stream_messages_until_response(conn)
      other -> other
    end
  end

  # TODO: certificate verification; badssl.com does not seem to support HTTP2
end
