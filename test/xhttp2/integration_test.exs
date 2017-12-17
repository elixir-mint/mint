defmodule XHTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  alias XHTTP2.Conn

  @moduletag :integration

  setup context do
    case context.connect do
      {host, port} ->
        assert {:ok, %Conn{} = conn} = Conn.connect(host, port)
        [conn: conn]

      _other ->
        []
    end
  end

  describe "http2.golang.org" do
    @moduletag connect: {"http2.golang.org", 443}

    test "GET /reqinfo", %{conn: conn} do
      assert {:ok, %Conn{} = conn, req_id} =
               Conn.request(conn, headers_for_request("GET", "https://http2.golang.org/reqinfo"))

      assert {:ok, %Conn{} = conn, responses} = stream_message(conn)
      assert [{:headers, ^req_id, _headers}] = responses

      assert {:ok, %Conn{} = conn, responses} = stream_message(conn)
      assert [{:data, ^req_id, data}, {:done, ^req_id}] = responses
      assert data =~ "Method: GET"

      assert conn.buffer == ""
      assert Conn.open?(conn)
    end

    test "PUT /ECHO", %{conn: conn} do
      headers = headers_for_request("PUT", "https://http2.golang.org/ECHO")

      assert {:ok, %Conn{} = conn, req_id} = Conn.request(conn, headers, "hello world")

      # TODO: this is a WINDOW_UPDATE. Figure out how to not care about this in the test.
      assert {:ok, %Conn{} = conn, []} = stream_message(conn)

      assert {:ok, %Conn{} = conn, responses} = stream_message(conn)
      assert [{:headers, ^req_id, _headers}, {:data, ^req_id, data}] = responses
      assert data == "HELLO WORLD"

      assert {:ok, %Conn{} = conn, responses} = stream_message(conn)
      assert [{:data, ^req_id, ""}, {:done, ^req_id}] = responses

      assert conn.buffer == ""
      assert Conn.open?(conn)
    end
  end

  defp headers_for_request(method, url) do
    uri = URI.parse(url)

    [
      {":method", method},
      {":path", uri.path},
      {":scheme", uri.scheme},
      {":authority", uri.authority}
    ]
  end

  defp stream_message(conn) do
    receive do
      message -> Conn.stream(conn, message)
    after
      10_000 -> flunk("did not receive any message after 10s")
    end
  end
end
