defmodule XHTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  alias XHTTP2.Conn

  @moduletag :integration

  describe "http2.golang.org" do
    test "connecting" do
      assert {:ok, %Conn{} = conn} = Conn.connect("http2.golang.org", 443)
      assert Conn.open?(conn)
      settings = Conn.read_server_settings(conn)
      max_concurrent_streams = Keyword.fetch!(settings, :max_concurrent_streams)
      assert is_integer(max_concurrent_streams) and max_concurrent_streams >= 0

      IO.inspect(conn)
    end

    test "GET /reqinfo" do
      assert {:ok, %Conn{} = conn} = Conn.connect("http2.golang.org", 443)

      assert {:ok, %Conn{} = conn, req_id} =
               Conn.request(conn, [
                 {":method", "GET"},
                 {":path", "/reqinfo"},
                 {":authority", "https://http2.golang.org:443"},
                 {":scheme", "https"}
               ])

      assert {:ok, %Conn{} = conn, responses} = stream_message(conn)
      assert [{:headers, ^req_id, _headers}] = responses

      assert {:ok, %Conn{} = conn, responses} = stream_message(conn)
      assert [{:data, ^req_id, data}, {:done, ^req_id}] = responses
      assert data =~ "Method: GET"

      assert conn.buffer == ""
      assert Conn.open?(conn)
    end
  end

  defp stream_message(conn) do
    receive do
      message -> Conn.stream(conn, message)
    after
      10_000 -> flunk("did not receive any message after 10s")
    end
  end
end
