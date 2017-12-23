defmodule XHTTP2.ConnTest do
  use ExUnit.Case, async: true
  alias XHTTP2.Conn
  alias XHTTP2.TestHelpers.SSLMock

  setup do
    {:ok, conn} = Conn.connect("localhost", 443, transport: SSLMock)
    [conn: conn]
  end

  test "unknown message", %{conn: conn} do
    headers = headers_for_request("GET", "/")
    {:ok, conn, _ref} = Conn.request(conn, headers)
    assert Conn.stream(conn, :unknown_message) == :unknown
  end

  test "server sends RST_STREAM", %{conn: conn} do
    headers = headers_for_request("GET", "/server-sends-rst-stream")
    {:ok, conn, ref} = Conn.request(conn, headers)
    assert_receive {:ssl_mock, _socket, data}
    assert {:ok, conn, responses} = Conn.stream(conn, {:ssl, conn.socket, data})
    assert [{:closed, ^ref, {:rst_stream, :protocol_error}}] = responses
  end

  defp headers_for_request(method, url) do
    uri = URI.parse(url)

    [
      {":method", method},
      {":path", uri.path},
      {":scheme", uri.scheme || "https"},
      {":authority", uri.authority || "https://localhost"}
    ]
  end
end
