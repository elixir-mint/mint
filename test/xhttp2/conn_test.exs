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
