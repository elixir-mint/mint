defmodule XHTTP2.ConnTest do
  use ExUnit.Case, async: true

  alias XHTTP2.{
    Conn,
    SSLMock
  }

  setup do
    {:ok, conn} = Conn.connect("localhost", 443, transport: SSLMock)
    [conn: conn]
  end

  test "unknown message", %{conn: conn} do
    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [])
    assert Conn.stream(conn, :unknown_message) == :unknown
  end

  test "server sends RST_STREAM", %{conn: conn} do
    {:ok, conn, ref} = Conn.request(conn, "GET", "/server-sends-rst-stream", [])
    assert_receive {:ssl_mock, _socket, data}
    assert {:ok, %Conn{}, responses} = Conn.stream(conn, {:ssl, conn.socket, data})
    assert [{:closed, ^ref, {:rst_stream, :protocol_error}}] = responses
  end
end
