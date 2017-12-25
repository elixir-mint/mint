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

  test "when server sends GOAWAY all unprocessed streams are closed", %{conn: conn} do
    {:ok, conn, _ref1} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/server-sends-goaway", [])

    assert_receive {:ssl_mock, _socket, data}
    assert {:ok, %Conn{} = conn, responses} = Conn.stream(conn, {:ssl, conn.socket, data})

    assert [
             {:closed, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:closed, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert Conn.open?(conn) == false
  end
end
