defmodule XHTTP2.ConnTest do
  use ExUnit.Case, async: true

  alias XHTTP2.{
    Conn
  }

  setup context do
    if context[:connect] == false do
      []
    else
      {:ok, port} = XHTTP2.Server.start()
      {:ok, conn} = Conn.connect("localhost", port, transport: :ssl)
      [conn: conn]
    end
  end

  @tag connect: false
  test "using an unknown transport raises an error" do
    message = "the :transport option must be either :gen_tcp or :ssl, got: :some_transport"

    assert_raise ArgumentError, message, fn ->
      Conn.connect("localhost", 80, transport: :some_transport)
    end
  end

  test "unknown message", %{conn: conn} do
    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [])
    assert Conn.stream(conn, :unknown_message) == :unknown
  end

  test "server sends RST_STREAM", %{conn: conn} do
    {:ok, conn, ref} = Conn.request(conn, "GET", "/server-sends-rst-stream", [])

    assert {:ok, %Conn{}, responses} = stream_next_message(conn)
    assert [{:closed, ^ref, {:rst_stream, :protocol_error}}] = responses
  end

  test "when server sends GOAWAY all unprocessed streams are closed", %{conn: conn} do
    {:ok, conn, _ref1} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/server-sends-goaway", [])

    assert {:ok, %Conn{}, responses} = stream_next_message(conn)

    assert [
             {:closed, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:closed, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert {:error, %Conn{}, :closed} = stream_next_message(conn)
  end

  test "server splits headers into multiple CONTINUATION frames", %{conn: conn} do
    {:ok, conn, ref} = Conn.request(conn, "GET", "/split-headers-into-continuation", [])

    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)

    assert [{:status, ^ref, "200"}, {:headers, ^ref, _headers}] = responses

    assert Conn.open?(conn)
  end

  test "server sends a badly encoded header block", %{conn: conn} do
    {:ok, conn, _ref} = Conn.request(conn, "GET", "/server-sends-badly-encoded-hbf", [])

    assert {:error, %Conn{} = conn, :compression_error} = stream_next_message(conn)

    assert Conn.open?(conn) == false
  end

  defp stream_next_message(conn) do
    assert_receive message, 1000
    Conn.stream(conn, message)
  end
end
