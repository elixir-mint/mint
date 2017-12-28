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

    assert_receive message, 2000

    assert {:ok, %Conn{}, responses} = Conn.stream(conn, message)
    assert [{:closed, ^ref, {:rst_stream, :protocol_error}}] = responses
  end

  test "when server sends GOAWAY all unprocessed streams are closed", %{conn: conn} do
    {:ok, conn, _ref1} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/server-sends-goaway", [])

    assert_receive message, 2000
    assert {:ok, %Conn{}, responses} = Conn.stream(conn, message)

    assert [
             {:closed, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:closed, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert_receive message, 2000
    assert {:error, %Conn{}, :closed} = Conn.stream(conn, message)
  end

  test "server splits headers into multiple CONTINUATION frames", %{conn: conn} do
    {:ok, conn, ref} = Conn.request(conn, "GET", "/split-headers-into-continuation", [])

    message1 =
      receive do
        message -> message
      end

    message2 =
      receive do
        message -> message
      end

    message3 =
      receive do
        message -> message
      end

    assert {:ok, %Conn{} = conn, []} = Conn.stream(conn, message1)
    assert {:ok, %Conn{} = conn, []} = Conn.stream(conn, message2)
    assert {:ok, %Conn{} = conn, responses} = Conn.stream(conn, message3)

    assert [{:status, ^ref, "200"}, {:headers, ^ref, _headers}] = responses

    assert Conn.open?(conn)
  end
end
