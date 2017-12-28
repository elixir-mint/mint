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
    assert Conn.stream(conn, :unknown_message) == :unknown
  end

  test "closed-socket messages are treated as errors", %{conn: conn} do
    assert {:error, %Conn{} = conn, :closed, []} = Conn.stream(conn, {:ssl_closed, conn.socket})
    assert Conn.open?(conn) == false
  end

  test "socket error messages are treated as errors", %{conn: conn} do
    message = {:ssl_error, conn.socket, :etimeout}
    assert {:error, %Conn{} = conn, :etimeout, []} = Conn.stream(conn, message)
    assert Conn.open?(conn) == false
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

    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)

    assert [
             {:closed, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:closed, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert {:error, %Conn{} = conn, :closed, []} = stream_next_message(conn)

    assert Conn.open?(conn) == false
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

    assert {:error, %Conn{} = conn, :compression_error, []} = stream_next_message(conn)

    assert Conn.open?(conn) == false
  end

  test "server sends a CONTINUATION frame outside of headers streaming", %{conn: conn} do
    path = "/server-sends-continuation-outside-headers-streaming"
    {:ok, conn, _ref} = Conn.request(conn, "GET", path, [])

    assert {:error, %Conn{} = conn, :protocol_error, []} = stream_next_message(conn)
    assert Conn.open?(conn) == false
  end

  test "server sends a non-CONTINUATION frame while streaming headers", %{conn: conn} do
    path = "/server-sends-frame-while-streaming-headers"
    {:ok, conn, _ref} = Conn.request(conn, "GET", path, [])

    assert {:error, %Conn{} = conn, :protocol_error, []} = stream_next_message(conn)
    assert Conn.open?(conn) == false
  end

  test "server sends a HEADERS with END_STREAM set but not END_HEADERS", %{conn: conn} do
    path = "/server-ends-stream-but-not-headers"
    {:ok, conn, ref} = Conn.request(conn, "GET", path, [])
    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)
    assert [{:status, ^ref, "200"}, {:headers, ^ref, _headers}, {:done, ^ref}] = responses
    assert Conn.open?(conn) == true
  end

  test "server sends a response without a :status header", %{conn: conn} do
    {:ok, conn, ref} = Conn.request(conn, "GET", "/no-status-header-in-response", [])
    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)
    assert [{:closed, ^ref, {:protocol_error, :missing_status_header}}] = responses
    assert Conn.open?(conn) == true
  end

  test "server sends a frame with the wrong stream id", %{conn: conn} do
    {:ok, conn, _ref} = Conn.request(conn, "GET", "/server-sends-frame-with-wrong-stream-id", [])
    assert {:error, %Conn{} = conn, :protocol_error, []} = stream_next_message(conn)
    assert Conn.open?(conn) == false
  end

  defp stream_next_message(conn) do
    assert_receive message, 1000
    Conn.stream(conn, message)
  end
end
