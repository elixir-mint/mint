defmodule XHTTP1.XHTTP1Test do
  use ExUnit.Case, async: true
  alias XHTTP1.TestServer

  setup do
    {:ok, port} = TestServer.start()
    assert {:ok, conn} = XHTTP1.connect(:http, "localhost", port)
    [conn: conn]
  end

  test "unknown message", %{conn: conn} do
    {:ok, conn, _ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    assert XHTTP1.stream(conn, :unknown_message) == :unknown
  end

  test "status", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, _conn, [{:status, ^ref, 200}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})
  end

  test "partial status", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, []} = XHTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1"})

    assert {:ok, _conn, [{:status, ^ref, 200}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, " 200 OK\r\n"})
  end

  test "headers", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})

    assert {:ok, _conn, [headers]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "Foo: Bar\r\nBaz: Boz\r\n\r\n"})

    assert {:headers, ^ref, [{"foo", "Bar"}, {"baz", "Boz"}]} = headers
  end

  test "partial headers", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})

    assert {:ok, conn, []} = XHTTP1.stream(conn, {:tcp, conn.socket, "Foo: Bar\r\nB"})

    assert {:ok, _conn, [headers]} = XHTTP1.stream(conn, {:tcp, conn.socket, "az: Boz\r\n\r\n"})

    assert {:headers, ^ref, [{"foo", "Bar"}, {"baz", "Boz"}]} = headers
  end

  test "status and headers", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, _conn, [status, headers]} =
             XHTTP1.stream(
               conn,
               {:tcp, conn.socket, "HTTP/1.1 200 OK\r\nFoo: Bar\r\n\r\n"}
             )

    assert {:status, ^ref, 200} = status
    assert {:headers, ^ref, [{"foo", "Bar"}]} = headers
  end

  test "body without content-length", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "BODY1"}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n\r\nBODY1"})

    assert {:ok, conn, [{:data, ^ref, "BODY2"}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "BODY2"})

    assert {:ok, conn, [{:done, ^ref}]} = XHTTP1.stream(conn, {:tcp_closed, conn.socket})
    refute XHTTP1.open?(conn)
  end

  test "body with content-length", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n"

    assert {:ok, conn, [_status, _headers]} = XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, [{:data, ^ref, "012345678"}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "012345678"})

    assert {:ok, conn, [{:data, ^ref, "9"}, {:done, ^ref}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "9XXX"})

    assert conn.buffer == "XXX"
    assert XHTTP1.open?(conn)
  end

  test "no body with HEAD request", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "HEAD", "/", [], nil)

    assert {:ok, conn, [_status, _headers, {:done, ^ref}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n\r\nXXX"})

    assert conn.buffer == "XXX"
  end

  test "status, headers, and body", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nXX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = XHTTP1.stream(conn, {:tcp, conn.socket, "X"})

    assert conn.buffer == "XX"
  end

  test "connection: close", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\nconnection: close\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = XHTTP1.stream(conn, {:tcp, conn.socket, "X"})
    refute XHTTP1.open?(conn)
  end

  test "connection: keep-alive", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.0 200 OK\r\ncontent-length: 1\r\nconnection: keep-alive\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = XHTTP1.stream(conn, {:tcp, conn.socket, "X"})
    assert XHTTP1.open?(conn)
  end

  test "implicit connection: close on http/1.0", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.0 200 OK\r\ncontent-length: 1\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = XHTTP1.stream(conn, {:tcp, conn.socket, "X"})
    refute XHTTP1.open?(conn)
  end

  test "implicit connection: keep-alive on http/1.1", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = XHTTP1.stream(conn, {:tcp, conn.socket, "X"})
    assert XHTTP1.open?(conn)
  end

  test "error with multiple content-length headers", %{conn: conn} do
    {:ok, conn, _ref} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 3\r\n\r\nX"

    assert {:error, conn, :invalid_response, []} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    refute XHTTP1.open?(conn)
  end

  test "pipeline", %{conn: conn} do
    {:ok, conn, ref1} = XHTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref2} = XHTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref3} = XHTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref4} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"

    assert {:ok, conn, responses} = XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref1, _}, {:headers, ^ref1, _}, {:data, ^ref1, "XXXXX"}, {:done, ^ref1}] =
             responses

    assert {:ok, conn, responses} = XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref2, _}, {:headers, ^ref2, _}, {:data, ^ref2, "XXXXX"}, {:done, ^ref2}] =
             responses

    assert {:ok, conn, responses} = XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref3, _}, {:headers, ^ref3, _}, {:data, ^ref3, "XXXXX"}, {:done, ^ref3}] =
             responses

    assert {:ok, _conn, responses} = XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref4, _}, {:headers, ^ref4, _}, {:data, ^ref4, "XXXXX"}, {:done, ^ref4}] =
             responses
  end

  test "pipeline with multiple responses in single message", %{conn: conn} do
    {:ok, conn, ref1} = XHTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref2} = XHTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref3} = XHTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref4} = XHTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"
    responses = for _ <- 1..4, do: response, into: ""

    assert {:ok, _conn, responses} = XHTTP1.stream(conn, {:tcp, conn.socket, responses})

    assert [
             {:status, ^ref1, _},
             {:headers, ^ref1, _},
             {:data, ^ref1, "XXXXX"},
             {:done, ^ref1},
             {:status, ^ref2, _},
             {:headers, ^ref2, _},
             {:data, ^ref2, "XXXXX"},
             {:done, ^ref2},
             {:status, ^ref3, _},
             {:headers, ^ref3, _},
             {:data, ^ref3, "XXXXX"},
             {:done, ^ref3},
             {:status, ^ref4, _},
             {:headers, ^ref4, _},
             {:data, ^ref4, "XXXXX"},
             {:done, ^ref4}
           ] = responses
  end

  test "body with chunked transfer-encoding", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" <>
        "2\r\n01\r\n2\r\n23\r\n0\r\n\r\nXXX"

    assert {:ok, conn, [status, headers, body, done]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert status == {:status, ref, 200}
    assert headers == {:headers, ref, [{"transfer-encoding", "chunked"}]}
    assert body == {:data, ref, "0123"}
    assert done == {:done, ref}

    assert conn.buffer == "XXX"
  end

  test "body with chunked transfer-encoding with metadata and trailers", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" <>
        "2meta\r\n01\r\n2\r\n23\r\n0meta\r\ntrailer: value\r\n\r\nXXX"

    assert {:ok, conn, [status, headers, body, trailers, done]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert status == {:status, ref, 200}
    assert headers == {:headers, ref, [{"transfer-encoding", "chunked"}]}
    assert body == {:data, ref, "0123"}
    assert trailers == {:headers, ref, [{"trailer", "value"}]}
    assert done == {:done, ref}

    assert conn.buffer == "XXX"
  end

  test "do not chunk if unknown transfer-encoding", %{conn: conn} do
    {:ok, conn, ref} = XHTTP1.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: custom, chunked\r\n\r\n" <>
        "2\r\n01\r\n2\r\n23\r\n0\r\n\r\nXXX"

    assert {:ok, _conn, [status, headers, body]} =
             XHTTP1.stream(conn, {:tcp, conn.socket, response})

    assert status == {:status, ref, 200}
    assert headers == {:headers, ref, [{"transfer-encoding", "custom, chunked"}]}
    assert body == {:data, ref, "2\r\n01\r\n2\r\n23\r\n0\r\n\r\nXXX"}
  end
end
