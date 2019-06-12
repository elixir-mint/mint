defmodule Mint.HTTP1Test do
  use ExUnit.Case, async: true

  alias Mint.{HTTPError, HTTP1, HTTP1.TestServer}

  setup do
    {:ok, port, server_ref} = TestServer.start()
    assert {:ok, conn} = HTTP1.connect(:http, "localhost", port)
    assert_receive {^server_ref, server_socket}

    [conn: conn, port: port, server_ref: server_ref, server_socket: server_socket]
  end

  test "unknown message", %{conn: conn} do
    {:ok, conn, _ref} = HTTP1.request(conn, "GET", "/", [], nil)
    assert HTTP1.stream(conn, :unknown_message) == :unknown
  end

  test "status", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, _conn, [{:status, ^ref, 200}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})
  end

  test "partial status", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, []} = HTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1"})

    assert {:ok, _conn, [{:status, ^ref, 200}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, " 200 OK\r\n"})
  end

  test "headers", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status]} = HTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})

    assert {:ok, _conn, [headers]} =
             HTTP1.stream(conn, {:tcp, conn.socket, "Foo: Bar\r\nBaz: Boz\r\n\r\n"})

    assert {:headers, ^ref, [{"foo", "Bar"}, {"baz", "Boz"}]} = headers
  end

  test "partial headers", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status]} = HTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})

    assert {:ok, conn, []} = HTTP1.stream(conn, {:tcp, conn.socket, "Foo: Bar\r\nB"})

    assert {:ok, _conn, [headers]} = HTTP1.stream(conn, {:tcp, conn.socket, "az: Boz\r\n\r\n"})

    assert {:headers, ^ref, [{"foo", "Bar"}, {"baz", "Boz"}]} = headers
  end

  test "status and headers", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, _conn, [status, headers]} =
             HTTP1.stream(
               conn,
               {:tcp, conn.socket, "HTTP/1.1 200 OK\r\nFoo: Bar\r\n\r\n"}
             )

    assert {:status, ^ref, 200} = status
    assert {:headers, ^ref, [{"foo", "Bar"}]} = headers
  end

  test "body without content-length", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "BODY1"}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n\r\nBODY1"})

    assert {:ok, conn, [{:data, ^ref, "BODY2"}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, "BODY2"})

    assert {:ok, conn, [{:done, ^ref}]} = HTTP1.stream(conn, {:tcp_closed, conn.socket})
    refute HTTP1.open?(conn)
  end

  test "body with content-length", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n"

    assert {:ok, conn, [_status, _headers]} = HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, [{:data, ^ref, "012345678"}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, "012345678"})

    assert {:ok, conn, [{:data, ^ref, "9"}, {:done, ^ref}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, "9XXX"})

    assert conn.buffer == "XXX"
    assert HTTP1.open?(conn)
  end

  test "no body with HEAD request", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "HEAD", "/", [], nil)

    assert {:ok, conn, [_status, _headers, {:done, ^ref}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n\r\nXXX"})

    assert conn.buffer == "XXX"
  end

  test "status, headers, and body", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert {:error, conn, %HTTPError{reason: {:unexpected_data, "X"}}, []} =
             HTTP1.stream(conn, {:tcp, conn.socket, "X"})

    refute HTTP1.open?(conn)
  end

  test "connection: close", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\nconnection: close\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    refute HTTP1.open?(conn)
  end

  test "connection: keep-alive", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.0 200 OK\r\ncontent-length: 1\r\nconnection: keep-alive\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert HTTP1.open?(conn)
  end

  test "implicit connection: close on http/1.0", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.0 200 OK\r\ncontent-length: 1\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    refute HTTP1.open?(conn)
  end

  test "implicit connection: keep-alive on http/1.1", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:data, ^ref, "X"}, {:done, ^ref}]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert HTTP1.open?(conn)
  end

  test "error with multiple content-length headers", %{conn: conn} do
    {:ok, conn, _ref} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 3\r\n\r\nX"

    assert {:error, conn, %HTTPError{reason: :more_than_one_content_length_header},
            [{:status, _ref, 200}]} = HTTP1.stream(conn, {:tcp, conn.socket, response})

    refute HTTP1.open?(conn)
  end

  test "pipeline", %{conn: conn} do
    {:ok, conn, ref1} = HTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref2} = HTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref3} = HTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref4} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"

    assert {:ok, conn, responses} = HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref1, _}, {:headers, ^ref1, _}, {:data, ^ref1, "XXXXX"}, {:done, ^ref1}] =
             responses

    assert {:ok, conn, responses} = HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref2, _}, {:headers, ^ref2, _}, {:data, ^ref2, "XXXXX"}, {:done, ^ref2}] =
             responses

    assert {:ok, conn, responses} = HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref3, _}, {:headers, ^ref3, _}, {:data, ^ref3, "XXXXX"}, {:done, ^ref3}] =
             responses

    assert {:ok, _conn, responses} = HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref4, _}, {:headers, ^ref4, _}, {:data, ^ref4, "XXXXX"}, {:done, ^ref4}] =
             responses
  end

  test "pipeline with multiple responses in single message", %{conn: conn} do
    {:ok, conn, ref1} = HTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref2} = HTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref3} = HTTP1.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref4} = HTTP1.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"
    responses = for _ <- 1..4, do: response, into: ""

    assert {:ok, _conn, responses} = HTTP1.stream(conn, {:tcp, conn.socket, responses})

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
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" <>
        "2\r\n01\r\n2\r\n23\r\n0\r\n\r\nXXX"

    assert {:ok, conn, [status, headers, body, done]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert status == {:status, ref, 200}
    assert headers == {:headers, ref, [{"transfer-encoding", "chunked"}]}
    assert body == {:data, ref, "0123"}
    assert done == {:done, ref}

    assert conn.buffer == "XXX"
  end

  test "body with chunked transfer-encoding with metadata and trailers", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" <>
        "2meta\r\n01\r\n2\r\n23\r\n0meta\r\ntrailer: value\r\n\r\nXXX"

    assert {:ok, conn, [status, headers, body, trailers, done]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert status == {:status, ref, 200}
    assert headers == {:headers, ref, [{"transfer-encoding", "chunked"}]}
    assert body == {:data, ref, "0123"}
    assert trailers == {:headers, ref, [{"trailer", "value"}]}
    assert done == {:done, ref}

    assert conn.buffer == "XXX"
  end

  test "do not chunk if unknown transfer-encoding", %{conn: conn} do
    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: custom, chunked\r\n\r\n" <>
        "2\r\n01\r\n2\r\n23\r\n0\r\n\r\nXXX"

    assert {:ok, _conn, [status, headers, body]} =
             HTTP1.stream(conn, {:tcp, conn.socket, response})

    assert status == {:status, ref, 200}
    assert headers == {:headers, ref, [{"transfer-encoding", "custom, chunked"}]}
    assert body == {:data, ref, "2\r\n01\r\n2\r\n23\r\n0\r\n\r\nXXX"}
  end

  test "close/1", %{conn: conn} do
    assert HTTP1.open?(conn)
    assert {:ok, conn} = HTTP1.close(conn)
    refute HTTP1.open?(conn)
  end

  test "request/5 returns an error if the connection is closed", %{conn: conn} do
    assert {:ok, conn} = HTTP1.close(conn)
    assert {:error, _conn, %HTTPError{reason: :closed}} = HTTP1.request(conn, "GET", "/", [])
  end

  test "open_request_count/1", %{conn: conn} do
    assert HTTP1.open_request_count(conn) == 0

    {:ok, conn, _} = HTTP1.request(conn, "GET", "/", [], nil)
    assert HTTP1.open_request_count(conn) == 1

    {:ok, conn, _} = HTTP1.request(conn, "GET", "/", [], nil)
    assert HTTP1.open_request_count(conn) == 2

    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"

    assert {:ok, conn, _responses} = HTTP1.stream(conn, {:tcp, conn.socket, response})
    assert HTTP1.open_request_count(conn) == 1

    assert {:ok, conn, _responses} = HTTP1.stream(conn, {:tcp, conn.socket, response})
    assert HTTP1.open_request_count(conn) == 0
  end

  test "connect/4 raises if :mode is not :active/:passive", %{port: port} do
    assert_raise ArgumentError, ~r/^the :mode option .* got: :something_else$/, fn ->
      HTTP1.connect(:http, "localhost", port, mode: :something_else)
    end
  end

  test "starting a connection in :passive mode and using recv/3",
       %{port: port, server_ref: server_ref} do
    assert {:ok, conn} = HTTP1.connect(:http, "localhost", port, mode: :passive)
    assert_receive {^server_ref, server_socket}

    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    :ok = :gen_tcp.send(server_socket, "HTTP/1.1 200 OK\r\n")

    assert {:ok, _conn, responses} = HTTP1.recv(conn, 0, 100)
    assert responses == [{:status, ref, 200}]
  end

  test "changing the connection mode with set_mode/2",
       %{conn: conn, server_socket: server_socket} do
    assert_raise ArgumentError, ~r"can't use recv/3", fn ->
      HTTP1.recv(conn, 0, 100)
    end

    assert {:ok, conn} = HTTP1.set_mode(conn, :passive)

    {:ok, conn, ref} = HTTP1.request(conn, "GET", "/", [], nil)

    :ok = :gen_tcp.send(server_socket, "HTTP/1.1 200 OK\r\n")

    assert {:ok, _conn, responses} = HTTP1.recv(conn, 0, 100)
    assert responses == [{:status, ref, 200}]
  end

  test "controlling_process/2", %{conn: conn, server_socket: server_socket} do
    parent = self()
    ref = make_ref()

    new_pid =
      spawn_link(fn ->
        receive do
          message -> send(parent, {ref, message})
        end
      end)

    {:ok, conn, request_ref} = HTTP1.request(conn, "GET", "/", [], nil)

    assert {:ok, conn} = HTTP1.controlling_process(conn, new_pid)

    :ok = :gen_tcp.send(server_socket, "HTTP/1.1 200 OK\r\n")

    assert_receive {^ref, message}, 500
    assert {:ok, _conn, responses} = HTTP1.stream(conn, message)
    assert responses == [{:status, request_ref, 200}]
  end
end
