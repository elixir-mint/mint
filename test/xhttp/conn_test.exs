defmodule XHTTP.ConnTest do
  use ExUnit.Case, async: true
  alias XHTTP.Conn
  alias XHTTP.ConnTest.TCPMock

  test "unknown message" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [], nil)
    assert Conn.stream(conn, :unknown_message) == :unknown
  end

  test "status" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)

    assert {:ok, _conn, [{:status, ^ref, {{1, 1}, 200, "OK"}}]} =
             Conn.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})
  end

  test "partial status" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, []} = Conn.stream(conn, {:tcp, conn.socket, "HTTP/1.1"})

    assert {:ok, _conn, [{:status, ^ref, {{1, 1}, 200, "OK"}}]} =
             Conn.stream(conn, {:tcp, conn.socket, " 200 OK\r\n"})
  end

  test "headers" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, [_status]} = Conn.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})

    assert {:ok, _conn, [headers]} =
             Conn.stream(conn, {:tcp, conn.socket, "Foo: Bar\r\nBaz: Boz\r\n\r\n"})

    assert {:headers, ^ref, [{"foo", "Bar"}, {"baz", "Boz"}]} = headers
  end

  test "partial headers" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, [_status]} = Conn.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n"})

    assert {:ok, conn, []} = Conn.stream(conn, {:tcp, conn.socket, "Foo: Bar\r\nB"})
    assert {:ok, _conn, [headers]} = Conn.stream(conn, {:tcp, conn.socket, "az: Boz\r\n\r\n"})
    assert {:headers, ^ref, [{"foo", "Bar"}, {"baz", "Boz"}]} = headers
  end

  test "status and headers" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)

    assert {:ok, _conn, [status, headers]} =
             Conn.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\nFoo: Bar\r\n\r\n"})

    assert {:status, ^ref, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^ref, [{"foo", "Bar"}]} = headers
  end

  test "body without content-length" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status, _headers, {:body, ^ref, "BODY1"}]} =
             Conn.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n\r\nBODY1"})

    assert {:ok, conn, [{:body, ^ref, "BODY2"}]} = Conn.stream(conn, {:tcp, conn.socket, "BODY2"})

    assert {:ok, conn, [{:done, ^ref}]} = Conn.stream(conn, {:tcp_close, conn.socket})
    refute Conn.open?(conn)
  end

  test "body with content-length" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n"

    assert {:ok, conn, [_status, _headers]} = Conn.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, [{:body, ^ref, "012345678"}]} =
             Conn.stream(conn, {:tcp, conn.socket, "012345678"})

    assert {:ok, conn, [{:body, ^ref, "9"}, {:done, ^ref}]} =
             Conn.stream(conn, {:tcp, conn.socket, "9XXX"})

    assert conn.buffer == "XXX"
    assert Conn.open?(conn)
  end

  test "no body with HEAD request" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "HEAD", "/", [], nil)

    assert {:ok, conn, [_status, _headers, {:done, ^ref}]} =
             Conn.stream(conn, {:tcp, conn.socket, "HTTP/1.1 200 OK\r\n\r\nXXX"})

    assert conn.buffer == "XXX"
    assert Conn.open?(conn)
  end

  test "status, headers, and body" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nXX"

    assert {:ok, conn, [_status, _headers, {:body, ^ref, "X"}, {:done, ^ref}]} =
             Conn.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = Conn.stream(conn, {:tcp, conn.socket, "X"})

    assert conn.buffer == "XX"
  end

  test "connection: close" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\nconnection: close\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:body, ^ref, "X"}, {:done, ^ref}]} =
             Conn.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = Conn.stream(conn, {:tcp, conn.socket, "X"})
    refute Conn.open?(conn)
  end

  test "connection: keep-alive" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.0 200 OK\r\ncontent-length: 1\r\nconnection: keep-alive\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:body, ^ref, "X"}, {:done, ^ref}]} =
             Conn.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = Conn.stream(conn, {:tcp, conn.socket, "X"})
    assert Conn.open?(conn)
  end

  test "implicit connection: close on http/1.0" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.0 200 OK\r\ncontent-length: 1\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:body, ^ref, "X"}, {:done, ^ref}]} =
             Conn.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = Conn.stream(conn, {:tcp, conn.socket, "X"})
    refute Conn.open?(conn)
  end

  test "implicit connection: keep-alive on http/1.1" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nX"

    assert {:ok, conn, [_status, _headers, {:body, ^ref, "X"}, {:done, ^ref}]} =
             Conn.stream(conn, {:tcp, conn.socket, response})

    assert {:ok, conn, []} = Conn.stream(conn, {:tcp, conn.socket, "X"})
    assert Conn.open?(conn)
  end

  test "error with multiple content-length headers" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 3\r\n\r\nX"

    assert {:error, ^ref, :invalid_response} = Conn.stream(conn, {:tcp, conn.socket, response})
  end

  test "pipeline" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref1} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref4} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"

    assert {:ok, conn, responses} = Conn.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref1, _}, {:headers, ^ref1, _}, {:body, ^ref1, "XXXXX"}, {:done, ^ref1}] =
             responses

    assert {:ok, conn, responses} = Conn.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref2, _}, {:headers, ^ref2, _}, {:body, ^ref2, "XXXXX"}, {:done, ^ref2}] =
             responses

    assert {:ok, conn, responses} = Conn.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref3, _}, {:headers, ^ref3, _}, {:body, ^ref3, "XXXXX"}, {:done, ^ref3}] =
             responses

    assert {:ok, _conn, responses} = Conn.stream(conn, {:tcp, conn.socket, response})

    assert [{:status, ^ref4, _}, {:headers, ^ref4, _}, {:body, ^ref4, "XXXXX"}, {:done, ^ref4}] =
             responses
  end

  test "pipeline with multiple responses in single message" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref1} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref4} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"
    responses = for _ <- 1..4, do: response, into: ""

    assert {:ok, _conn, responses} = Conn.stream(conn, {:tcp, conn.socket, responses})

    assert [
             {:status, ^ref1, _},
             {:headers, ^ref1, _},
             {:body, ^ref1, "XXXXX"},
             {:done, ^ref1},
             {:status, ^ref2, _},
             {:headers, ^ref2, _},
             {:body, ^ref2, "XXXXX"},
             {:done, ^ref2},
             {:status, ^ref3, _},
             {:headers, ^ref3, _},
             {:body, ^ref3, "XXXXX"},
             {:done, ^ref3},
             {:status, ^ref4, _},
             {:headers, ^ref4, _},
             {:body, ^ref4, "XXXXX"},
             {:done, ^ref4}
           ] = responses
  end

  defmodule TCPMock do
    def connect(hostname, port, opts \\ []) do
      Kernel.send(self(), {:tcp_mock, :connect, [hostname, port, opts]})
      {:ok, make_ref()}
    end

    def close(socket) do
      Kernel.send(self(), {:tcp_mock, :close, [socket]})
      :ok
    end

    def getopts(socket, list) do
      Kernel.send(self(), {:tcp_mock, :getopts, [socket, list]})
      {:ok, Enum.map(list, &{&1, 0})}
    end

    def setopts(socket, opts) do
      Kernel.send(self(), {:tcp_mock, :setopts, [socket, opts]})
      :ok
    end

    def send(socket, data, opts \\ []) do
      Kernel.send(self(), {:tcp_mock, :send, [socket, data, opts]})
      :ok
    end
  end
end
