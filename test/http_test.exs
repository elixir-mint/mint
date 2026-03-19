defmodule Mint.HTTPTest do
  use ExUnit.Case, async: true
  doctest Mint.HTTP

  alias Mint.{HTTP, HTTP1.TestServer}

  setup do
    {:ok, port, server_ref} = TestServer.start()
    assert {:ok, conn} = HTTP.connect(:http, "localhost", port)
    assert_receive {^server_ref, server_socket}

    [conn: conn, server_socket: server_socket]
  end

  describe "next_body_chunk_size/2" do
    test "returns a positive integer for an active streaming request", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)

      send_window = HTTP.next_body_chunk_size(conn, ref)
      assert is_integer(send_window)
      assert send_window > 0
    end

    test "raises ArgumentError for an unknown request ref", %{conn: conn} do
      assert_raise ArgumentError, fn ->
        HTTP.next_body_chunk_size(conn, make_ref())
      end
    end
  end

  describe "next_body_chunk/3" do
    test "returns body size when body is smaller than send window", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)
      small_body = "hello"
      assert {"hello", ""} = HTTP.next_body_chunk(conn, ref, small_body)
    end

    test "returns send window when body is larger than send window", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)
      chunk_size = HTTP.next_body_chunk_size(conn, ref)
      large_body = :binary.copy(<<0>>, chunk_size + 1000)
      assert {chunk, rest} = HTTP.next_body_chunk(conn, ref, large_body)
      assert byte_size(chunk) == chunk_size
      assert byte_size(rest) == 1000
    end

    test "returns 0 for empty body", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)
      assert {"", ""} = HTTP.next_body_chunk(conn, ref, "")
    end
  end
end
