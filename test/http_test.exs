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

  describe "get_send_window/2" do
    test "returns a positive integer for an active streaming request", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)

      send_window = HTTP.get_send_window(conn, ref)
      assert is_integer(send_window)
      assert send_window > 0
    end
  end

  describe "next_body_chunk_size/3" do
    test "returns body size when body is smaller than send window", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)
      small_body = "hello"
      assert HTTP.next_body_chunk_size(conn, ref, small_body) == byte_size(small_body)
    end

    test "returns send window when body is larger than send window", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)
      send_window = HTTP.get_send_window(conn, ref)
      large_body = :binary.copy(<<0>>, send_window + 1000)
      assert HTTP.next_body_chunk_size(conn, ref, large_body) == send_window
    end

    test "returns 0 for empty body", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)
      assert HTTP.next_body_chunk_size(conn, ref, "") == 0
    end
  end
end
