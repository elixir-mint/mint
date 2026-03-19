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

  describe "request_body_window/2" do
    test "returns :infinity for an HTTP/1 streaming request", %{conn: conn} do
      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], :stream)
      assert HTTP.request_body_window(conn, ref) == :infinity
    end

    test "raises ArgumentError for an unknown request ref", %{conn: conn} do
      assert_raise ArgumentError, fn ->
        HTTP.request_body_window(conn, make_ref())
      end
    end
  end
end
