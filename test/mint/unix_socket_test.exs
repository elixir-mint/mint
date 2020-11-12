defmodule Mint.UnitSocketTest do
  use ExUnit.Case, async: true

  alias Mint.{HTTP, TestSocketServer}

  require HTTP

  unix? = match?({:unix, _}, :os.type())
  otp_19? = System.otp_release() >= "19"
  @moduletag skip: not (unix? and otp_19?)

  test "starting an HTTP connection to a Unix domain socket works" do
    {:ok, address, server_ref} = TestSocketServer.start(ssl: false)

    assert {:ok, conn} = HTTP.connect(:http, address, 0, mode: :passive, hostname: "localhost")

    assert_receive {^server_ref, server_socket}

    {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], nil)

    :ok = :gen_tcp.send(server_socket, "HTTP/1.1 200 OK\r\n")

    assert {:ok, _conn, responses} = HTTP.recv(conn, 0, 100)
    assert responses == [{:status, ref, 200}]
  end

  test "starting an https connection to a unix domain socket works" do
    {:ok, address, server_ref} = TestSocketServer.start(ssl: true)

    assert {:ok, conn} =
             HTTP.connect(:https, address, 0,
               mode: :passive,
               hostname: "localhost",
               transport_opts: [
                 verify: :verify_none
               ]
             )

    assert_receive {^server_ref, server_socket}

    {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], nil)

    :ok = :ssl.send(server_socket, "HTTP/1.1 200 OK\r\n")

    assert {:ok, _conn, responses} = HTTP.recv(conn, 0, 100)
    assert responses == [{:status, ref, 200}]
  end
end
