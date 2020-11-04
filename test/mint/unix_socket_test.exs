defmodule Mint.UnitSocketTest do
  use ExUnit.Case, async: true

  alias Mint.{HTTP, TestSocketServer}

  require HTTP

  test "starting an http connection to a unix domain socket works" do
    unless is_unix?() && otp_19?() do
      {:ok, address, server_ref} = TestSocketServer.start()
      assert {:ok, conn} = HTTP.connect(:http, address, 0, mode: :passive)
      assert_receive {^server_ref, server_socket}

      {:ok, conn, ref} = HTTP.request(conn, "GET", "/", [], nil)

      :ok = :gen_tcp.send(server_socket, "HTTP/1.1 200 OK\r\n")

      assert {:ok, _conn, responses} = HTTP.recv(conn, 0, 100)
      assert responses == [{:status, ref, 200}]
    end
  end

  test "starting an https connection to a unix domain socket works" do
    unless is_unix?() && otp_19?() do
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

  defp is_unix?, do: match?({:unix, _}, :os.type())

  # NOTE: elixir >= 1.6.0 requires OTP >= 19
  defp otp_19?, do: Version.compare(System.version(), "1.6.0") != :lt
end
