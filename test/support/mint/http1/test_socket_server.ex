defmodule Mint.HTTP1.TestSocketServer do
  import Mint.HTTP1.TestServer, only: [loop: 3]

  @socket_path "/tmp/mint_http1_test_socket_server.sock"

  def start do
    _ = File.rm(@socket_path)

    {:ok, listen_socket} =
      :gen_tcp.listen(0, mode: :binary, packet: :raw, ifaddr: {:local, @socket_path})

    server_ref = make_ref()
    parent = self()

    spawn_link(fn ->
      loop(listen_socket, parent, server_ref)
    end)

    {:ok, "unix://#{@socket_path}", server_ref}
  end
end
