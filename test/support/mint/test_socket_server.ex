defmodule Mint.TestSocketServer do
  @socket_path "/tmp/mint_http1_test_socket_server.sock"

  @opts [
    mode: :binary,
    packet: :raw,
    ifaddr: {:local, @socket_path}
  ]

  @ssl_opts [
    active: false,
    reuseaddr: true,
    nodelay: true,
    certfile: Path.expand("certificate.pem", __DIR__),
    keyfile: Path.expand("key.pem", __DIR__)
  ]

  def start, do: start(ssl: false)

  def start(ssl: ssl?) do
    _ = File.rm(@socket_path)

    server_ref = make_ref()
    parent = self()

    {:ok, listen_socket} = do_start(ssl: ssl?)

    spawn_link(fn ->
      {:ok, socket} = do_accept(listen_socket, ssl: ssl?)
      send(parent, {server_ref, socket})

      # NOTE: not looping, just sleeping forever
      :ok = Process.sleep(:infinity)
    end)

    {:ok, "unix://#{@socket_path}", server_ref}
  end

  defp do_start(ssl: false), do: :gen_tcp.listen(0, @opts)
  defp do_start(ssl: true), do: :ssl.listen(0, @opts ++ @ssl_opts)

  defp do_accept(listen_socket, ssl: false),
    do: :gen_tcp.accept(listen_socket)

  defp do_accept(listen_socket, ssl: true) do
    {:ok, socket} = :ssl.transport_accept(listen_socket)
    :ok = :ssl.ssl_accept(socket)

    {:ok, socket}
  end
end
