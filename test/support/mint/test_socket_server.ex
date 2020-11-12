defmodule Mint.TestSocketServer do
  @ssl_opts [
    active: false,
    reuseaddr: true,
    nodelay: true,
    certfile: Path.expand("certificate.pem", __DIR__),
    keyfile: Path.expand("key.pem", __DIR__)
  ]

  def start(options) when is_list(options) do
    ssl? = Keyword.fetch!(options, :ssl)
    socket_path = Path.join(System.tmp_dir!(), "mint_http1_test_socket_server.sock")

    _ = File.rm(socket_path)

    server_ref = make_ref()
    parent = self()

    {:ok, listen_socket} = listen(socket_path, ssl?)

    spawn_link(fn ->
      {:ok, socket} = accept(listen_socket, ssl?)
      send(parent, {server_ref, socket})
      :ok = Process.sleep(:infinity)
    end)

    {:ok, {:local, socket_path}, server_ref}
  end

  defp listen(socket_path, _ssl? = false) do
    :gen_tcp.listen(0, mode: :binary, packet: :raw, ifaddr: {:local, socket_path})
  end

  defp listen(socket_path, _ssl? = true) do
    opts = [mode: :binary, packet: :raw, ifaddr: {:local, socket_path}]
    :ssl.listen(0, opts ++ @ssl_opts)
  end

  defp accept(listen_socket, _ssl? = false) do
    {:ok, _socket} = :gen_tcp.accept(listen_socket)
  end

  defp accept(listen_socket, _ssl? = true) do
    {:ok, socket} = :ssl.transport_accept(listen_socket)
    :ok = :ssl.ssl_accept(socket)
    {:ok, socket}
  end
end
