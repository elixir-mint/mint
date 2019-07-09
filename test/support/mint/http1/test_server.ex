defmodule Mint.HTTP1.TestServer do
  def start() do
    {:ok, listen_socket} = :gen_tcp.listen(0, mode: :binary, packet: :raw)
    server_ref = make_ref()
    parent = self()

    spawn_link(fn -> loop(listen_socket, parent, server_ref) end)

    with {:ok, port} <- :inet.port(listen_socket) do
      {:ok, port, server_ref}
    end
  end

  defp loop(listen_socket, parent, server_ref) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, socket} ->
        send(parent, {server_ref, socket})
        :ok = :gen_tcp.controlling_process(socket, parent)
        loop(listen_socket, parent, server_ref)

      {:error, :closed} ->
        :ok
    end
  end
end
