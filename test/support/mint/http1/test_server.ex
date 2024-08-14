defmodule Mint.HTTP1.TestServer do
  def start(fun \\ nil) do
    {:ok, listen_socket} = :gen_tcp.listen(0, mode: :binary, packet: :raw)
    server_ref = make_ref()
    parent = self()

    spawn_link(fn -> loop(listen_socket, parent, server_ref, fun) end)

    with {:ok, port} <- :inet.port(listen_socket) do
      {:ok, port, server_ref}
    end
  end

  defp loop(listen_socket, parent, server_ref, fun) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, socket} ->
        send(parent, {server_ref, socket})

        # :einval started showing up with Erlang 23 and Ubuntu 18.
        case :gen_tcp.controlling_process(socket, parent) do
          :ok -> :ok
          {:error, :einval} -> :ok
        end

        if fun do
          fun.(%{socket: socket, parent: parent})
        end

        loop(listen_socket, parent, server_ref, fun)

      {:error, :closed} ->
        :ok
    end
  end
end
