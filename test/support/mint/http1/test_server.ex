defmodule Mint.HTTP1.TestServer do
  def start() do
    {:ok, listen_socket} = :gen_tcp.listen(0, mode: :binary, packet: :raw)
    spawn_link(fn -> loop(listen_socket) end)
    :inet.port(listen_socket)
  end

  defp loop(listen_socket) do
    case :gen_tcp.accept(listen_socket) do
      {:ok, _socket} -> loop(listen_socket)
      {:error, :closed} -> :ok
    end
  end
end
