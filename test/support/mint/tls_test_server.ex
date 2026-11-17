defmodule Mint.TLSTestServer do
  @moduledoc false

  # Listens on a random local port and completes the TLS handshake for every
  # connection it accepts. Accepted connections stay open until the calling
  # process exits.
  def start(ssl_opts) do
    socket_opts = [mode: :binary, packet: :raw, active: false, reuseaddr: true]
    {:ok, listen_socket} = :ssl.listen(0, socket_opts ++ ssl_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)

    spawn_link(fn -> accept_loop(listen_socket) end)

    {:ok, port}
  end

  defp accept_loop(listen_socket) do
    case :ssl.transport_accept(listen_socket) do
      {:ok, socket} ->
        _ = :ssl.handshake(socket, 5_000)
        accept_loop(listen_socket)

      {:error, _reason} ->
        :ok
    end
  end
end
