defmodule Mint.Core.Transport.TCP do
  @moduledoc false

  @behaviour Mint.Core.Transport

  @transport_opts [
    packet: :raw,
    mode: :binary,
    active: false
  ]

  @default_timeout 30_000

  @impl true
  def connect(hostname, port, opts) do
    hostname = String.to_charlist(hostname)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    opts =
      opts
      |> Keyword.merge(@transport_opts)
      |> Keyword.delete(:alpn_advertised_protocols)

    :gen_tcp.connect(hostname, port, opts, timeout)
  end

  @impl true
  def upgrade(socket, transport, _hostname, _port, _opts) do
    {:ok, {transport, socket}}
  end

  @impl true
  def negotiated_protocol(_socket), do: {:error, :protocol_not_negotiated}

  @impl true
  defdelegate send(socket, payload), to: :gen_tcp

  @impl true
  defdelegate close(socket), to: :gen_tcp

  @impl true
  defdelegate recv(socket, bytes), to: :gen_tcp

  @impl true
  defdelegate setopts(socket, opts), to: :inet

  @impl true
  defdelegate getopts(socket, opts), to: :inet
end
