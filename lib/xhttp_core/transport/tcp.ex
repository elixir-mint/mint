defmodule XHTTPCore.Transport.TCP do
  @moduledoc false

  @behaviour XHTTPCore.Transport

  @transport_opts [
    packet: :raw,
    mode: :binary,
    active: false
  ]

  @impl true
  def connect(host, port, opts) do
    # TODO: Timeout

    opts =
      opts
      |> Keyword.merge(@transport_opts)
      |> Keyword.delete(:alpn_advertised_protocols)

    host
    |> String.to_charlist()
    |> :gen_tcp.connect(port, opts)
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
