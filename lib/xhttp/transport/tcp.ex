defmodule XHTTP.Transport.TCP do
  @behaviour XHTTP.Transport

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
  def send(socket, payload) do
    with :ok <- :gen_tcp.send(socket, payload) do
      {:ok, socket}
    end
  end

  @impl true
  def close(socket) do
    with :ok <- :gen_tcp.close(socket) do
      {:ok, socket}
    end
  end

  @impl true
  def recv(socket, bytes) do
    with {:ok, data} <- :gen_tcp.recv(socket, bytes) do
      {:ok, data, socket}
    end
  end

  @impl true
  defdelegate setopts(socket, opts), to: :inet

  @impl true
  defdelegate getopts(socket, opts), to: :inet
end
