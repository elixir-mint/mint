defmodule XHTTP.Transport.SSL do
  @behaviour XHTTP.Transport

  @default_ssl_opts [verify: :verify_peer]

  @impl true
  def connect(host, port, opts) do
    host
    |> String.to_charlist()
    |> :ssl.connect(port, Keyword.merge(@default_ssl_opts, opts))
  end

  @impl true
  defdelegate negotiated_protocol(socket), to: :ssl

  @impl true
  def send(socket, payload) do
    with :ok <- :ssl.send(socket, payload) do
      {:ok, socket}
    end
  end

  @impl true
  def close(socket) do
    with :ok <- :ssl.close(socket) do
      {:ok, socket}
    end
  end

  @impl true
  def recv(socket, bytes) do
    with {:ok, data} <- :ssl.recv(socket, bytes) do
      {:ok, data, socket}
    end
  end

  @impl true
  defdelegate setopts(socket, opts), to: :ssl

  @impl true
  defdelegate getopts(socket, opts), to: :ssl
end
