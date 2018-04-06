defmodule XHTTP.Transport.SSL do
  @behaviour XHTTP.Transport

  @impl true
  def connect(host, port, opts) do
    host
    |> String.to_charlist()
    |> :ssl.connect(port, opts)
  end

  @impl true
  defdelegate negotiated_protocol(socket), to: :ssl

  @impl true
  defdelegate send(socket, payload), to: :ssl

  @impl true
  defdelegate close(socket), to: :ssl

  @impl true
  defdelegate recv(socket, bytes), to: :ssl

  @impl true
  defdelegate setopts(socket, opts), to: :ssl

  @impl true
  defdelegate getopts(socket, opts), to: :ssl
end
