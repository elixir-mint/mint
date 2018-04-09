defmodule XHTTP.Transport.TCP do
  @behaviour XHTTP.Transport

  @impl true
  def connect(host, port, opts) do
    host
    |> String.to_charlist()
    |> :gen_tcp.connect(port, opts)
  end

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
