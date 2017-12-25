defmodule XHTTP1.Transport.TCP do
  @behaviour XHTTP1.Transport

  defdelegate connect(hostname, port, options), to: :gen_tcp
  defdelegate getopts(socket, opts), to: :inet
  defdelegate setopts(socket, opts), to: :inet
  defdelegate close(socket), to: :gen_tcp
  defdelegate send(socket, packet), to: :gen_tcp

  def message_tags() do
    {:tcp, :tcp_error, :tcp_close}
  end
end
