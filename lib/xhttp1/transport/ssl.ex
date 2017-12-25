defmodule XHTTP1.Transport.SSL do
  @behaviour XHTTP1.Transport

  defdelegate connect(hostname, port, options), to: :ssl
  defdelegate getopts(socket, opts), to: :ssl
  defdelegate setopts(socket, opts), to: :ssl
  defdelegate close(socket), to: :ssl
  defdelegate send(socket, packet), to: :ssl

  def message_tags() do
    {:ssl, :ssl_error, :ssl_close}
  end
end
