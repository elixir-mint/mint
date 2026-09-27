defmodule Mint.Core.Transport.SSL.Tunnel do
  @moduledoc false

  # The transport callback module given to `:ssl.connect/3` through the
  # `:cb_info` option when nesting a TLS session inside an established
  # `:ssl` socket. `:ssl` requires the callback module to behave like
  # `:gen_tcp`, with functions corresponding to `:inet.setopts/2`,
  # `:inet.getopts/2`, `:inet.peername/1`, `:inet.sockname/1`, and
  # `:inet.port/1`.

  defdelegate setopts(socket, opts), to: :ssl
  defdelegate getopts(socket, opts), to: :ssl
  defdelegate send(socket, data), to: :ssl
  defdelegate recv(socket, length), to: :ssl
  defdelegate recv(socket, length, timeout), to: :ssl
  defdelegate controlling_process(socket, pid), to: :ssl
  defdelegate close(socket), to: :ssl
  defdelegate shutdown(socket, how), to: :ssl
  defdelegate getstat(socket, options), to: :ssl
  defdelegate peername(socket), to: :ssl
  defdelegate sockname(socket), to: :ssl

  def port(socket) do
    with {:ok, {_address, port}} <- :ssl.sockname(socket) do
      {:ok, port}
    end
  end
end
