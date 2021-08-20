defmodule Mint.HTTP2.TestTransportSendTimeout do
  @behaviour Mint.Core.Transport

  @real_module Mint.Core.Transport.SSL

  defdelegate connect(address, port, opts), to: @real_module
  defdelegate upgrade(socket, original_scheme, hostname, port, opts), to: @real_module
  defdelegate negotiated_protocol(socket), to: @real_module

  def send(socket, payload) do
    case @real_module.send(socket, payload) do
      :ok -> {:error, wrap_error(:timeout)}
      error -> error
    end
  end

  defdelegate close(socket), to: @real_module
  defdelegate recv(socket, bytes, timeout), to: @real_module
  defdelegate controlling_process(socket, pid), to: @real_module
  defdelegate setopts(socket, opts), to: @real_module
  defdelegate getopts(socket, opts), to: @real_module
  defdelegate wrap_error(reason), to: @real_module
end
