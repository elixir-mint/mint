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
  def connect(address, port, opts) when is_binary(address),
    do: connect(String.to_charlist(address), port, opts)

  def connect(address, port, opts) do
    opts = Keyword.delete(opts, :hostname)

    timeout = Keyword.get(opts, :timeout, @default_timeout)
    inet4? = Keyword.get(opts, :inet4, true)
    inet6? = Keyword.get(opts, :inet6, false)
    trace_fun = Keyword.get(opts, :trace_fun, fn _ -> :ok end)

    opts =
      opts
      |> Keyword.merge(@transport_opts)
      |> Keyword.drop([:alpn_advertised_protocols, :timeout, :inet4, :inet6, :trace_fun])

    with true <- inet6?,
         {:ok, ip} <- :inet.getaddr(address, :inet6),
         :ok <- trace_fun.(:dns_done),
         {:ok, tcpsocket} <- :gen_tcp.connect(ip, port, [:inet6 | opts], timeout) do
      trace_fun.(:connected)
      {:ok, tcpsocket}
    else
      _error when inet4? ->
        with {:ok, ip} <- :inet.getaddr(address, :inet),
             :ok <- trace_fun.(:dns_done),
             {:ok, tcpsocket} <- :gen_tcp.connect(ip, port, opts, timeout) do
          trace_fun.(:connected)
          {:ok, tcpsocket}
        else
          error -> wrap_err(error)
        end

      error ->
        wrap_err(error)
    end
  end

  @impl true
  def upgrade(socket, _scheme, _hostname, _port, _opts) do
    {:ok, socket}
  end

  @impl true
  def negotiated_protocol(_socket), do: wrap_err({:error, :protocol_not_negotiated})

  @impl true
  def send(socket, payload) do
    wrap_err(:gen_tcp.send(socket, payload))
  end

  @impl true
  defdelegate close(socket), to: :gen_tcp

  @impl true
  def recv(socket, bytes, timeout) do
    wrap_err(:gen_tcp.recv(socket, bytes, timeout))
  end

  @impl true
  def controlling_process(socket, pid) do
    wrap_err(:gen_tcp.controlling_process(socket, pid))
  end

  @impl true
  def setopts(socket, opts) do
    wrap_err(:inet.setopts(socket, opts))
  end

  @impl true
  def getopts(socket, opts) do
    wrap_err(:inet.getopts(socket, opts))
  end

  @impl true
  def wrap_error(reason) do
    %Mint.TransportError{reason: reason}
  end

  defp wrap_err({:error, reason}), do: {:error, wrap_error(reason)}
  defp wrap_err(other), do: other
end
