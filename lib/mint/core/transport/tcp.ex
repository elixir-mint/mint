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
  def connect(hostname, port, opts) do
    address = hostname_to_address(hostname)
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    inet6? = Keyword.get(opts, :inet6, false)

    opts =
      opts
      |> Keyword.merge(@transport_opts)
      |> Keyword.drop([:alpn_advertised_protocols, :timeout, :inet6])

    if inet6? do
      # Try inet6 first, then fall back to the defaults provided by
      # gen_tcp if connection fails.
      case :gen_tcp.connect(address, port, [:inet6 | opts], timeout) do
        {:ok, socket} ->
          {:ok, socket}

        _error ->
          wrap_err(:gen_tcp.connect(address, port, opts, timeout))
      end
    else
      # Use the defaults provided by gen_tcp.
      wrap_err(:gen_tcp.connect(address, port, opts, timeout))
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

  def hostname_to_address("unix://" <> path), do: {:local, String.to_charlist(path)}
  def hostname_to_address(hostname), do: String.to_charlist(hostname)

  defp wrap_err({:error, reason}), do: {:error, wrap_error(reason)}
  defp wrap_err(other), do: other
end
