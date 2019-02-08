defmodule Mint.Negotiate do
  @moduledoc false

  import Mint.Core.Util

  alias Mint.{
    Core.Transport,
    HTTP1,
    HTTP2
  }

  @default_protocols [:http1, :http2]
  @transport_opts [alpn_advertised_protocols: ["http/1.1", "h2"]]

  def connect(scheme, hostname, port, opts \\ []) do
    {protocols, opts} = Keyword.pop(opts, :protocols, @default_protocols)

    case Enum.sort(protocols) do
      [:http1] ->
        HTTP1.connect(scheme, hostname, port, opts)

      [:http2] ->
        HTTP2.connect(scheme, hostname, port, opts)

      [:http1, :http2] ->
        transport = scheme_to_transport(scheme)
        transport_connect(transport, hostname, port, opts)
    end
  end

  def upgrade(old_transport, transport_state, scheme, hostname, port, opts) do
    {protocols, opts} = Keyword.pop(opts, :protocols, @default_protocols)
    new_transport = scheme_to_transport(scheme)

    case Enum.sort(protocols) do
      [:http1] ->
        HTTP1.upgrade(old_transport, transport_state, new_transport, hostname, port, opts)

      [:http2] ->
        HTTP2.upgrade(old_transport, transport_state, new_transport, hostname, port, opts)

      [:http1, :http2] ->
        transport_upgrade(old_transport, transport_state, new_transport, hostname, port, opts)
    end
  end

  def initiate(transport, transport_state, hostname, port, opts),
    do: alpn_negotiate(transport, transport_state, hostname, port, opts)

  defp transport_connect(Transport.TCP, hostname, port, opts) do
    # TODO: http1 upgrade? Should be explicit since support is not clear
    HTTP1.connect(Transport.TCP, hostname, port, opts)
  end

  defp transport_connect(Transport.SSL, hostname, port, opts) do
    connect_negotiate(Transport.SSL, hostname, port, opts)
  end

  defp connect_negotiate(transport, hostname, port, opts) do
    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    case transport.connect(hostname, port, transport_opts) do
      {:ok, transport_state} -> alpn_negotiate(transport, transport_state, hostname, port, opts)
      {:error, reason} -> {:error, reason}
    end
  end

  defp transport_upgrade(
         old_transport,
         transport_state,
         Transport.TCP,
         hostname,
         port,
         opts
       ) do
    # TODO: http1 upgrade? Should be explicit since support is not clear
    HTTP1.upgrade(old_transport, transport_state, Transport.TCP, hostname, port, opts)
  end

  defp transport_upgrade(
         old_transport,
         transport_state,
         Transport.SSL,
         hostname,
         port,
         opts
       ) do
    connect_upgrade(old_transport, transport_state, Transport.SSL, hostname, port, opts)
  end

  defp connect_upgrade(old_transport, transport_state, new_transport, hostname, port, opts) do
    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    case new_transport.upgrade(transport_state, old_transport, hostname, port, transport_opts) do
      {:ok, {new_transport, transport_state}} ->
        alpn_negotiate(new_transport, transport_state, hostname, port, opts)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp alpn_negotiate(transport, socket, hostname, port, opts) do
    case transport.negotiated_protocol(socket) do
      {:ok, "http/1.1"} ->
        HTTP1.initiate(transport, socket, hostname, port, opts)

      {:ok, "h2"} ->
        HTTP2.initiate(transport, socket, hostname, port, opts)

      {:error, :protocol_not_negotiated} ->
        # Assume HTTP1 if ALPN is not supported
        HTTP1.initiate(transport, socket, hostname, port, opts)

      {:ok, protocol} ->
        {:error, {:bad_alpn_protocol, protocol}}
    end
  end
end
