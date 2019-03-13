defmodule Mint.Negotiate do
  @moduledoc false

  import Mint.Core.Util

  alias Mint.{
    HTTP1,
    HTTP2,
    TransportError
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
        transport_connect(scheme, hostname, port, opts)
    end
  end

  def upgrade(proxy_scheme, transport_state, scheme, hostname, port, opts) do
    {protocols, opts} = Keyword.pop(opts, :protocols, @default_protocols)

    case Enum.sort(protocols) do
      [:http1] ->
        HTTP1.upgrade(proxy_scheme, transport_state, scheme, hostname, port, opts)

      [:http2] ->
        HTTP2.upgrade(proxy_scheme, transport_state, scheme, hostname, port, opts)

      [:http1, :http2] ->
        transport_upgrade(proxy_scheme, transport_state, scheme, hostname, port, opts)
    end
  end

  def initiate(transport, transport_state, hostname, port, opts),
    do: alpn_negotiate(transport, transport_state, hostname, port, opts)

  defp transport_connect(:http, hostname, port, opts) do
    # HTTP1 upgrade is not supported
    HTTP1.connect(:http, hostname, port, opts)
  end

  defp transport_connect(:https, hostname, port, opts) do
    connect_negotiate(:https, hostname, port, opts)
  end

  defp connect_negotiate(scheme, hostname, port, opts) do
    transport = scheme_to_transport(scheme)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    with {:ok, transport_state} <- transport.connect(hostname, port, transport_opts) do
      alpn_negotiate(scheme, transport_state, hostname, port, opts)
    end
  end

  defp transport_upgrade(
         proxy_scheme,
         transport_state,
         :http,
         hostname,
         port,
         opts
       ) do
    # HTTP1 upgrade is not supported
    HTTP1.upgrade(proxy_scheme, transport_state, :http, hostname, port, opts)
  end

  defp transport_upgrade(
         proxy_scheme,
         transport_state,
         :https,
         hostname,
         port,
         opts
       ) do
    connect_upgrade(proxy_scheme, transport_state, :https, hostname, port, opts)
  end

  defp connect_upgrade(proxy_scheme, transport_state, new_scheme, hostname, port, opts) do
    transport = scheme_to_transport(new_scheme)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    case transport.upgrade(transport_state, proxy_scheme, hostname, port, transport_opts) do
      {:ok, transport_state} ->
        alpn_negotiate(new_scheme, transport_state, hostname, port, opts)

      {:error, reason} ->
        {:error, %TransportError{reason: reason}}
    end
  end

  defp alpn_negotiate(scheme, socket, hostname, port, opts) do
    transport = scheme_to_transport(scheme)

    case transport.negotiated_protocol(socket) do
      {:ok, "http/1.1"} ->
        HTTP1.initiate(scheme, socket, hostname, port, opts)

      {:ok, "h2"} ->
        HTTP2.initiate(scheme, socket, hostname, port, opts)

      {:error, %TransportError{reason: :protocol_not_negotiated}} ->
        # Assume HTTP1 if ALPN is not supported
        HTTP1.initiate(scheme, socket, hostname, port, opts)

      {:ok, protocol} ->
        {:error, %TransportError{reason: {:bad_alpn_protocol, protocol}}}
    end
  end
end
