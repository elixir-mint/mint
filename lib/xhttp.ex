defmodule XHTTP do
  @moduledoc """
  Single interface for `XHTTP1` and `XHTTP2` with version negotiation support and support for
  proxies.
  """

  import XHTTPCore.Util

  alias XHTTP.{TunnelProxy, UnsafeProxy}
  alias XHTTPCore.Transport

  @behaviour XHTTPCore.Conn

  def connect(scheme, hostname, port, opts \\ []) do
    # TODO: Proxy auth

    case Keyword.fetch(opts, :proxy) do
      {:ok, {proxy_scheme, proxy_hostname, proxy_port, proxy_opts}} ->
        case scheme_to_transport(scheme) do
          Transport.TCP ->
            proxy = {proxy_scheme, proxy_hostname, proxy_port}
            host = {scheme, hostname, port}
            opts = Keyword.merge(opts, proxy_opts)
            UnsafeProxy.connect(proxy, host, opts)

          Transport.SSL ->
            proxy = {proxy_scheme, proxy_hostname, proxy_port, proxy_opts}
            host = {scheme, hostname, port, opts}
            TunnelProxy.connect(proxy, host)
        end

      :error ->
        XHTTP.Negotiate.connect(scheme, hostname, port, opts)
    end
  end

  def upgrade(old_transport, transport_state, scheme, hostname, port, opts),
    do: XHTTP.Negotiate.upgrade(old_transport, transport_state, scheme, hostname, port, opts)

  def get_transport(conn), do: conn_module(conn).get_transport(conn)

  def initiate(transport, transport_state, hostname, port, opts),
    do: XHTTP.Negotiate.initiate(transport, transport_state, hostname, port, opts)

  def open?(conn), do: conn_module(conn).open?(conn)

  def request(conn, method, path, headers, body \\ nil),
    do: conn_module(conn).request(conn, method, path, headers, body)

  def stream_request_body(conn, ref, body),
    do: conn_module(conn).stream_request_body(conn, ref, body)

  def stream(conn, message), do: conn_module(conn).stream(conn, message)

  def put_private(conn, key, value), do: conn_module(conn).put_private(conn, key, value)

  def get_private(conn, key, default \\ nil),
    do: conn_module(conn).get_private(conn, key, default)

  def delete_private(conn, key), do: conn_module(conn).delete_private(conn, key)

  def get_socket(conn), do: conn_module(conn).get_socket(conn)

  defp conn_module(%UnsafeProxy{}), do: UnsafeProxy
  defp conn_module(%XHTTP1{}), do: XHTTP1
  defp conn_module(%XHTTP2{}), do: XHTTP2
end
