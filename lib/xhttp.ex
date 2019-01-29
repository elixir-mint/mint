defmodule XHTTP do
  @moduledoc """
  Single interface for `XHTTP1` and `XHTTP2` with version negotiation support and support for
  proxies.
  """

  import XHTTPCore.Util

  alias XHTTP.{TunnelProxy, UnsafeProxy}
  alias XHTTPCore.Transport

  @behaviour XHTTPCore.Conn

  @opaque t() :: XHTTP1.t() | XHTTP2.t()

  @type scheme() :: :http | :https | module()
  @type headers() :: XHTTPCore.Conn.headers()
  @type request_ref() :: XHTTPCore.Conn.request_ref()
  @type socket_message() :: XHTTPCore.Conn.socket_message()
  @type response() :: XHTTPCore.Conn.response()

  @spec connect(scheme(), String.t(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, term()}
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

  @spec upgrade(
          module(),
          XHTTPCore.Transport.socket(),
          scheme(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def upgrade(old_transport, transport_state, scheme, hostname, port, opts),
    do: XHTTP.Negotiate.upgrade(old_transport, transport_state, scheme, hostname, port, opts)

  # TODO: deal with this by either having it in the behaviour or not having it at all.
  def get_transport(conn), do: conn_module(conn).get_transport(conn)

  @spec initiate(
          module(),
          XHTTPCore.Transport.socket(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def initiate(transport, transport_state, hostname, port, opts),
    do: XHTTP.Negotiate.initiate(transport, transport_state, hostname, port, opts)

  @spec open?(t()) :: boolean()
  def open?(conn), do: conn_module(conn).open?(conn)

  @spec request(
          t(),
          method :: String.t(),
          path :: String.t(),
          headers(),
          body :: iodata() | nil | :stream
        ) ::
          {:ok, t(), request_ref()}
          | {:error, t(), term()}
  def request(conn, method, path, headers, body \\ nil),
    do: conn_module(conn).request(conn, method, path, headers, body)

  @spec stream_request_body(t(), request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(conn, ref, body),
    do: conn_module(conn).stream_request_body(conn, ref, body)

  @spec stream(t(), socket_message()) ::
          {:ok, t(), [response()]}
          | {:error, t(), term(), [response()]}
          | :unknown
  def stream(conn, message), do: conn_module(conn).stream(conn, message)

  @spec put_private(t(), atom(), term()) :: t()
  def put_private(conn, key, value), do: conn_module(conn).put_private(conn, key, value)

  @spec get_private(t(), atom(), term()) :: term()
  def get_private(conn, key, default \\ nil),
    do: conn_module(conn).get_private(conn, key, default)

  @spec delete_private(t(), atom()) :: t()
  def delete_private(conn, key), do: conn_module(conn).delete_private(conn, key)

  @spec get_socket(t()) :: XHTTPCore.Transport.socket()
  def get_socket(conn), do: conn_module(conn).get_socket(conn)

  ## Helpers

  defp conn_module(%UnsafeProxy{}), do: UnsafeProxy
  defp conn_module(%XHTTP1{}), do: XHTTP1
  defp conn_module(%XHTTP2{}), do: XHTTP2
end
