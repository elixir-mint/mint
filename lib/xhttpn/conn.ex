defmodule XHTTPN.Conn do
  @moduledoc """
  Single interface for `XHTTP1.Conn` and `XHTTP2.Conn` with version negotiation support.
  """

  import XHTTP.Util

  @behaviour XHTTP.ConnBehaviour

  @default_protocols [:http1, :http2]
  @transport_opts [alpn_advertised_protocols: ["http/1.1", "h2"]]

  def connect(scheme, hostname, port, opts \\ []) do
    {protocols, opts} = Keyword.pop(opts, :protocols, @default_protocols)

    case Enum.sort(protocols) do
      [:http1] ->
        XHTTP1.Conn.connect(scheme, hostname, port, opts)

      [:http2] ->
        XHTTP2.Conn.connect(scheme, hostname, port, opts)

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
        XHTTP1.Conn.upgrade(old_transport, transport_state, new_transport, hostname, port, opts)

      [:http2] ->
        XHTTP2.Conn.upgrade(old_transport, transport_state, new_transport, hostname, port, opts)

      [:http1, :http2] ->
        transport_upgrade(old_transport, transport_state, new_transport, hostname, port, opts)
    end
  end

  def get_transport(conn) do
    conn_module(conn).get_transport(conn)
  end

  def put_transport(conn, transport) do
    conn_module(conn).put_transport(conn, transport)
  end

  def transport_socket(conn) do
    conn_module(conn).transport_socket(conn)
  end

  def initiate(transport, transport_state, hostname, port, opts),
    do: alpn_negotiate(transport, transport_state, hostname, port, opts)

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

  defp transport_connect(XHTTP.Transport.TCP, hostname, port, opts) do
    # TODO: http1 upgrade? Should be explicit since support is not clear
    XHTTP1.Conn.connect(XHTTP.Transport.TCP, hostname, port, opts)
  end

  defp transport_connect(XHTTP.Transport.SSL, hostname, port, opts) do
    connect_negotiate(XHTTP.Transport.SSL, hostname, port, opts)
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
         XHTTP.Transport.TCP,
         hostname,
         port,
         opts
       ) do
    # TODO: http1 upgrade? Should be explicit since support is not clear
    XHTTP1.Conn.upgrade(old_transport, transport_state, XHTTP.Transport.TCP, hostname, port, opts)
  end

  defp transport_upgrade(
         old_transport,
         transport_state,
         XHTTP.Transport.SSL,
         hostname,
         port,
         opts
       ) do
    connect_upgrade(old_transport, transport_state, XHTTP.Transport.SSL, hostname, port, opts)
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
        XHTTP1.Conn.initiate(transport, socket, hostname, port, opts)

      {:ok, "h2"} ->
        XHTTP2.Conn.initiate(transport, socket, hostname, port, opts)

      {:error, :protocol_not_negotiated} ->
        # Assume HTTP1 if ALPN is not supported
        XHTTP1.Conn.initiate(transport, socket, hostname, port, opts)

      {:ok, protocol} ->
        {:error, {:bad_alpn_protocol, protocol}}
    end
  end

  defp conn_module(%XHTTP1.Conn{}), do: XHTTP1.Conn
  defp conn_module(%XHTTP2.Conn{}), do: XHTTP2.Conn
end
