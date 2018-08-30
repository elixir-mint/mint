defmodule XHTTPN.Conn do
  @moduledoc """
  Single interface for `XHTTP1.Conn` and `XHTTP2.Conn` with version negotiation support.
  """

  import XHTTP.Util

  @default_protocols [:http1, :http2]

  @transport_opts [
    packet: :raw,
    mode: :binary,
    active: false,
    alpn_advertised_protocols: ["http/1.1", "h2"]
  ]

  def connect(hostname, port, opts \\ []) do
    {protocols, opts} = Keyword.pop(opts, :protocols, @default_protocols)

    case Enum.sort(protocols) do
      [:http1] -> XHTTP1.Conn.connect(hostname, port, opts)
      [:http2] -> XHTTP2.Conn.connect(hostname, port, opts)
      [:http1, :http2] -> negotiate(hostname, port, opts)
    end
  end

  def open?(conn), do: conn_module(conn).open?(conn)

  def request(conn, method, path, headers, body),
    do: conn_module(conn).request(conn, method, path, headers, body)

  def stream_request_body(conn, body), do: conn_module(conn).stream_request_body(conn, body)

  def stream(conn, message), do: conn_module(conn).stream(conn, message)

  def put_private(conn, key, value), do: conn_module(conn).put_private(conn, key, value)

  def get_private(conn, key, default \\ nil), do: conn_module(conn).get_private(conn, key, default)

  def delete_private(conn, key), do: conn_module(conn).delete_private(conn, key)

  defp negotiate(hostname, port, opts) do
    transport = get_transport(opts, XHTTP.Transport.SSL)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    with {:ok, socket} <- transport.connect(hostname, port, transport_opts) do
      case transport do
        XHTTP.Transport.TCP -> http1_with_upgrade(socket, hostname, port, opts)
        XHTTP.Transport.SSL -> alpn_negotiate(socket, hostname, port, transport, opts)
      end
    end
  end

  defp http1_with_upgrade(_socket, _hostname, _port, _opts) do
    # TODO
  end

  defp alpn_negotiate(socket, hostname, port, transport, opts) do
    case transport.negotiated_protocol(socket) do
      {:ok, "http/1.1"} ->
        XHTTP1.Conn.initiate_connection(socket, hostname, transport)

      {:ok, "h2"} ->
        XHTTP2.Conn.initiate_connection(socket, hostname, port, transport, opts)

      {:error, :protocol_not_negotiated} ->
        # Assume HTTP1 if ALPN is not supported
        {:ok, XHTTP1.Conn.initiate_connection(socket, hostname, transport)}

      {:ok, protocol} ->
        {:error, {:bad_alpn_protocol, protocol}}
    end
  end

  defp conn_module(%XHTTP1.Conn{}), do: XHTTP1.Conn
  defp conn_module(%XHTTP2.Conn{}), do: XHTTP2.Conn
end
