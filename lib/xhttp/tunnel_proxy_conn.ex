defmodule XHTTP.TunnelProxyConn do
  import XHTTP.Util

  def connect(proxy, host) do
    with {:ok, conn} <- establish_proxy(proxy, host) do
      initiate_host_connection(conn, host)
    end
  end

  defp establish_proxy(proxy, host) do
    {proxy_scheme, proxy_hostname, proxy_port, proxy_opts} = proxy
    {_scheme, hostname, port, _opts} = host
    path = "#{hostname}:#{port}"

    with {:ok, conn} <- XHTTPN.Conn.connect(proxy_scheme, proxy_hostname, proxy_port, proxy_opts),
         {:ok, conn, ref} <- XHTTPN.Conn.request(conn, "CONNECT", path, []),
         :ok <- receive_response(conn, ref) do
      {:ok, conn}
    else
      {:error, reason} -> {:error, {:proxy, reason}}
    end
  end

  defp initiate_host_connection(conn, {scheme, hostname, port, opts}) do
    transport = scheme_to_transport(scheme)

    with {:ok, conn} = conn.__struct__.upgrade_transport(conn, transport, hostname, port, opts) do
      conn_transport = conn_to_transport(conn)
      XHTTPN.Conn.initiate(conn_transport, conn, hostname, port, opts)
    end
  end

  defp conn_to_transport(%XHTTP1.Conn{}), do: XHTTP.Transport.HTTP1
  defp conn_to_transport(%XHTTP2.Conn{}), do: XHTTP.Transport.HTTP2

  defp receive_response(conn, ref) do
    # TODO: Timeout deadline

    receive do
      {tag, _socket, _data} = msg when tag in [:tcp, :ssl] ->
        stream(conn, ref, msg)

      {tag, _socket, _data} = msg when tag in [:tcp_closed, :ssl_closed] ->
        stream(conn, ref, msg)

      {tag, _socket, _data} = msg when tag in [:tcp_error, :ssl_error] ->
        stream(conn, ref, msg)
    end
  end

  defp stream(conn, ref, msg) do
    case XHTTPN.Conn.stream(conn, msg) do
      {:ok, conn, responses} ->
        case handle_responses(conn, ref, responses) do
          :done -> :ok
          :more -> receive_response(conn, ref)
          {:error, reason} -> {:error, reason}
        end

      {:error, _conn, reason, _responses} ->
        # TODO: Close connection
        {:error, reason}
    end
  end

  defp handle_responses(conn, ref, [response | responses]) do
    # TODO: Close connection on error

    case response do
      {:status, ^ref, status} when status in 200..299 ->
        handle_responses(conn, ref, responses)

      {:status, ^ref, status} ->
        {:error, {:unexpected_status, status}}

      {:headers, ^ref, _headers} ->
        if responses == [] do
          :done
        else
          {:error, {:unexpected_trailing_responses, responses}}
        end

      {:error, ^ref, reason} ->
        {:error, reason}
    end
  end

  defp handle_responses(_conn, _ref, []) do
    :more
  end
end
