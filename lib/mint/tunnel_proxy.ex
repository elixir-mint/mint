defmodule Mint.TunnelProxy do
  @moduledoc false

  alias Mint.{HTTP1, Negotiate}

  def connect(proxy, host) do
    with {:ok, conn} <- establish_proxy(proxy, host) do
      upgrade_connection(conn, proxy, host)
    end
  end

  defp establish_proxy(proxy, host) do
    {proxy_scheme, proxy_hostname, proxy_port, proxy_opts} = proxy
    {_scheme, hostname, port, _opts} = host
    path = "#{hostname}:#{port}"

    with {:ok, conn} <- HTTP1.connect(proxy_scheme, proxy_hostname, proxy_port, proxy_opts),
         {:ok, conn, ref} <- HTTP1.request(conn, "CONNECT", path, []),
         :ok <- receive_response(conn, ref) do
      {:ok, conn}
    else
      {:error, reason} ->
        {:error, {:proxy, reason}}

      {:error, conn, reason} ->
        {:ok, _conn} = HTTP1.close(conn)
        {:error, {:proxy, reason}}
    end
  end

  defp upgrade_connection(conn, proxy, {scheme, hostname, port, opts}) do
    {proxy_scheme, _proxy_hostname, _proxy_port, _proxy_opts} = proxy
    socket = HTTP1.get_socket(conn)

    # Note that we may leak messages if the server sent data after the CONNECT response
    Negotiate.upgrade(proxy_scheme, socket, scheme, hostname, port, opts)
  end

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
    case HTTP1.stream(conn, msg) do
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
