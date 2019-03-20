defmodule Mint.TunnelProxy do
  @moduledoc false

  alias Mint.{HTTP1, HTTPError, Negotiate, TransportError}

  @tunnel_timeout 30_000

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
         timeout_deadline = timeout_deadline(proxy_opts),
         {:ok, conn, ref} <- HTTP1.request(conn, "CONNECT", path, []),
         :ok <- receive_response(conn, ref, timeout_deadline) do
      {:ok, conn}
    else
      {:error, reason} ->
        {:error, wrap_in_proxy_error(reason)}

      {:error, conn, reason} ->
        {:ok, _conn} = HTTP1.close(conn)
        {:error, wrap_in_proxy_error(reason)}
    end
  end

  defp upgrade_connection(conn, proxy, {scheme, hostname, port, opts}) do
    {proxy_scheme, _proxy_hostname, _proxy_port, _proxy_opts} = proxy
    socket = HTTP1.get_socket(conn)

    # Note that we may leak messages if the server sent data after the CONNECT response
    case Negotiate.upgrade(proxy_scheme, socket, scheme, hostname, port, opts) do
      {:ok, conn} -> {:ok, conn}
      {:error, reason} -> wrap_in_proxy_error(reason)
    end
  end

  defp receive_response(conn, ref, timeout_deadline) do
    timeout = timeout_deadline - System.monotonic_time(:millisecond)

    receive do
      {tag, _socket, _data} = msg when tag in [:tcp, :ssl] ->
        stream(conn, ref, timeout_deadline, msg)

      {tag, _socket, _data} = msg when tag in [:tcp_closed, :ssl_closed] ->
        stream(conn, ref, timeout_deadline, msg)

      {tag, _socket, _data} = msg when tag in [:tcp_error, :ssl_error] ->
        stream(conn, ref, timeout_deadline, msg)
    after
      timeout ->
        {:error, conn, wrap_error({:proxy, :tunnel_timeout})}
    end
  end

  defp stream(conn, ref, timeout_deadline, msg) do
    case HTTP1.stream(conn, msg) do
      {:ok, conn, responses} ->
        case handle_responses(conn, ref, timeout_deadline, responses) do
          :done -> :ok
          :more -> receive_response(conn, ref, timeout_deadline)
          {:error, reason} -> {:error, conn, reason}
        end

      {:error, conn, reason, _responses} ->
        {:error, conn, wrap_in_proxy_error(reason)}
    end
  end

  defp handle_responses(conn, ref, timeout_deadline, [response | responses]) do
    case response do
      {:status, ^ref, status} when status in 200..299 ->
        handle_responses(conn, ref, timeout_deadline, responses)

      {:status, ^ref, status} ->
        {:error, conn, wrap_error({:proxy, {:unexpected_status, status}})}

      {:headers, ^ref, _headers} when responses == [] ->
        :done

      {:headers, ^ref, _headers} ->
        {:error, conn, wrap_error({:proxy, {:unexpected_trailing_responses, responses}})}

      {:error, ^ref, reason} ->
        {:error, conn, wrap_in_proxy_error(reason)}
    end
  end

  defp handle_responses(_conn, _ref, _timeout_deadline, []) do
    :more
  end

  defp timeout_deadline(opts) do
    timeout = Keyword.get(opts, :tunnel_timeout, @tunnel_timeout)
    System.monotonic_time(:millisecond) + timeout
  end

  defp wrap_error(reason) do
    %HTTPError{module: __MODULE__, reason: reason}
  end

  defp wrap_in_proxy_error(%HTTPError{reason: {:proxy, _}} = error) do
    error
  end

  defp wrap_in_proxy_error(%HTTPError{reason: reason}) do
    %HTTPError{module: __MODULE__, reason: {:proxy, reason}}
  end

  defp wrap_in_proxy_error(%TransportError{} = error) do
    error
  end

  @doc false
  def format_error({:proxy, reason}) do
    case reason do
      :tunnel_timeout ->
        "proxy tunnel timeout"

      {:unexpected_status, status} ->
        "expected tunnel proxy to return a status between 200 and 299, got: #{inspect(status)}"

      {:unexpected_trailing_responses, responses} ->
        "tunnel proxy returned unexpected trailing responses: #{inspect(responses)}"

      http_reason ->
        "error when establishing the tunnel proxy connection: " <>
          HTTP1.format_error(http_reason)
    end
  end
end
