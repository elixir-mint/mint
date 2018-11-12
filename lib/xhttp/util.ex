defmodule XHTTP.Util do
  def inet_opts(transport, socket) do
    with {:ok, opts} <- transport.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = calculate_buffer(opts),
         :ok <- transport.setopts(socket, buffer: buffer) do
      :ok
    end
  end

  def get_transport(opts, default) do
    transport = Keyword.get(opts, :transport, default)

    if transport not in [XHTTP.Transport.TCP, XHTTP.Transport.SSL] do
      raise ArgumentError,
            "the :transport option must be either TCP or SSL, got: #{inspect(transport)}"
    end

    transport
  end

  defp calculate_buffer(opts) do
    Keyword.fetch!(opts, :buffer)
    |> max(Keyword.fetch!(opts, :sndbuf))
    |> max(Keyword.fetch!(opts, :recbuf))
  end

  def proxy_hostname_port(hostname, port, opts) do
    case Keyword.fetch(opts, :proxy) do
      {:ok, proxy} -> proxy
      :error -> {hostname, port}
    end
  end

  def proxy_uri(transport, hostname, port, opts) do
    case Keyword.fetch(opts, :proxy) do
      {:ok, _proxy} ->
        "#{transport_scheme(transport)}://#{hostname}:#{port}"

      :error ->
        nil
    end
  end

  def proxy_host(hostname, port, opts) do
    case Keyword.fetch(opts, :proxy) do
      {:ok, _proxy} ->
        "#{hostname}:#{port}"

      :error ->
        hostname
    end
  end

  def proxy_auth(opts) do
    case Keyword.fetch(opts, :proxy_auth) do
      {:ok, {username, password}} ->
        combined = "#{username}:#{password}"
        "Basic #{Base.encode64(combined, padding: false)}"

      :error ->
        nil
    end
  end

  def proxy_path(nil, path), do: path
  def proxy_path(uri, "/" <> _ = path), do: uri <> path
  def proxy_path(uri, path), do: uri <> "/" <> path

  defp transport_scheme(XHTTP.Transport.TCP), do: "http"
  defp transport_scheme(XHTTP.Transport.SSL), do: "https"
end
