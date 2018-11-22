defmodule XHTTP.UnsafeProxyConn do
  @behaviour XHTTP.ConnBehaviour

  import XHTTP.Util
  alias XHTTP.UnsafeProxyConn, as: Conn

  defstruct [
    :hostname,
    :port,
    :scheme,
    :module,
    :state
  ]

  def connect(module, proxy, host, opts \\ []) do
    {proxy_scheme, proxy_hostname, proxy_port} = proxy
    {scheme, hostname, port} = host

    transport = scheme_to_transport(proxy_scheme)
    transport_opts = module.transport_opts()

    opts =
      Keyword.update(opts, :transport_opts, transport_opts, &Keyword.merge(&1, transport_opts))

    with {:ok, transport_state} <- transport.connect(proxy_hostname, proxy_port, opts),
         {:ok, state} <- module.initiate(transport, transport_state, hostname, port, opts) do
      conn = %Conn{
        scheme: scheme,
        hostname: hostname,
        port: port,
        module: module,
        state: state
      }

      {:ok, conn}
    end
  end

  def transport_opts() do
    raise "transport_opts/0 does not apply for #{inspect(__MODULE__)}"
  end

  def initiate(_transport, _transport_state, _hostname, _port, _opts) do
    raise "initiate/5 does not apply for #{inspect(__MODULE__)}"
  end

  def open?(%Conn{module: module, state: state}) do
    module.open?(state)
  end

  def request(%Conn{module: module, state: state} = conn, method, path, headers, body \\ nil) do
    path = request_line(conn, path)

    case module.request(state, method, path, headers, body) do
      {:ok, state, request} -> {:ok, %{conn | state: state}, request}
      {:error, state, reason} -> {:error, %{conn | state: state}, reason}
    end
  end

  def stream_request_body(%Conn{module: module, state: state} = conn, ref, body) do
    case module.stream_request_body(state, ref, body) do
      {:ok, state} -> {:ok, %{conn | state: state}}
      {:error, state, reason} -> {:error, %{conn | state: state}, reason}
    end
  end

  def stream(%Conn{module: module, state: state} = conn, message) do
    case module.stream(state, message) do
      {:ok, state, responses} -> {:ok, %{conn | state: state}, responses}
      {:error, state, reason, responses} -> {:error, %{conn | state: state}, reason, responses}
      :unknown -> :unknown
    end
  end

  def put_private(%Conn{module: module, state: state} = conn, key, value) do
    state = module.put_private(state, key, value)
    %{conn | state: state}
  end

  def get_private(%Conn{module: module, state: state}, key, default \\ nil) do
    module.get_private(state, key, default)
  end

  def delete_private(%Conn{module: module, state: state} = conn, key) do
    state = module.delete_private(state, key)
    %{conn | state: state}
  end

  defp request_line(%Conn{scheme: scheme, hostname: hostname, port: port}, path) do
    %URI{scheme: Atom.to_string(scheme), host: hostname, port: port, path: path}
    |> URI.to_string()
  end
end
