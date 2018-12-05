defmodule XHTTP.UnsafeProxyConn do
  @behaviour XHTTP.ConnBehaviour

  alias XHTTP.UnsafeProxyConn, as: Conn

  defstruct [
    :hostname,
    :port,
    :scheme,
    :module,
    :state
  ]

  @opaque t() :: %Conn{}

  @type scheme :: :http | :https | module()
  @type request_ref() :: XHTTP.ConnBehaviour.request_ref()
  @type tcp_message() :: XHTTP.ConnBehaviour.tcp_message()
  @type response() :: XHTTP.ConnBehaviour.response()
  @type status() :: XHTTP.ConnBehaviour.response()
  @type headers() :: XHTTP.ConnBehaviour.headers()
  @type host_triple :: {scheme(), hostname :: String.t(), :inet.port_number()}

  @spec connect(host_triple(), host_triple(), opts :: Keyword.t()) ::
          {:ok, t()} | {:error, term()}
  def connect(proxy, host, opts \\ []) do
    {proxy_scheme, proxy_hostname, proxy_port} = proxy
    {scheme, hostname, port} = host

    with {:ok, state} <- XHTTP1.Conn.connect(proxy_scheme, proxy_hostname, proxy_port, opts) do
      conn = %Conn{
        scheme: scheme,
        hostname: hostname,
        port: port,
        module: state.__struct__,
        state: state
      }

      {:ok, conn}
    end
  end

  @impl true
  @spec get_transport(t()) :: {module(), XHTTP.Transport.state()}
  def get_transport(%Conn{module: module, state: state}) do
    module.get_transport(state)
  end

  @impl true
  @spec put_transport(t(), {module(), XHTTP.Transport.state()}) :: t()
  def put_transport(%Conn{module: module, state: state}, transport) do
    module.put_transport(state, transport)
  end

  @impl true
  @spec transport_socket(t()) :: port()
  def transport_socket(%Conn{module: module, state: state}) do
    module.socket(state)
  end

  @impl true
  @spec initiate(
          module(),
          XHTTP.Transport.state(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: no_return()
  def initiate(_transport, _transport_state, _hostname, _port, _opts) do
    raise "initiate/5 does not apply for #{inspect(__MODULE__)}"
  end

  @impl true
  @spec open?(t()) :: boolean()
  def open?(%Conn{module: module, state: state}) do
    module.open?(state)
  end

  @impl true
  @spec request(
          t(),
          method :: atom | String.t(),
          path :: String.t(),
          headers(),
          body :: iodata() | nil | :stream
        ) ::
          {:ok, t(), request_ref()}
          | {:error, t(), term()}
  def request(%Conn{module: module, state: state} = conn, method, path, headers, body \\ nil) do
    path = request_line(conn, path)

    case module.request(state, method, path, headers, body) do
      {:ok, state, request} -> {:ok, %{conn | state: state}, request}
      {:error, state, reason} -> {:error, %{conn | state: state}, reason}
    end
  end

  @impl true
  @spec stream_request_body(t(), request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(%Conn{module: module, state: state} = conn, ref, body) do
    case module.stream_request_body(state, ref, body) do
      {:ok, state} -> {:ok, %{conn | state: state}}
      {:error, state, reason} -> {:error, %{conn | state: state}, reason}
    end
  end

  @impl true
  @spec stream(t(), tcp_message()) ::
          {:ok, t(), [response()]}
          | {:error, t(), term(), [response()]}
          | :unknown
  def stream(%Conn{module: module, state: state} = conn, message) do
    case module.stream(state, message) do
      {:ok, state, responses} -> {:ok, %{conn | state: state}, responses}
      {:error, state, reason, responses} -> {:error, %{conn | state: state}, reason, responses}
      :unknown -> :unknown
    end
  end

  @impl true
  @spec put_private(t(), atom(), term()) :: t()
  def put_private(%Conn{module: module, state: state} = conn, key, value) do
    state = module.put_private(state, key, value)
    %{conn | state: state}
  end

  @impl true
  @spec get_private(t(), atom(), term()) :: term()
  def get_private(%Conn{module: module, state: state}, key, default \\ nil) do
    module.get_private(state, key, default)
  end

  @impl true
  @spec delete_private(t(), atom()) :: t()
  def delete_private(%Conn{module: module, state: state} = conn, key) do
    state = module.delete_private(state, key)
    %{conn | state: state}
  end

  defp request_line(%Conn{scheme: scheme, hostname: hostname, port: port}, path) do
    %URI{scheme: Atom.to_string(scheme), host: hostname, port: port, path: path}
    |> URI.to_string()
  end
end
