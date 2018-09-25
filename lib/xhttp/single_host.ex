defmodule XHTTP.SingleHost do
  use GenServer

  alias XHTTPN.Conn

  # max_concurrent_requests: pos_integer()
  # keepalive_timeout: pos_integer()
  # die_after_close: boolean()
  # fill_connections: boolean() (only http1)
  # max_connections: pos_integer() (only http1)
  # pipeline: boolean() (only http1)
  # max_pipeline_length: pos_integer() (only http1 when pipelining)
  # connection_reuse_strategy: :fifo | :lifo (only http1)
  # connection_fill_strategy: :fill_connections | :fill_pipeline (only http1 when pipelining)

  def start_link(host, port, opts \\ []) do
    GenServer.start_link(__MODULE__, {host, port, opts})
  end

  def init({host, port, opts}) do
    {:ok, new_state(host, port, opts)}
  end

  def request(server, method, path, headers, body) do
    GenServer.call(server, {:request, {method, path, headers, body}})
  end

  def handle_call({:request, request}, from, %{conn_refs: []} = s) do
    connect(request, from, s)
  end

  def handle_call({:request, request}, from, %{protocol: :http1, conn_refs: conn_refs} = s) do
    conn =
      Enum.find_value(conn_refs, fn ref ->
        conn = Map.fetch!(s.conns, ref)

        if Conn.get_private(conn, :pipeline) == 0 do
          conn
        end
      end)

    if conn do
      request(conn, request, from, s)
    else
      # TODO: check :max_connections
      connect(request, from, s)
    end
  end

  def handle_call({:request, request}, from, %{protocol: :http2, conn_refs: [ref]} = s) do
    # TODO: check :max_concurrent_requests
    conn = Map.fetch!(s.conns, ref)
    request(conn, request, from, s)
  end

  def handle_info(message, s) do
    s =
      Enum.reduce(s.conns, s, fn {_key, conn}, s ->
        case Conn.stream(conn, message) do
          {:ok, conn, responses} ->
            conn_ref = Conn.get_private(conn, :ref)
            s = put_in(s.conns[conn_ref], conn)
            Enum.reduce(responses, s, &apply_response(&1, conn_ref, &2))

          {:error, conn, reason, responses} ->
            conn_ref = Conn.get_private(conn, :ref)
            s = put_in(s.conns[conn_ref], conn)
            s = Enum.reduce(responses, s, &apply_response(&1, conn_ref, &2))
            close_conn(conn, reason, s)

          :unknown ->
            s
        end
      end)

    {:noreply, s}
  end

  defp connect(request, from, s) do
    case Conn.connect(s.host, s.port, s.opts) do
      {:ok, conn} ->
        ref = make_ref()
        conn = Conn.put_private(conn, :ref, ref)
        conn = Conn.put_private(conn, :pipeline, 0)
        conn_requests = Map.put(s.conn_requests, ref, MapSet.new())
        conns = Map.put(s.conns, ref, conn)

        s = %{
          s
          | conns: conns,
            conn_refs: [ref],
            protocol: protocol(conn),
            conn_requests: conn_requests
        }

        request(conn, request, from, s)

      {:error, reason} ->
        {:reply, {:error, reason}, s}
    end
  end

  defp request(conn, {method, path, headers, body}, from, s) do
    case Conn.request(conn, method, path, headers, body) do
      {:ok, conn, ref} ->
        conn_ref = Conn.get_private(conn, :ref)
        pipeline_length = Conn.get_private(conn, :pipeline)
        conn = Conn.put_private(conn, :pipeline, pipeline_length + 1)
        request = %{from: from, status: nil, headers: nil, data: ""}
        requests = Map.put(s.requests, ref, request)
        conns = Map.put(s.conns, conn_ref, conn)

        conn_requests =
          Map.update!(s.conn_requests, conn_ref, &MapSet.put(&1, ref))

        s = %{s | conns: conns, requests: requests, conn_requests: conn_requests}
        {:noreply, s}

      {:error, reason} ->
        s = close_conn(conn, reason, s)
        {:noreply, s}
    end
  end

  defp apply_response({:status, ref, status}, _conn_ref, s) do
    put_in(s.requests[ref].status, status)
  end

  defp apply_response({:headers, ref, headers}, _conn_ref, s) do
    put_in(s.requests[ref].headers, headers)
  end

  defp apply_response({:data, ref, data}, _conn_ref, s) do
    update_in(s.requests[ref].data, &[&1 | data])
  end

  defp apply_response({:done, ref}, conn_ref, s) do
    request = Map.fetch!(s.requests, ref)
    request_done({:ok, {request.status, request.headers, request.data}}, ref, conn_ref, s)
  end

  defp apply_response({:error, ref, reason}, conn_ref, s) do
    request_done({:error, reason}, ref, conn_ref, s)
  end

  defp request_done(reply, request_ref, conn_ref, s) do
    conn = Map.fetch!(s.conns, conn_ref)
    pipeline_length = Conn.get_private(conn, :pipeline)
    conn = Conn.put_private(conn, :pipeline, pipeline_length - 1)
    conns = Map.put(s.conns, conn_ref, conn)
    request = Map.fetch!(s.requests, request_ref)
    requests = Map.delete(s.requests, request_ref)
    conn_requests = Map.update!(s.conn_requests, conn_ref, &MapSet.delete(&1, request_ref))
    GenServer.reply(request.from, reply)
    %{s | requests: requests, conn_requests: conn_requests, conns: conns}
  end

  defp close_conn(conn, reason, s) do
    conn_ref = Conn.get_private(conn, :ref)
    error_requests = Map.fetch!(s.conn_requests, conn_ref)
    conn_requests = Map.delete(s.conn_requests, conn_ref)
    conns = Map.delete(s.conns, conn_ref)
    conn_refs = List.delete(s.conn_refs, conn_ref)

    requests =
      Enum.reduce(error_requests, s.requests, fn ref, requests ->
        request = Map.fetch!(requests, ref)
        GenServer.reply(request.from, {:error, reason})
        Map.delete(s.requests, ref)
      end)

    %{s | requests: requests, conn_requests: conn_requests, conns: conns, conn_refs: conn_refs}
  end

  defp new_state(host, port, opts) do
    %{
      host: host,
      port: port,
      opts: opts,
      protocol: nil,
      conns: %{},
      conn_requests: %{},
      conn_refs: [],
      requests: %{}
    }
  end

  defp protocol(%XHTTP1.Conn{}), do: :http1
  defp protocol(%XHTTP2.Conn{}), do: :http2
end
