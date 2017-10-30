defmodule XHTTP.Conn do
  alias XHTTP.{Conn, Request, Response}

  require Logger

  @type t() :: %Conn{}

  @type request_ref() :: reference()
  @type tcp_message() ::
          {:tcp | :ssl, :gen_tcp.socket(), binary()}
          | {:tcp_close | :ssl_close, :gen_tcp.socket()}
          | {:tcp_error | :ssl_error, :gen_tcp.socket(), term()}
  @type response() ::
          {:status, request_ref(), status_line()}
          | {:headers, request_ref(), headers()}
          | {:body, request_ref(), binary()}
          | {:done, request_ref()}
  @type status_line() :: {http_version(), status(), reason()}
  @type http_version() :: {non_neg_integer(), non_neg_integer()}
  @type status() :: non_neg_integer()
  @type reason() :: String.t()
  @type headers() :: [{String.t(), String.t()}]

  defstruct [
    :socket,
    :host,
    :request,
    :transport,
    requests: :queue.new(),
    state: :closed,
    buffer: ""
  ]

  @spec connect(hostname :: String.t(), port :: :inet.port_number(), opts :: Keyword.t()) ::
          {:ok, t()}
          | {:error, term()}
  def connect(hostname, port, opts \\ []) do
    transport = Keyword.get(opts, :transport, :gen_tcp)
    transport_opts = [packet: :raw, mode: :binary, active: true]

    case transport.connect(String.to_charlist(hostname), port, transport_opts) do
      {:ok, socket} ->
        inet_opts(transport, socket)
        {:ok, %Conn{socket: socket, host: hostname, transport: transport, state: :open}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp inet_opts(transport, socket) do
    inet = transport_to_inet(transport)
    {:ok, opts} = inet.getopts(socket, [:sndbuf, :recbuf, :buffer])

    buffer =
      Keyword.fetch!(opts, :buffer)
      |> max(Keyword.fetch!(opts, :sndbuf))
      |> max(Keyword.fetch!(opts, :recbuf))

    :ok = inet.setopts(socket, buffer: buffer)
  end

  @spec open?(t()) :: boolean()
  def open?(%Conn{state: state}), do: state == :open

  @spec request(
          t(),
          method :: atom | String.t(),
          path :: String.t(),
          headers(),
          body :: iodata() | :stream
        ) ::
          {:ok, t(), request_ref()}
          | {:error, term()}
  def request(%Conn{request: request}, _method, _path, _headers, _body) when is_reference(request) do
    {:error, :request_already_in_flight}
  end

  def request(
        %Conn{socket: socket, host: host, transport: transport} = conn,
        method,
        path,
        headers,
        body
      ) do
    method = normalize_method(method)
    iodata = Request.encode(method, path, host, headers, body)

    case transport.send(socket, iodata) do
      :ok ->
        request_ref = make_ref()
        state = if body == :stream, do: :stream_request, else: :status
        request = new_request(request_ref, state, method)

        if conn.request == nil do
          conn = %Conn{conn | request: request}
          {:ok, conn, request_ref}
        else
          requests = :queue.in(request, conn.requests)
          conn = %Conn{conn | requests: requests}
          {:ok, conn, request_ref}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec stream_request_body(t(), body :: iodata() | :eof) :: {:ok, t()} | {:error, term()}
  def stream_request_body(%Conn{request: %{state: :stream_request}} = conn, :eof) do
    {:ok, put_in(conn.request.state, :status)}
  end

  def stream_request_body(
        %Conn{request: %{state: :stream_request}, transport: transport, socket: socket} = conn,
        body
      ) do
    case transport.send(socket, body) do
      :ok -> {:ok, conn}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec stream(t(), tcp_message()) ::
          {:ok, t(), [response()]}
          | {:error, t(), term()}
          | :unknown
  def stream(%Conn{request: %{state: :stream_request}}, _message) do
    {:error, :request_body_not_streamed}
  end

  def stream(%Conn{socket: socket, buffer: buffer, request: nil} = conn, {tag, socket, data})
      when tag in [:tcp, :ssl] do
    # TODO: Figure out if we should keep buffering even though there are no
    # requests in flight
    {:ok, put_in(conn.buffer, buffer <> data), []}
  end

  def stream(%Conn{socket: socket, buffer: buffer, request: request} = conn, {tag, socket, data})
      when tag in [:tcp, :ssl] do
    data = buffer <> data

    case decode(request.state, conn, data, []) do
      {:ok, conn, responses} -> {:ok, conn, Enum.reverse(responses)}
      other -> other
    end
  catch
    :throw, {:xhttp, reason} ->
      {:error, request.ref, reason}
  end

  def stream(%Conn{socket: socket, request: request} = conn, {tag, socket})
      when tag in [:tcp_close, :ssl_close] do
    conn = put_in(conn.state, :closed)

    if request.body_left == :until_closed do
      {:ok, conn, [{:done, request.ref}]}
    else
      {:error, conn, :closed}
    end
  end

  def stream(%Conn{socket: socket} = conn, {tag, socket, reason})
      when tag in [:tcp_error, :ssl_error] do
    conn = put_in(conn.state, :closed)
    {:error, conn, reason}
  end

  def stream(%Conn{}, _other) do
    :unknown
  end

  defp decode(:status, %{request: request} = conn, data, []) do
    case Response.decode_status_line(data) do
      {:ok, {version, status, _reason} = status_line, rest} ->
        request = %{request | version: version, status: status, state: :headers}
        conn = put_in(conn.request, request)
        decode(:headers, conn, rest, [{:status, request.ref, status_line}])

      :more ->
        conn = put_in(conn.buffer, data)
        {:ok, conn, []}

      :error ->
        {:error, :invalid_response}
    end
  end

  defp decode(:headers, %{request: request} = conn, data, responses) do
    case Response.decode_header(data) do
      {:ok, {name, value}, rest} ->
        responses = add_header(name, value, request.ref, responses)
        decode(:headers, conn, rest, responses)

      {:ok, :eof, rest} ->
        responses = reverse_headers(responses)

        request = %{
          request
          | content_length: content_length_header(responses),
            connection: connection_header(responses),
            state: :body
        }

        conn = put_in(conn.request, request)
        decode(:body, conn, rest, responses)

      :more ->
        conn = put_in(conn.buffer, data)
        {:ok, conn, responses}

      :error ->
        {:error, :invalid_response}
    end
  end

  defp decode(:body, conn, data, responses) do
    request_ref = conn.request.ref
    body_left = body_left(conn.request)
    conn = put_in(conn.request.body_left, body_left)
    conn = put_in(conn.buffer, "")

    cond do
      body_left == :none ->
        conn = put_in(conn.buffer, data)
        responses = [{:done, request_ref} | responses]
        {:ok, conn, responses}

      body_left == :until_closed ->
        responses = add_body(data, request_ref, responses)
        {:ok, conn, responses}

      body_left > byte_size(data) ->
        conn = put_in(conn.request.body_left, body_left - byte_size(data))
        responses = add_body(data, request_ref, responses)
        {:ok, conn, responses}

      body_left == byte_size(data) ->
        conn = put_in(conn.request.body_left, 0)
        responses = [{:done, request_ref} | add_body(data, request_ref, responses)]
        {:ok, request_done(conn), responses}

      body_left < byte_size(data) ->
        <<body::binary-size(body_left), rest::binary>> = data
        conn = put_in(conn.buffer, rest)
        conn = put_in(conn.request.body_left, 0)
        responses = [{:done, request_ref} | add_body(body, request_ref, responses)]
        {:ok, request_done(conn), responses}
    end
  end

  defp add_body("", _request_ref, responses), do: responses
  defp add_body(data, request_ref, responses), do: [{:body, request_ref, data} | responses]

  defp add_header(name, value, request_ref, [{:headers, request_ref, headers} | responses]) do
    headers = [{name, value} | headers]
    [{:headers, request_ref, headers} | responses]
  end

  defp add_header(name, value, request_ref, responses) do
    headers = [{name, value}]
    [{:headers, request_ref, headers} | responses]
  end

  defp reverse_headers([{:headers, request_ref, headers} | responses]) do
    [{:headers, request_ref, Enum.reverse(headers)} | responses]
  end

  defp reverse_headers(responses) do
    responses
  end

  defp content_length_header([{:headers, _request_ref, headers} | _responses]) do
    with [string] <- get_header(headers, "content-length"),
         {length, ""} <- Integer.parse(string) do
      length
    else
      [] -> nil
      _other -> throw({:xhttp, :invalid_response})
    end
  end

  defp content_length_header(_responses) do
    nil
  end

  defp connection_header([{:headers, _request_ref, headers} | _responses]) do
    case get_header(headers, "connection") do
      [token] -> token
      _ -> nil
    end
  end

  defp connection_header(_responses) do
    nil
  end

  defp request_done(%{request: request} = conn) do
    conn = next_request(conn)

    cond do
      request.connection == "close" -> close(conn)
      request.version >= {1, 1} -> conn
      request.connection == "keep-alive" -> conn
      true -> close(conn)
    end
  end

  defp next_request(conn) do
    case :queue.out(conn.requests) do
      {{:value, request}, requests} ->
        %{conn | request: request, requests: requests}
      {:empty, requests} ->
        %{conn | request: nil, requests: requests}
    end
  end

  defp close(conn) do
    if conn.buffer != "" do
      Logger.debug("Connection closed with data left on the socket: ", inspect(conn.buffer))
    end

    :ok = conn.transport.close(conn.socket)
    %{conn | state: :closed}
  end

  defp body_left(%{body_left: nil, method: method, status: status, content_length: content_length}) do
    cond do
      method == "HEAD" or status in 100..199 or status in [204, 304] ->
        :none

      # method == "CONNECT" and status in 200..299 -> nil
      # transfer-encoding

      content_length ->
        content_length

      true ->
        :until_closed
    end
  end

  defp body_left(%{body_left: body_left}) do
    body_left
  end

  defp get_header(headers, name) do
    for {n, v} <- headers, n == name, do: v
  end

  defp normalize_method(atom) when is_atom(atom), do: atom |> Atom.to_string() |> String.upcase()
  defp normalize_method(binary) when is_binary(binary), do: String.upcase(binary)

  defp transport_to_inet(:gen_tcp), do: :inet
  defp transport_to_inet(other), do: other

  defp new_request(ref, state, method) do
    %{
      ref: ref,
      state: state,
      method: method,
      version: nil,
      status: nil,
      content_length: nil,
      connection: nil,
      body_left: nil
    }
  end
end
