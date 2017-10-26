defmodule XHTTP.Conn do
  alias XHTTP.{Conn, Request, Response}

  @type t() :: %Conn{}

  @type request_ref() :: reference()
  @type tcp_message() ::
          {:tcp, :gen_tcp.socket(), binary()}
          | {:tcp_closed, :gen_tcp.socket()}
          | {:tcp_error, :gen_tcp.socket(), term()}
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
    buffer: ""
  ]

  @spec connect(hostname :: String.t(), port :: :inet.port_number(), opts :: Keyword.t()) ::
          {:ok, t()}
          | {:error, term()}
  def connect(hostname, port, opts \\ []) do
    transport = Keyword.get(opts, :transport, :gen_tcp)
    transport_opts = [active: true, mode: :binary]

    case transport.connect(String.to_charlist(hostname), port, transport_opts) do
      {:ok, socket} ->
        {:ok, %Conn{socket: socket, host: hostname, transport: transport}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec request(t(), method :: atom | String.t(), path :: String.t(), headers(), body :: binary()) ::
          {:ok, t(), request_ref()}
          | {:error, term()}
  def request(%Conn{request: request}, _method, _path, _headers, _body) when is_reference(request) do
    {:error, :request_already_in_flight}
  end

  # TODO: Allow streaming body
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
        conn = %Conn{conn | request: new_request(request_ref, method)}
        {:ok, conn, request_ref}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec stream(t(), tcp_message()) ::
          {:ok, t(), [response()]}
          | {:error, t(), term()}
          | :unknown
  def stream(%Conn{socket: socket}, {:tcp_closed, socket}) do
    {:error, :closed}
  end

  def stream(%Conn{socket: socket}, {:tcp_error, socket, reason}) do
    {:error, reason}
  end

  def stream(%Conn{socket: socket, buffer: buffer, request: request} = conn, {:tcp, socket, data}) do
    data = buffer <> data

    case decode(request.state, conn, data, []) do
      {:ok, conn, responses} -> {:ok, conn, Enum.reverse(responses)}
      other -> other
    end
  catch
    :throw, {:xhttp, reason} ->
      {:error, request.ref, reason}
  end

  def stream(%Conn{socket: socket, request: request} = conn, {:tcp_closed, socket}) do
    # TODO: Update conn state informing socket is closed
    if request.body_left == :until_closed do
      {:ok, conn, [{:done, request.ref}]}
    else
      {:error, conn, :closed}
    end
  end

  def stream(%Conn{socket: socket} = conn, {:tcp_error, socket, reason}) do
    # TODO: Update conn state informing socket is closed
    {:error, conn, reason}
  end

  def stream(%Conn{}, _other) do
    :unknown
  end

  defp decode(:status, conn, data, []) do
    case Response.decode_status_line(data) do
      {:ok, {_version, status, _reason} = status_line, rest} ->
        conn = put_in(conn.request.status, status)
        decode(:headers, conn, rest, [{:status, conn.request.ref, status_line}])

      :more ->
        conn = put_in(conn.request.state, :status)
        {:ok, conn, []}

      :error ->
        {:error, :invalid_response}
    end
  end

  defp decode(:headers, conn, data, responses) do
    case Response.decode_header(data) do
      {:ok, {name, value}, rest} ->
        responses = add_header(name, value, conn.request.ref, responses)
        decode(:headers, conn, rest, responses)

      {:ok, :eof, rest} ->
        responses = reverse_headers(responses)
        content_length = content_length(responses)
        conn = put_in(conn.request.content_length, content_length)
        conn = put_in(conn.request.state, :body)
        decode(:body, conn, rest, responses)

      :more ->
        conn = put_in(conn.request.state, :headers)
        {:ok, conn, responses}

      :error ->
        {:error, :invalid_response}
    end
  end

  defp decode(:body, conn, data, responses) do
    request_ref = conn.request.ref
    body_left = body_left(conn.request)
    conn = put_in(conn.request.body_left, body_left)

    cond do
      body_left == :none ->
        conn = put_in(conn.buffer, data)
        responses = [{:done, request_ref} | responses]
        {:ok, conn, responses}

      body_left == :until_closed or body_left > byte_size(data) ->
        conn = put_in(conn.request.body_left, body_left - byte_size(data))
        responses = [{:done, request_ref}, {:body, request_ref, data} | responses]
        {:ok, conn, responses}

      body_left == byte_size(data) ->
        conn = put_in(conn.request.body_left, 0)
        responses = [{:done, request_ref}, {:body, request_ref, data} | responses]
        {:ok, conn, responses}

      body_left < byte_size(data) ->
        {body, rest} = :binary.part(data, 0, body_left)
        conn = put_in(conn.buffer, rest)
        conn = put_in(conn.request.body_left, 0)
        responses = [{:done, request_ref}, {:body, request_ref, body} | responses]
        {:ok, conn, responses}
    end
  end

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

  defp content_length([{:headers, _request_ref, headers} | _responses]) do
    with [string] <- get_header(headers, "content-length"),
         {length, ""} <- Integer.parse(string) do
      length
    else
      [] ->
        nil

      _other ->
        throw({:xhttp, :invalid_response})
    end
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

  defp new_request(ref, method) do
    %{
      ref: ref,
      state: :status,
      method: method,
      status: nil,
      content_length: nil,
      body_left: nil
    }
  end
end
