defmodule XHTTP1.Conn do
  @moduledoc """
  Streaming API for HTTP connections.

  After a connection is established with `connect/3` and a request has been
  sent with `request/5`, the connection needs to be streamed messages to
  `stream/2` from `:gen_tcp` or `:ssl` socket active modes.

  If the message is from the socket belonging to the given `%Conn{}` then
  `stream/2` will return parts of the response.

  All connection handling happens in the current process.

  The `stream/2` function is pure because it's the users responsibility to
  receive socket messages and pass them to the function, therefor it's important
  to always store the returned `%Conn{}` struct from functions.
  """

  alias XHTTP1.{Conn, Parse, Request, Response}

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

  # TODO: Currently we keep the Host on the conn but we could also supply
  # it on each request so you can use multiple Hosts on a single conn
  defstruct [
    :socket,
    :host,
    :request,
    :transport,
    requests: :queue.new(),
    state: :closed,
    buffer: ""
  ]

  @doc """
  Establishes a connection and returns a `%Conn{}` with the connection state.

  The connection will be in `active: true` mode.
  """
  @spec connect(hostname :: String.t(), port :: :inet.port_number(), opts :: Keyword.t()) ::
          {:ok, t()}
          | {:error, term()}
  def connect(hostname, port, opts \\ []) do
    transport = Keyword.get(opts, :transport, :gen_tcp)
    transport_opts = [packet: :raw, mode: :binary, active: true]

    if transport not in [:gen_tcp, :ssl] do
      raise ArgumentError, "the :transport option must be either :gen_tcp or :ssl"
    end

    with {:ok, socket} <- transport.connect(String.to_charlist(hostname), port, transport_opts),
         :ok <- inet_opts(transport, socket) do
      {:ok, %Conn{socket: socket, host: hostname, transport: transport, state: :open}}
    else
      {:error, reason} ->
        {:error, {:connect, reason}}
    end
  end

  @doc """
  Returns `true` if the connection is currently open.

  Should be called between every request to check that server has not
  closed the connection.
  """
  @spec open?(t()) :: boolean()
  def open?(%Conn{state: state}), do: state == :open

  @doc """
  Sends an HTTP request.

  Requests can be pipelined so the full response does not have to received
  before the next request can be sent. It is up to users to verify that the
  server supports pipelining and that the request is safe to pipeline.

  If `:stream` is given as `body` the request body should be be streamed with
  `stream_request_body/2`.
  """
  @spec request(
          t(),
          method :: atom | String.t(),
          path :: String.t(),
          headers(),
          body :: iodata() | :stream
        ) ::
          {:ok, t(), request_ref()}
          | {:error, term()}
  def request(%Conn{request: %{state: :stream_request}}, _method, _path, _headers, _body) do
    {:error, :request_body_is_streaming}
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
        {:error, {:send, reason}}
    end
  catch
    :throw, {:xhttp, reason} ->
      {:error, reason}
  end

  @doc """
  Streams the request body.

  Requires the `body` to be set as `:stream` in `request/5`. The body will be
  sent until `:eof` is given.

  Users should send the appropriate request headers to indicate the length of
  the message body.
  """
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
      {:error, reason} -> {:error, {:send, reason}}
    end
  end

  @doc """
  Streams the HTTP response.

  This functions takes messages received from `:gen_tcp` or `:ssl` sockets in
  active mode and returns the HTTP response in parts:

    * `:status` - This response will always be returned and will be the first
      response returned for a request.
    * `:headers` - Headers will always be returned after the status and before
      the body, the headers will only be returned when all headers have been
      received. Trailing headers can optionally be returned after the body
      and before done.
    * `:body` - The body is optional and can be returned in multiple parts.
    * `:done` - This is the last response for a request and indicates that the
      response is done streaming.

  If the message does not belong to the connection's socket `:unknown` will
  be returned.

  If requests are pipelined multiple responses may be returned, use the request
  reference `t:request_ref/0` to distinguish them.
  """
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
    conn = request_done(conn)

    if request.body == :until_closed do
      {:ok, conn, [{:done, request.ref}]}
      # TODO: Notify that we are closed
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

  defp inet_opts(transport, socket) do
    inet = transport_to_inet(transport)

    with {:ok, opts} <- inet.getopts(socket, [:sndbuf, :recbuf, :buffer]) do
      buffer =
        Keyword.fetch!(opts, :buffer)
        |> max(Keyword.fetch!(opts, :sndbuf))
        |> max(Keyword.fetch!(opts, :recbuf))

      inet.setopts(socket, buffer: buffer)
    end
  end

  defp decode(:status, %{request: request} = conn, data, responses) do
    case Response.decode_status_line(data) do
      {:ok, {version, status, _reason} = status_line, rest} ->
        request = %{request | version: version, status: status, state: :headers}
        conn = %{conn | request: request}
        responses = [{:status, request.ref, status_line} | responses]
        decode(:headers, conn, rest, responses)

      :more ->
        conn = put_in(conn.buffer, data)
        {:ok, conn, responses}

      :error ->
        {:error, :invalid_status_line}
    end
  end

  defp decode(:headers, %{request: request} = conn, data, responses) do
    decode_headers(conn, request, data, responses, request.headers_buffer)
  end

  defp decode(:body, conn, data, responses) do
    body = message_body(conn.request)
    conn = put_in(conn.request.body, body)
    decode_body(body, conn, data, conn.request.ref, responses)
  end

  defp decode_headers(conn, request, data, responses, headers) do
    case Response.decode_header(data) do
      {:ok, {name, value}, rest} ->
        headers = [{name, value} | headers]
        request = store_header(request, name, value)
        decode_headers(conn, request, rest, responses, headers)

      {:ok, :eof, rest} ->
        responses = [{:headers, request.ref, Enum.reverse(headers)} | responses]
        request = %{request | state: :body, headers_buffer: []}
        conn = %{conn | buffer: "", request: request}
        decode(:body, conn, rest, responses)

      :more ->
        request = %{request | headers_buffer: headers}
        conn = %{conn | buffer: data, request: request}
        {:ok, conn, responses}

      :error ->
        {:error, :invalid_header}
    end
  end

  defp decode_body(:none, conn, data, request_ref, responses) do
    conn = put_in(conn.buffer, data)
    conn = request_done(conn)
    responses = [{:done, request_ref} | responses]
    {:ok, conn, responses}
  end

  defp decode_body(:until_closed, conn, data, request_ref, responses) do
    responses = add_body(data, request_ref, responses)
    {:ok, conn, responses}
  end

  defp decode_body({:content_length, length}, conn, data, request_ref, responses) do
    cond do
      length > byte_size(data) ->
        conn = put_in(conn.request.body, {:content_length, length - byte_size(data)})
        responses = add_body(data, request_ref, responses)
        {:ok, conn, responses}

      length <= byte_size(data) ->
        <<body::binary-size(length), rest::binary>> = data
        conn = request_done(conn)
        responses = [{:done, request_ref} | add_body(body, request_ref, responses)]
        next_request(conn, rest, responses)
    end
  end

  defp decode_body({:chunked, nil}, conn, "", _request_ref, responses) do
    conn = put_in(conn.buffer, "")
    conn = put_in(conn.request.body, {:chunked, nil})
    {:ok, conn, responses}
  end

  defp decode_body({:chunked, nil}, conn, data, request_ref, responses) do
    case Integer.parse(data, 16) do
      {_size, ""} ->
        conn = put_in(conn.buffer, data)
        conn = put_in(conn.request.body, {:chunked, nil})
        {:ok, conn, responses}

      {0, rest} ->
        decode_body({:chunked, :metadata, :trailer}, conn, rest, request_ref, responses)

      {size, rest} when size > 0 ->
        decode_body({:chunked, :metadata, size}, conn, rest, request_ref, responses)

      _other ->
        {:error, :invalid_chunk_size}
    end
  end

  defp decode_body({:chunked, :metadata, size}, conn, data, request_ref, responses) do
    case Parse.ignore_until_crlf(data) do
      {:ok, rest} ->
        decode_body({:chunked, size}, conn, rest, request_ref, responses)

      :more ->
        conn = put_in(conn.buffer, data)
        conn = put_in(conn.request.body, {:chunked, :metadata, size})
        {:ok, conn, responses}
    end
  end

  defp decode_body({:chunked, :trailer}, conn, data, _request_ref, responses) do
    decode_trailer_headers(conn, data, responses, conn.request.headers_buffer)
  end

  defp decode_body({:chunked, :crlf}, conn, data, request_ref, responses) do
    case data do
      <<"\r\n", rest::binary>> ->
        conn = put_in(conn.request.body, {:chunked, nil})
        decode_body({:chunked, nil}, conn, rest, request_ref, responses)

      _other when byte_size(data) < 2 ->
        conn = put_in(conn.buffer, data)
        {:ok, conn, responses}

      _other ->
        {:error, :missing_crlf_after_chunk}
    end
  end

  defp decode_body({:chunked, length}, conn, data, request_ref, responses) do
    cond do
      length > byte_size(data) ->
        conn = put_in(conn.buffer, "")
        conn = put_in(conn.request.body, {:chunked, length - byte_size(data)})
        responses = add_body(data, request_ref, responses)
        {:ok, conn, responses}

      length <= byte_size(data) ->
        <<body::binary-size(length), rest::binary>> = data
        responses = add_body(body, request_ref, responses)
        conn = put_in(conn.request.body, {:chunked, :crlf})
        decode_body({:chunked, :crlf}, conn, rest, request_ref, responses)
    end
  end

  defp decode_trailer_headers(conn, data, responses, headers) do
    case Response.decode_header(data) do
      {:ok, {name, value}, rest} ->
        headers = [{name, value} | headers]
        decode_trailer_headers(conn, rest, responses, headers)

      {:ok, :eof, rest} ->
        responses = [
          {:done, conn.request.ref}
          | add_trailing_headers(headers, conn.request.ref, responses)
        ]

        conn = request_done(conn)
        next_request(conn, rest, responses)

      :more ->
        request = %{conn.request | body: {:chunked, :trailer}, headers_buffer: headers}
        conn = %{conn | buffer: data, request: request}
        {:ok, conn, responses}

      :error ->
        {:error, :invalid_trailer_header}
    end
  end

  defp next_request(%{request: nil} = conn, data, responses) do
    # TODO: Figure out if we should keep buffering even though there are no
    # requests in flight
    {:ok, %{conn | buffer: data}, responses}
  end

  defp next_request(conn, data, responses) do
    decode(:status, %{conn | state: :status}, data, responses)
  end

  defp add_trailing_headers([], _request_ref, responses), do: responses

  defp add_trailing_headers(headers, request_ref, responses),
    do: [{:headers, request_ref, Enum.reverse(headers)} | responses]

  defp add_body("", _request_ref, responses), do: responses

  # TODO: Concat binaries or build iodata?
  defp add_body(new_data, request_ref, [{:body, request_ref, data} | responses]),
    do: [{:body, request_ref, data <> new_data} | responses]

  defp add_body(new_data, request_ref, responses),
    do: [{:body, request_ref, new_data} | responses]

  defp store_header(%{content_length: nil} = request, "content-length", value) do
    %{request | content_length: Parse.content_length_header(value)}
  end

  defp store_header(%{connection: connection} = request, "connection", value) do
    %{request | connection: connection ++ Parse.connection_header(value)}
  end

  defp store_header(%{transfer_encoding: transfer_encoding} = request, "transfer-encoding", value) do
    %{request | transfer_encoding: transfer_encoding ++ Parse.transfer_encoding_header(value)}
  end

  defp store_header(_request, name, _value) when name in ~w(content-length) do
    throw({:xhttp, :invalid_response})
  end

  defp store_header(request, _name, _value) do
    request
  end

  defp request_done(%{request: request} = conn) do
    # TODO: Figure out what to do if connection is closed or there is no next
    # request and we still have data on the socket. RFC7230 3.4
    conn = pop_request(conn)

    cond do
      "close" in request.connection -> close(conn)
      request.version >= {1, 1} -> conn
      "keep-alive" in request.connection -> conn
      true -> close(conn)
    end
  end

  defp pop_request(conn) do
    case :queue.out(conn.requests) do
      {{:value, request}, requests} ->
        %{conn | request: request, requests: requests}

      {:empty, requests} ->
        %{conn | request: nil, requests: requests}
    end
  end

  defp close(conn) do
    if conn.buffer != "" do
      Logger.debug(["Connection closed with data left in the buffer: ", inspect(conn.buffer)])
    end

    :ok = conn.transport.close(conn.socket)
    %{conn | state: :closed}
  end

  # TODO: We should probably error if both transfer-encoding and content-length
  # is set. RFC7230 3.3.3:
  # > If a message is received with both a Transfer-Encoding and a
  # > Content-Length header field, the Transfer-Encoding overrides the
  # > Content-Length.  Such a message might indicate an attempt to
  # > perform request smuggling (Section 9.5) or response splitting
  # > (Section 9.4) and ought to be handled as an error.  A sender MUST
  # > remove the received Content-Length field prior to forwarding such
  # > a message downstream.
  defp message_body(%{body: nil, method: method, status: status} = request) do
    cond do
      method == "HEAD" or status in 100..199 or status in [204, 304] ->
        :none

      # method == "CONNECT" and status in 200..299 -> nil

      "chunked" == List.first(request.transfer_encoding) ->
        {:chunked, nil}

      request.content_length ->
        {:content_length, request.content_length}

      true ->
        :until_closed
    end
  end

  defp message_body(%{body: body}) do
    body
  end

  defp normalize_method(atom) when is_atom(atom), do: atom |> Atom.to_string() |> String.upcase()
  defp normalize_method(binary) when is_binary(binary), do: String.upcase(binary)

  defp transport_to_inet(:gen_tcp), do: :inet
  defp transport_to_inet(:ssl), do: :ssl

  defp new_request(ref, state, method) do
    %{
      ref: ref,
      state: state,
      method: method,
      version: nil,
      status: nil,
      headers_buffer: [],
      content_length: nil,
      connection: [],
      transfer_encoding: [],
      body: nil
    }
  end
end
