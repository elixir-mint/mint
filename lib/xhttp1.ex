defmodule XHTTP1 do
  @moduledoc """
  Processless HTTP client with support for HTTP/1.1.

  This module provides a data structure that represents an HTTP/1.1 connection to
  a given server. The connection is represented as an opaque struct `%XHTTP1{}`.
  The connection is a data structure and is not backed by a process, and all the
  connection handling happens in the process that creates the struct.

  This module and data structure work exactly like the ones described in the `XHTTP`
  module, with the exception that `XHTTP1` specifically deals with HTTP/1.1 while
  `XHTTP` deals seamlessly with HTTP/1.1 and HTTP/2. For more information on
  how to use the data structure and client architecture, see `XHTTP`.
  """

  import XHTTPCore.Util

  alias XHTTP1.{Parse, Request, Response}

  require Logger

  @behaviour XHTTPCore.Conn

  @opaque t() :: %XHTTP1{}

  @type scheme :: :http | :https | module()
  @type request_ref() :: XHTTPCore.Conn.request_ref()
  @type socket_message() :: XHTTPCore.Conn.socket_message()
  @type response() :: XHTTPCore.Conn.response()
  @type status() :: XHTTPCore.Conn.response()
  @type headers() :: XHTTPCore.Conn.headers()

  # TODO: Currently we keep the Host on the conn but we could also supply
  # it on each request so you can use multiple Hosts on a single conn
  defstruct [
    :host,
    :request,
    :socket,
    :transport,
    requests: :queue.new(),
    state: :closed,
    buffer: "",
    private: %{}
  ]

  @doc """
  Creates a new HTTP/1.1 connection to a given server.

  Creates a new `%XHTTP1{}` struct and establishes the connection to the given server,
  identified by the given `host` and `port` combination. Both HTTP and HTTPS are supported
  by passing respectively `:http` and `:https` as the `scheme`.

  The connection struct wraps a TCP/SSL socket, which is created once the connection
  is established inside this function. If HTTP is used, then the created socket is a TCP
  socket and the `:gen_tcp` module is used to create that socket. If HTTPS is used, then
  the created socket is an SSL socket and the `:ssl` module is used to create that socket.
  The socket is created in active mode, which is why it is important to know the type of
  the socket: messages from the socket will be delivered directly to the process that
  creates the connection and tagged appropriately (see the `:gen_tcp` and `:ssl` modules).

  ## Options

    * `:transport_opts` - (keyword) options to be given to the transport being used.
      These options will be merged with some default options that cannot be overridden.

  ## Examples

      {:ok, conn} = XHTTP1.connect(:http, "httpbin.org", 80)

  """
  @spec connect(scheme(), String.t(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def connect(scheme, hostname, port, opts \\ []) do
    # TODO: Also ALPN negotiate HTTP1?

    transport = scheme_to_transport(scheme)
    transport_opts = Keyword.get(opts, :transport_opts, [])

    case transport.connect(hostname, port, transport_opts) do
      {:ok, socket} ->
        initiate(transport, socket, hostname, port, opts)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  TODO: write docs.
  """
  @spec upgrade(
          module(),
          XHTTPCore.Transport.socket(),
          scheme(),
          String.t(),
          :inet.port_number(),
          Keyword.t()
        ) :: {:ok, t()} | {:error, term()}
  def upgrade(old_transport, socket, scheme, hostname, port, opts) do
    # TODO: Also ALPN negotiate HTTP1?

    new_transport = scheme_to_transport(scheme)
    transport_opts = Keyword.get(opts, :transport_opts, [])

    case new_transport.upgrade(socket, old_transport, hostname, port, transport_opts) do
      {:ok, {new_transport, socket}} ->
        initiate(new_transport, socket, hostname, port, opts)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc false
  @impl true
  @spec initiate(
          module(),
          XHTTPCore.Transport.socket(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def initiate(transport, socket, hostname, _port, _opts) do
    with :ok <- inet_opts(transport, socket),
         :ok <- transport.setopts(socket, active: :once) do
      conn = %XHTTP1{
        transport: transport,
        socket: socket,
        host: hostname,
        state: :open
      }

      {:ok, conn}
    else
      error ->
        transport.close(socket)
        error
    end
  end

  @doc """
  Checks whether the connection is open.

  This function returns `true` if the connection is open, `false` otherwise. It should
  be used to check that a connection is open before sending requests or performing
  operations that involve talking to the server.

  If a connection is not open, it has become useless and you should get rid of it.
  If you still need a connection to the server, start a new connection with `connect/4`.

  ## Examples

      {:ok, conn} = XHTTP1.connect(:http, "httpbin.org", 80)
      XHTTP1.open?(conn)
      #=> true

  """
  @impl true
  @spec open?(t()) :: boolean()
  def open?(%XHTTP1{state: state}), do: state == :open

  @doc """
  Sends a request to the connected server.

  This function sends a new request to the server that `conn` is connected to.
  `method` is a string representing the method for the request, such as `"GET"`
  or `"POST"`. `path` is the path on the host to send the request to. `headers`
  is a list of request headers in the form `{header_name, header_value}` with
  `header_name` and `header_value` being strings. `body` can have one of three
  values:

    * `nil` - no body is sent with the request. This is the default value.

    * iodata - the body to send for the request.

    * `:stream` - when the value of the body is `:stream` the request
      body can be streamed on the connection. See `stream_request_body/3`.

  If the request is sent correctly, this function returns `{:ok, conn, request_ref}`.
  `conn` is an updated connection that should be stored over the old connection.
  `request_ref` is a unique reference that can be used to match on responses for this
  request that are returned by `stream/2`. See `stream/2` for more information.

  If there's an error with sending the request, `{:error, conn, reason}` is returned.
  `reason` is the cause of the error. `conn` is an updated connection. It's important
  to store the returned connection over the old connection in case of errors too, because
  the state of the connection might change when there are errors as well. An error when
  sending a request **does not** necessarily mean that the connection is closed. Use
  `open?/1` to verify that the connection is open.

  Requests can be pipelined so the full response does not have to received
  before the next request can be sent. It is up to users to verify that the
  server supports pipelining and that the request is safe to pipeline.

  ## Examples

      XHTTP1.request(conn, "GET", "/", _headers = [])
      XHTTP1.request(conn, "POST", "/path", [{"Content-Type", "application/json"}], "{}")

  """
  @impl true
  @spec request(
          t(),
          method :: String.t(),
          path :: String.t(),
          headers(),
          body :: iodata() | nil | :stream
        ) ::
          {:ok, t(), request_ref()}
          | {:error, t(), term()}
  def request(conn, method, path, headers, body \\ nil)

  def request(%XHTTP1{request: %{state: :stream_request}}, _method, _path, _headers, _body) do
    {:error, :request_body_is_streaming}
  end

  def request(%XHTTP1{} = conn, method, path, headers, body) do
    %XHTTP1{host: host, transport: transport, socket: socket} = conn
    iodata = Request.encode(method, path, host, headers, body || "")

    case transport.send(socket, iodata) do
      :ok ->
        request_ref = make_ref()
        state = if body == :stream, do: :stream_request, else: :status
        request = new_request(request_ref, state, method)

        if conn.request == nil do
          conn = %XHTTP1{conn | request: request}
          {:ok, conn, request_ref}
        else
          requests = :queue.in(request, conn.requests)
          conn = %XHTTP1{conn | requests: requests}
          {:ok, conn, request_ref}
        end

      {:error, :closed} ->
        {:error, %{conn | state: :closed}, :closed}

      {:error, reason} ->
        {:error, conn, reason}
    end
  catch
    :throw, {:xhttp, reason} ->
      {:error, conn, reason}
  end

  @doc """
  Streams a chunk of the request body on the connection or signals the end of the body.

  If a request is opened (through `request/5`) with the body as `:stream`, then the
  body can be streamed through this function. The function takes a `conn`, a
  `request_ref` returned by `request/5` to identify the request to stream the body for,
  and a chunk of body to stream. The value of chunk can be:

    * iodata - a chunk of iodata is transmitted to the server as part of the body
      of the request.

    * `:eof` - signals the end of the streaming of the request body for the given
      request. Usually the server won't send any reply until this is sent.

  This function always returns an updated connection to be stored over the old connection.

  ## Examples

  Let's see an example of streaming an empty JSON object (`{}`) by streaming one curly
  brace at a time.

      headers = [{"Content-Type", "application/json"}, {"Content-Length", "2"}]
      {:ok, request_ref, conn} = XHTTP1.request(conn, "POST", "/", headers, :stream)
      {:ok, conn} = XHTTP1.stream_request_body(conn, request_ref, "{")
      {:ok, conn} = XHTTP1.stream_request_body(conn, request_ref, "}")
      {:ok, conn} = XHTTP1.stream_request_body(conn, request_ref, :eof)

  """
  @impl true
  @spec stream_request_body(t(), request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(%XHTTP1{request: %{state: :stream_request, ref: ref}} = conn, ref, :eof) do
    {:ok, put_in(conn.request.state, :status)}
  end

  def stream_request_body(%XHTTP1{request: %{state: :stream_request, ref: ref}} = conn, ref, body) do
    case conn.transport.send(conn.socket, body) do
      :ok -> {:ok, conn}
      {:error, :closed} -> {:error, %{conn | state: :closed}, :closed}
      {:error, reason} -> {:error, conn, reason}
    end
  end

  @doc """
  Streams the next batch of responses from the given message.

  This function processes a "message" which can be any term, but should be
  a message received by the process that owns the connection. **Processing**
  a message means that this function will parse it and check if it's a message
  that is directed to this connection, that is, a TCP/SSL message received on the
  connection's socket. If it is, then this function will parse the message,
  turn it into a list of responses, and possibly take action given the responses.
  As an example of an action that this function could perform, if the server sends
  a ping request this function will transparently take care of pinging the server back.

  If there's no error, this function returns `{:ok, conn, responses}` where `conn` is
  the updated connection and `responses` is a list of responses. See the "Responses"
  section below. If there's an error, `{:error, conn, reason, responses}` is returned,
  where `conn` is the updated connection, `reason` is the error reason, and `responses`
  is a list of responses that were correctly parsed before the error.

  If the given `message` is not from the connection's socket,
  this function returns `:unknown`.

  ## Responses

  Each possible response returned by this function is a tuple with two or more elements.
  The first element is always an atom that identifies the kind of response. The second
  element is a unique reference `t:request_ref/0` that identifies the request that the response
  belongs to. This is the term returned by `request/5`. After these two elements, there can be
  response-specific terms as well, documented below.

  These are the possible responses that can be returned.

    * `{:status, request_ref, status_code}` - returned when the server replied
      with a response status code. The status code is a non-negative integer.

    * `{:headers, request_ref, headers}` - returned when the server replied
      with a list of headers. Headers are in the form `{header_name, header_value}`
      with `header_name` and `header_value` being strings.

    * `{:data, request_ref, binary}` - returned when the server replied with
      a chunk of response body (as a binary). The request shouldn't be considered done
      when a piece of body is received because multiple chunks could be received. The
      request is done when the `:done` response is returned.

    * `{:done, request_ref}` - returned when the server signaled the request
      as done. When this is received, the response body and headers can be considered
      complete and it can be assumed that no more responses will be received for this
      request. This means that for example, you can stop holding on to the request ref
      for this request.

    * `{:error, request_ref, reason}` - returned when there is an error that
      only affects the request and not the whole connection. For example, if the
      server sends bad data on a given request, that request will be closed an an error
      for that request will be returned among the responses, but the connection will
      remain alive and well.

  ## Examples

  Let's assume we have a function called `receive_next_and_stream/1` that takes
  a connection and then receives the next message, calls `stream/2` with that message
  as an argument, and then returns the result of `stream/2`:

      defp receive_next_and_stream(conn) do
        receive do
          message -> XHTTP1.stream(conn, message)
        end
      end

  Now, we can see an example of a workflow involving `stream/2`.

      {:ok, request_ref, conn} = XHTTP1.request(conn, "GET", "/", _headers = [])

      {:ok, conn, responses} = receive_next_and_stream(conn)
      responses
      #=> [{:status, ^request_ref, 200}]

      {:ok, conn, responses} = receive_next_and_stream(conn)
      responses
      #=> [{:headers, ^request_ref, [{"Content-Type", "application/json"}]},
      #=>  {:data, ^request_ref, "{"}]

      {:ok, conn, responses} = receive_next_and_stream(conn)
      responses
      #=> [{:data, ^request_ref, "}"}, {:done, ^request_ref}]

  """
  @impl true
  @spec stream(t(), socket_message()) ::
          {:ok, t(), [response()]}
          | {:error, t(), term(), [response()]}
          | :unknown
  def stream(conn, message)

  def stream(%XHTTP1{request: %{state: :stream_request}} = conn, _message) do
    # TODO: Close connection
    {:error, conn, :request_body_not_streamed, []}
  end

  def stream(%XHTTP1{transport: transport, socket: socket} = conn, {tag, socket, data})
      when tag in [:tcp, :ssl] do
    result = handle_data(conn, data)
    _ = transport.setopts(socket, active: :once)
    result
  end

  def stream(%XHTTP1{socket: socket} = conn, {tag, socket})
      when tag in [:tcp_closed, :ssl_closed] do
    handle_close(conn)
  end

  def stream(%XHTTP1{socket: socket} = conn, {tag, socket, reason})
      when tag in [:tcp_error, :ssl_error] do
    handle_error(conn, reason)
  end

  def stream(%XHTTP1{}, _message) do
    :unknown
  end

  defp handle_data(%XHTTP1{request: nil} = conn, data) do
    # TODO: Figure out if we should keep buffering even though there are no
    # requests in flight
    {:ok, put_in(conn.buffer, conn.buffer <> data), []}
  end

  defp handle_data(%XHTTP1{request: request} = conn, data) do
    data = conn.buffer <> data

    case decode(request.state, conn, data, []) do
      {:ok, conn, responses} ->
        {:ok, conn, Enum.reverse(responses)}

      {:error, conn, reason} ->
        conn = put_in(conn.state, :closed)
        # TODO: Include responses that were successfully decoded before the error
        {:error, conn, reason, []}
    end
  end

  defp handle_close(%XHTTP1{request: request} = conn) do
    conn = put_in(conn.state, :closed)
    conn = request_done(conn)

    if request && request.body == :until_closed do
      conn = put_in(conn.state, :closed)
      {:ok, conn, [{:done, request.ref}]}
    else
      {:error, conn, :closed, []}
    end
  end

  defp handle_error(conn, reason) do
    conn = put_in(conn.state, :closed)
    {:error, conn, reason, []}
  end

  @doc """
  Assigns a new private key and value in the connection.

  This storage is meant to be used to associate metadata with the connection and
  it can be useful when handling multiple connections.

  The given `key` must be an atom, while the given `value` can be an arbitrary
  term. The return value of this function is an updated connection.

  See also `get_private/3` and `delete_private/2`.

  ## Examples

  Let's see an example of putting a value and then getting it:

      conn = XHTTP1.put_private(conn, :client_name, "XHTTP")
      XHTTP1.get_private(conn, :client_name)
      #=> "XHTTP"

  """
  @impl true
  @spec put_private(t(), atom(), term()) :: t()
  def put_private(%XHTTP1{private: private} = conn, key, value) when is_atom(key) do
    %{conn | private: Map.put(private, key, value)}
  end

  @doc """
  Gets a private value from the connection.

  Retrieves a private value previously set with `put_private/3` from the connection.
  `key` is the key under which the value to retrieve is stored. `default` is a default
  value returned in case there's no value under the given key.

  See also `put_private/3` and `delete_private/2`.

  ## Examples

      conn = XHTTP1.put_private(conn, :client_name, "XHTTP")

      XHTTP1.get_private(conn, :client_name)
      #=> "XHTTP"

      XHTTP1.get_private(conn, :non_existent)
      #=> nil

  """
  @impl true
  @spec get_private(t(), atom(), term()) :: term()
  def get_private(%XHTTP1{private: private} = _conn, key, default \\ nil) when is_atom(key) do
    Map.get(private, key, default)
  end

  @doc """
  Deletes a value in the private store.

  Deletes the private value stored under `key` in the connection. Returns the
  updated connection.

  See also `put_private/3` and `get_private/3`.

  ## Examples

      conn = XHTTP1.put_private(conn, :client_name, "XHTTP")

      XHTTP1.get_private(conn, :client_name)
      #=> "XHTTP"

      conn = XHTTP1.delete_private(conn, :client_name)
      XHTTP1.get_private(conn, :client_name)
      #=> nil

  """
  @impl true
  @spec delete_private(t(), atom()) :: t()
  def delete_private(%XHTTP1{private: private} = conn, key) when is_atom(key) do
    %{conn | private: Map.delete(private, key)}
  end

  @doc """
  Gets the underlying TCP/SSL socket from the connection.

  Right now there is no built-in way to tell if the socket being retrieved
  is a `:gen_tcp` or an `:ssl` socket. You can store the transport (`:http`
  or `:https`) you're using in the private store when starting the connection.
  See `put_private/3` and `get_private/3`.

  ## Examples

      socket = XHTTP1.get_socket(conn)

  """
  @impl true
  @spec get_socket(t()) :: XHTTPCore.Transport.socket()
  def get_socket(%XHTTP1{socket: socket} = _conn) do
    socket
  end

  ## Helpers

  defp decode(:status, %{request: request} = conn, data, responses) do
    case Response.decode_status_line(data) do
      {:ok, {version, status, _reason}, rest} ->
        request = %{request | version: version, status: status, state: :headers}
        conn = %{conn | request: request}
        responses = [{:status, request.ref, status} | responses]
        decode(:headers, conn, rest, responses)

      :more ->
        conn = put_in(conn.buffer, data)
        {:ok, conn, responses}

      :error ->
        {:error, conn, :invalid_status_line}
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

        case store_header(request, name, value) do
          {:ok, request} -> decode_headers(conn, request, rest, responses, headers)
          {:error, reason} -> {:error, conn, reason}
        end

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
        {:error, conn, :invalid_header}
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
        {:error, conn, :invalid_chunk_size}
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
        {:error, conn, :missing_crlf_after_chunk}
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
        {:error, conn, :invalid_trailer_header}
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
  defp add_body(new_data, request_ref, [{:data, request_ref, data} | responses]),
    do: [{:data, request_ref, data <> new_data} | responses]

  defp add_body(new_data, request_ref, responses),
    do: [{:data, request_ref, new_data} | responses]

  defp store_header(%{content_length: nil} = request, "content-length", value) do
    {:ok, %{request | content_length: Parse.content_length_header(value)}}
  end

  defp store_header(%{connection: connection} = request, "connection", value) do
    {:ok, %{request | connection: connection ++ Parse.connection_header(value)}}
  end

  defp store_header(%{transfer_encoding: transfer_encoding} = request, "transfer-encoding", value) do
    {:ok,
     %{request | transfer_encoding: transfer_encoding ++ Parse.transfer_encoding_header(value)}}
  end

  defp store_header(_request, "content-length", _value) do
    {:error, :invalid_response}
  end

  defp store_header(request, _name, _value) do
    {:ok, request}
  end

  defp request_done(%{request: request} = conn) do
    # TODO: Figure out what to do if connection is closed or there is no next
    # request and we still have data on the socket. RFC7230 3.4
    conn = pop_request(conn)

    cond do
      !request -> conn
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
      Logger.debug(["XHTTP1ection closed with data left in the buffer: ", inspect(conn.buffer)])
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
