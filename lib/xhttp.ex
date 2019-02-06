defmodule XHTTP do
  @moduledoc """
  Processless HTTP connection data structure and functions.

  Single interface for `XHTTP1` and `XHTTP2` with version negotiation support
  and support for proxies.

  ## Usage

  To establish a connection with a given server, use `connect/4`. This will
  return an opaque data structure, `%XHTTP{}`, that represents the connection
  to the server. To send a request, you can use `request/5`. Sending a request
  does not take care of the response to that request, instead we use `XHTTP.stream/2` to process the response, which we will look at in just a bit. The connection is a
  wrapper around a TCP (`:gen_tcp` module) or SSL (`:ssl` module) socket that is
  set in **active mode**. This means that TCP/SSL messages will be delivered to
  the process that started the connection and created the `%XHTTP{}` data structure.

  The process that owns the connection is responsible for receiving the messages
  (for example, a GenServer is responsible for defining `handle_info/2`). However,
  `XHTTP` makes it easy to identify TCP/SSL messages that are coming from the
  connection with the server with the `stream/2` function. This function takes the
  connection and a term and returns `:unknown` if the term is not a TCP/SSL message
  belonging to the connection. If the term *is* a message for the connection, then
  a response and a new connection are returned. It's important to store the new
  returned connection data structure over the old one since the connection is an
  immutable data structure.

  Let's see an example of a common workflow of connecting to a server, sending a
  request, and processing the response. We start by using `connect/3` to connect
  to a server.

      {:ok, conn} = XHTTP.connect(:http, "httpbin.org", 80)

  `conn` is a `%XHTTP{}` data structure that represents the connection. This
  data structure is a wrapper around a TCP (`:gen_tcp` module) or SSL (`:ssl`
  module) socket that is set in **active mode**. This means that TCP/SSL messages
  will be delivered to the process that started the connection.

  To send a request, we use `request/5`.

      {:ok, conn, request_ref} = XHTTP.request(conn, "GET", "/", [], nil)

  As you can see, sending a request returns a new updated `conn` struct and a
  `request_ref`. The updated connection struct is returned because the connection
  is an immutable piece of data, so every action we do on it must return a new,
  possibly updated, connection that we're responsible for storing over the old
  one. `request_ref` is a unique reference that can be used to identify which
  request a given response belongs to.

  Now that we sent our request, we're responsible for receiving the messages that
  the TCP/SSL socket will send to our process. For example, in a GenServer
  we would do that with a `handle_info/2` callback. In our case, we're going to
  use a simple `receive`. `XHTTP` provides a way to tell if a message comes
  from the socket wrapped by our connection or not: the `stream/2` function. If
  the message we pass to it is not destined for our connection, this function returns
  `:unknown`. Otherwise, it returns an updated connection and one or more responses.

      receive do
        message ->
          case XHTTP.stream(conn, message) do
            :unknown -> handle_normal_message(message)
            {:ok, conn, responses} -> handle_responses(conn, responses)
          end
      end

  `responses` is a list of possible responses. The most common responses are:

    * `{:status, request_ref, status_code}` for the status code
    * `{:headers, request_ref, headers}` for the response headers
    * `{:data, request_ref, binary}` for pieces of the response body
    * `{:done, request_ref}` for the end of the response

  As you can see, all responses have the unique request reference as the second
  element of the tuple, so that we know which request the response belongs to.

  ## Architecture

  A processless architecture like the one here requires a few modifications to how
  we use this HTTP client. Usually, you will want to create this data structure
  in a process that acts as *connection manager*. Sometimes, you might want to
  have a single process responsible for multiple connections, either to just one
  host or different hosts. For more discussion on architectures based off of this
  HTTP client, see the [TODO architecture] page in the docs.
  """

  import XHTTPCore.Util

  alias XHTTP.{TunnelProxy, UnsafeProxy}
  alias XHTTPCore.Transport

  @behaviour XHTTPCore.Conn

  @opaque t() :: XHTTP1.t() | XHTTP2.t()

  @type scheme() :: :http | :https | module()
  @type headers() :: XHTTPCore.Conn.headers()
  @type request_ref() :: XHTTPCore.Conn.request_ref()
  @type socket_message() :: XHTTPCore.Conn.socket_message()
  @type response() :: XHTTPCore.Conn.response()

  @doc """
  Creates a new connection to a given server.

  Creates a new `%XHTTP{}` struct and establishes the connection to the given server,
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

    * `:protocols` - (list of atoms) a list of protocols to try when connecting to the
      server. The possible values in the list are `:http1` for HTTP/1.1 and `:http2` for
      HTTP/2. If only one protocol is present in the list, then the connection will
      be forced to use that protocol. If both `:http1` and `:http2` are present in the
      list, then XHTTP will negotiate the protocol. See the section "Protocol negotiation"
      below for more information. Defaults to `[:http1, :http2]`.

  The following options are HTTP/1.1-specific and will force the connection
  to be an HTTP/1.1 connection.

    * `:proxy` - a `{scheme, hostname, port, opts}` tuple that identifies a proxy to
      connect to. See the "Proxying" section below for more information.

  The following options are HTTP/2-specific and will only be used on HTTP/2 connections.

    * `:client_settings` - (keyword) a list of client HTTP/2 settings to send to the
      server. See `put_settings/2` for more information.

  ## Protocol negotiation

  If both `:http1` and `:http2` are present in the list passed in the `:protocol` options,
  the protocol negotiation happens in the following way:

    * If the scheme used to connect to the server is `:http`, then HTTP/1.1 is used.

    * If the scheme is `:https`, then ALPN negotiation is used to determine the right
      protocol. This means that the server will decide whether to use HTTP/1.1 or
      HTTP/2. If the server doesn't support protocol negotiation, we will fall back to
      HTTP/1.1. If the server negotiates a protocol that we don't know how to handle,
      `{:error, {:bad_alpn_protocol, protocol}}` is returned.

  ## Proxying

  You can set up proxying through the `:proxy` option, which is a tuple
  `{scheme, hostname, port, opts}` that identifies the proxy to connect to.
  Once a proxied connection is returned, the proxy is transparent to you and you
  can use the connection like a normal HTTP/1.1 connection.

  If the `scheme` is `:http`, we will use an unsafe proxy to connect to
  the given host.

  If the scheme is `:https`, we will use a tunnel proxy to connect to the
  given host.

  ## Examples

      {:ok, conn} = XHTTP.connect(:http, "httpbin.org", 80)

  Using a proxy:

      proxy = {:https, "myproxy.example.com", 443, []}
      {:ok, conn} = XHTTP.connect(:https, "httpbin.org", 443, proxy: proxy)

  Forcing the connection to be an HTTP/2 connection:

      {:ok, conn} = XHTTP.connect(:https, "http2.golang.org", 443, protocols: [:http2])

  """
  @spec connect(scheme(), String.t(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def connect(scheme, hostname, port, opts \\ []) do
    # TODO: Proxy auth

    case Keyword.fetch(opts, :proxy) do
      {:ok, {proxy_scheme, proxy_hostname, proxy_port, proxy_opts}} ->
        case scheme_to_transport(scheme) do
          Transport.TCP ->
            proxy = {proxy_scheme, proxy_hostname, proxy_port}
            host = {scheme, hostname, port}
            opts = Keyword.merge(opts, proxy_opts)
            UnsafeProxy.connect(proxy, host, opts)

          Transport.SSL ->
            proxy = {proxy_scheme, proxy_hostname, proxy_port, proxy_opts}
            host = {scheme, hostname, port, opts}
            TunnelProxy.connect(proxy, host)
        end

      :error ->
        XHTTP.Negotiate.connect(scheme, hostname, port, opts)
    end
  end

  @doc """
  TODO: write docs
  """
  @spec upgrade(
          module(),
          XHTTPCore.Transport.socket(),
          scheme(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def upgrade(old_transport, transport_state, scheme, hostname, port, opts),
    do: XHTTP.Negotiate.upgrade(old_transport, transport_state, scheme, hostname, port, opts)

  # TODO: deal with this by either having it in the behaviour or not having it at all.
  @doc false
  def get_transport(conn), do: conn_module(conn).get_transport(conn)

  @doc false
  @impl true
  @spec initiate(
          module(),
          XHTTPCore.Transport.socket(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def initiate(transport, transport_state, hostname, port, opts),
    do: XHTTP.Negotiate.initiate(transport, transport_state, hostname, port, opts)

  @doc """
  Checks whether the connection is open.

  This function returns `true` if the connection is open, `false` otherwise. It should
  be used to check that a connection is open before sending requests or performing
  operations that involve talking to the server.

  If a connection is not open, it has become useless and you should get rid of it.
  If you still need a connection to the server, start a new connection with `connect/4`.

  ## Examples

      {:ok, conn} = XHTTP.connect(:http, "httpbin.org", 80)
      XHTTP.open?(conn)
      #=> true

  """
  @impl true
  @spec open?(t()) :: boolean()
  def open?(conn), do: conn_module(conn).open?(conn)

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
      In HTTP/1.1, you can't open a request if the body of another request is
      streaming.

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

  In HTTP/1.1, you can't open a request if the body of another request is streaming.
  See `XHTTP1.request/5` for more information.

  For a quick discussion on HTTP/2 streams and requests, see the `XHTTP2` module and
  `XHTTP2.request/5`.

  ## Examples

      XHTTP.request(conn, "GET", "/", _headers = [])
      XHTTP.request(conn, "POST", "/path", [{"content-type", "application/json"}], "{}")

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
  def request(conn, method, path, headers, body \\ nil),
    do: conn_module(conn).request(conn, method, path, headers, body)

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

      headers = [{"content-type", "application/json"}, {"content-length", "2"}]
      {:ok, request_ref, conn} = XHTTP.request(conn, "POST", "/", headers, :stream)
      {:ok, conn} = XHTTP.stream_request_body(conn, request_ref, "{")
      {:ok, conn} = XHTTP.stream_request_body(conn, request_ref, "}")
      {:ok, conn} = XHTTP.stream_request_body(conn, request_ref, :eof)

  """
  @impl true
  @spec stream_request_body(t(), request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(conn, ref, body),
    do: conn_module(conn).stream_request_body(conn, ref, body)

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

    * `{:pong, request_ref}` - returned when a server replies to a ping
      request sent by the client. This response type is HTTP/2-specific
      and will never be returned by an HTTP/1.1 connection. See `XHTTP2.ping/2`
      for more information.

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
  def stream(conn, message), do: conn_module(conn).stream(conn, message)

  @doc """
  Assigns a new private key and value in the connection.

  This storage is meant to be used to associate metadata with the connection and
  it can be useful when handling multiple connections.

  The given `key` must be an atom, while the given `value` can be an arbitrary
  term. The return value of this function is an updated connection.

  See also `get_private/3` and `delete_private/2`.

  ## Examples

  Let's see an example of putting a value and then getting it:

      conn = XHTTP.put_private(conn, :client_name, "XHTTP")
      XHTTP.get_private(conn, :client_name)
      #=> "XHTTP"

  """
  @impl true
  @spec put_private(t(), atom(), term()) :: t()
  def put_private(conn, key, value), do: conn_module(conn).put_private(conn, key, value)

  @doc """
  Gets a private value from the connection.

  Retrieves a private value previously set with `put_private/3` from the connection.
  `key` is the key under which the value to retrieve is stored. `default` is a default
  value returned in case there's no value under the given key.

  See also `put_private/3` and `delete_private/2`.

  ## Examples

      conn = XHTTP.put_private(conn, :client_name, "XHTTP")

      XHTTP.get_private(conn, :client_name)
      #=> "XHTTP"

      XHTTP.get_private(conn, :non_existent)
      #=> nil

  """
  @impl true
  @spec get_private(t(), atom(), term()) :: term()
  def get_private(conn, key, default \\ nil),
    do: conn_module(conn).get_private(conn, key, default)

  @doc """
  Deletes a value in the private store.

  Deletes the private value stored under `key` in the connection. Returns the
  updated connection.

  See also `put_private/3` and `get_private/3`.

  ## Examples

      conn = XHTTP.put_private(conn, :client_name, "XHTTP")

      XHTTP.get_private(conn, :client_name)
      #=> "XHTTP"

      conn = XHTTP.delete_private(conn, :client_name)
      XHTTP.get_private(conn, :client_name)
      #=> nil

  """
  @impl true
  @spec delete_private(t(), atom()) :: t()
  def delete_private(conn, key), do: conn_module(conn).delete_private(conn, key)

  @doc """
  Gets the underlying TCP/SSL socket from the connection.

  Right now there is no built-in way to tell if the socket being retrieved
  is a `:gen_tcp` or an `:ssl` socket. You can store the transport (`:http`
  or `:https`) you're using in the private store when starting the connection.
  See `put_private/3` and `get_private/3`.

  ## Examples

      socket = XHTTP.get_socket(conn)

  """
  @impl true
  @spec get_socket(t()) :: XHTTPCore.Transport.socket()
  def get_socket(conn), do: conn_module(conn).get_socket(conn)

  ## Helpers

  defp conn_module(%UnsafeProxy{}), do: UnsafeProxy
  defp conn_module(%XHTTP1{}), do: XHTTP1
  defp conn_module(%XHTTP2{}), do: XHTTP2
end
