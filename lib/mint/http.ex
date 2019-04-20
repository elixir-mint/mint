defmodule Mint.HTTP do
  @moduledoc """
  Processless HTTP connection data structure and functions.

  Single interface for `Mint.HTTP1` and `Mint.HTTP2` with support for version
  negotiation and proxies.

  ## Usage

  To establish a connection with a given server, use `connect/4`. This will
  return an opaque data structure that represents the connection
  to the server. To send a request, you can use `request/5`. Sending a request
  does not take care of the response to that request, instead we use `Mint.stream/2`
  to process the response, which we will look at in just a bit. The connection is a
  wrapper around a TCP (`:gen_tcp` module) or SSL (`:ssl` module) socket that is
  set in **active mode**. This means that TCP/SSL messages will be delivered to
  the process that started the connection.

  The process that owns the connection is responsible for receiving the messages
  (for example, a GenServer is responsible for defining `handle_info/2`). However,
  `Mint.HTTP` makes it easy to identify TCP/SSL messages that are coming from the
  connection with the server with the `stream/2` function. This function takes the
  connection and a term and returns `:unknown` if the term is not a TCP/SSL message
  belonging to the connection. If the term *is* a message for the connection, then
  a response and a new connection are returned. It's important to store the new
  returned connection data structure over the old one since the connection is an
  immutable data structure.

  Let's see an example of a common workflow of connecting to a server, sending a
  request, and processing the response. We start by using `connect/3` to connect
  to a server.

      {:ok, conn} = Mint.HTTP.connect(:http, "httpbin.org", 80)

  `conn` is a data structure that represents the connection.

  To send a request, we use `request/5`.

      {:ok, conn, request_ref} = Mint.HTTP.request(conn, "GET", "/", [], nil)

  As you can see, sending a request returns a new updated `conn` struct and a
  `request_ref`. The updated connection struct is returned because the connection
  is an immutable structure keeping the connection state, so every action we do on it must return a new,
  possibly updated, connection that we're responsible for storing over the old
  one. `request_ref` is a unique reference that can be used to identify which
  request a given response belongs to.

  Now that we sent our request, we're responsible for receiving the messages that
  the TCP/SSL socket will send to our process. For example, in a GenServer
  we would do that with a `handle_info/2` callback. In our case, we're going to
  use a simple `receive`. `Mint.HTTP` provides a way to tell if a message comes
  from the socket wrapped by our connection or not: the `stream/2` function. If
  the message we pass to it is not destined for our connection, this function returns
  `:unknown`. Otherwise, it returns an updated connection and one or more responses.

      receive do
        message ->
          case Mint.HTTP.stream(conn, message) do
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
  See `t:Mint.Types.response/0` for the full list of responses returned by `Mint.HTTP.stream/2`.

  ## Architecture

  A processless architecture like the one here requires a few modifications to how
  we use this HTTP client. Usually, you will want to create this data structure
  in a process that acts as *connection manager*. Sometimes, you might want to
  have a single process responsible for multiple connections, either to just one
  host or multiple hosts. For more discussion on architectures based off of this
  HTTP client, see the [*Architecture*](architecture.html) page in the docs.

  ## SSL certificates

  When using SSL, you can pass in your own CA certificate store or use one provided by Mint. Mint
  doesn't ship with the certificate store itself, but it has an optional dependency on
  [CAStore](https://github.com/ericmj/castore), which provides an up-to-date certificate store. If
  you don't want to use your own certificate store, just add `:castore` to your dependencies.
  """

  import Mint.Core.Util

  alias Mint.{Types, TunnelProxy, UnsafeProxy}
  alias Mint.Core.Transport

  @behaviour Mint.Core.Conn

  @opaque t() :: Mint.HTTP1.t() | Mint.HTTP2.t()

  @doc """
  Creates a new connection to a given server.

  Creates a new connection struct and establishes the connection to the given server,
  identified by the given `host` and `port` combination. Both HTTP and HTTPS are supported
  by passing respectively `:http` and `:https` as the `scheme`.

  The connection struct wraps a socket, which is created once the connection
  is established inside this function. If HTTP is used, then the created socket is a TCP
  socket and the `:gen_tcp` module is used to create that socket. If HTTPS is used, then
  the created socket is an SSL socket and the `:ssl` module is used to create that socket.
  The socket is created in active mode, which is why it is important to know the type of
  the socket: messages from the socket (of type `t:socket_message/0` will be delivered
  directly to the process that creates the connection and tagged appropriately by the socket
  module (see the `:gen_tcp` and `:ssl` modules). See `stream/2` for more information on the
  messages and how to process them.

  ## Options

    * `:transport_opts` - (keyword) options to be given to the transport being used.
      These options will be merged with some default options that cannot be overridden.
      For more details, refer to the "Transport options" section below.

    * `:protocols` - (list of atoms) a list of protocols to try when connecting to the
      server. The possible values in the list are `:http1` for HTTP/1 and HTTP/1.1 and
      `:http2` for HTTP/2. If only one protocol is present in the list, then the connection
      will be forced to use that protocol. If both `:http1` and `:http2` are present in the
      list, then Mint will negotiate the protocol. See the section "Protocol negotiation"
      below for more information. Defaults to `[:http1, :http2]`.

  The following options are HTTP/1-specific and will force the connection
  to be an HTTP/1 connection.

    * `:proxy` - a `{scheme, hostname, port, opts}` tuple that identifies a proxy to
      connect to. See the "Proxying" section below for more information.

  The following options are HTTP/2-specific and will only be used on HTTP/2 connections.

    * `:client_settings` - (keyword) a list of client HTTP/2 settings to send to the
      server. See `Mint.HTTP2.put_settings/2` for more information. This is only used
      in HTTP/2 connections.

  ## Protocol negotiation

  If both `:http1` and `:http2` are present in the list passed in the `:protocols` option,
  the protocol negotiation happens in the following way:

    * If the scheme used to connect to the server is `:http`, then HTTP/1 or HTTP/1.1 is used.

    * If the scheme is `:https`, then ALPN negotiation is used to determine the right
      protocol. This means that the server will decide whether to use HTTP/1 or
      HTTP/2. If the server doesn't support protocol negotiation, we will fall back to
      HTTP/1. If the server negotiates a protocol that we don't know how to handle,
      `{:error, {:bad_alpn_protocol, protocol}}` is returned.

  ## Proxying

  You can set up proxying through the `:proxy` option, which is a tuple
  `{scheme, hostname, port, opts}` that identifies the proxy to connect to.
  Once a proxied connection is returned, the proxy is transparent to you and you
  can use the connection like a normal HTTP/1 connection.

  If the `scheme` is `:http`, we will connect to the host in the most compatible
  way, supporting older proxy servers. Data will be sent in clear text.

  If the connection scheme is `:https`, we will connect to the host with a tunnel
  through the proxy. Using `:https` for both the proxy and the connection scheme
  is not supported, it is recommended to use `:https` for the end host connection
  instead of the proxy.

  ## Transport options

  The options specified in `:transport_opts` are passed to the module that
  implements the socket interface: `:gen_tcp` when the scheme is `:http`, and
  `:ssl` when the scheme is `:https`. Please refer to the documentation for those
  modules, as well as for `:inet.setopts/2`, for a detailed description of all
  available options.

  The behaviour of some options is modified by Mint, as described below.

  A special case is the `:timeout` option, which is passed to the transport
  module's `connect` function to limit the amount of time to wait for the
  network connection to be established.

  Common options for `:http` and `:https`:

    * `:active` - managed by Mint. Should not normally be modified by the
      application at any time.

    * `:mode` - set to `:binary`. Cannot be overriden.

    * `:packet` - set to `:raw`. Cannot be overridden.

    * `:timeout` - connect timeout in milliseconds. Defaults to `30_000` (30
      seconds), and may be overridden by the caller. Set to `:infinity` to
      disable the connect timeout.

  Options for `:https` only:

    * `:alpn_advertised_protocols` - managed by Mint. Cannot be overridden.

    * `:cacertfile` - if `:verify` is set to `:verify_peer` (the default) and
      no CA trust store is specified using the `:cacertfile` or `:cacerts`
      option, Mint will attempt to use the trust store from the
      [CAStore](https://github.com/ericmj/castore) package or raise an
      exception if this package is not available.

    * `:ciphers` - defaults to the list returned by `:ssl.cipher_suites/0`
      filtered according to the blocklist in
      [RFC7540 appendix A](https://tools.ietf.org/html/rfc7540#appendix-A);
      May be overridden by the caller. See the "Supporting older cipher suites"
      section below for some examples.

    * `:depth` - defaults to `4`. May be overridden by the caller.

    * `:partial_chain_fun` - unless a custom `:partial_chain_fun` is specified,
      Mint will enable its own partial chain handler, which accepts server
      certificate chains containing a certificate that was issued by a
      CA certificate in the CA trust store, even if that certificate is not
      last in the chain. This improves interoperability with some servers
      (for example, with a cross-signed intermediate CA or some misconfigured servers),
      but is a less strict interpretation of the TLS specification than the
      Erlang/OTP default behaviour.

    * `:reuse_sessions` - defaults to `true`. May be overridden by the caller.

    * `:secure_renegotiate` - defaults to `true`. May be overridden by the
      caller.

    * `:server_name_indication` - defaults to specified destination hostname.
      May be overridden by the caller.

    * `:verify` - defaults to `:verify_peer`. May be overridden by the caller.

    * `:verify_fun` - unless a custom `:verify_fun` is specified, or `:verify`
      is set to `:verify_none`, Mint will enable hostname verification with
      support for wildcards in the server's 'SubjectAltName' extension, similar
      to the behaviour implemented in
      `:public_key.pkix_verify_hostname_match_fun(:https)` in recent Erlang/OTP
      releases. This improves compatibility with recently issued wildcard
      certificates also on older Erlang/OTP releases.

    * `:versions` - defaults to `[:"tlsv1.2"]` (TLS v1.2 only). May be
      overridden by the caller.

  ### Supporting older cipher suites

  By default only a small list of modern cipher suites is enabled, in compliance
  with the HTTP/2 specification. Some servers, in particular HTTP/1 servers, may
  not support any of these cipher suites, resulting in TLS handshake failures or
  closed connections.

  To select the default cipher suites of Erlang/OTP (including for example
  AES-CBC), use the following `:transport_opts`:

      # Erlang/OTP 20.3 or later:
      transport_opts: [ciphers: :ssl.cipher_suites(:default, :"tlsv1.2")]
      # Older versions:
      transport_opts: [ciphers: :ssl.cipher_suites()]

  Recent Erlang/OTP releases do not enable RSA key exchange by default, due to
  known weaknesses. If necessary, you can build a cipher list with RSA exchange
  and use it in `:transport_opts`:

      ciphers =
        :ssl.cipher_suites(:all, :"tlsv1.2")
        |> :ssl.filter_cipher_suites(
          key_exchange: &(&1 == :rsa),
          cipher: &(&1 in [:aes_256_gcm, :aes_128_gcm, :aes_256_cbc, :aes_128_cbc])
        )
        |> :ssl.append_cipher_suites(:ssl.cipher_suites(:default, :"tlsv1.2"))

  ## Examples

      {:ok, conn} = Mint.HTTP.connect(:http, "httpbin.org", 80)

  Using a proxy:

      proxy = {:http, "myproxy.example.com", 80, []}
      {:ok, conn} = Mint.HTTP.connect(:https, "httpbin.org", 443, proxy: proxy)

  Forcing the connection to be an HTTP/2 connection:

      {:ok, conn} = Mint.HTTP.connect(:https, "http2.golang.org", 443, protocols: [:http2])

  Enable all default cipher suites of Erlang/OTP (release 20.3 or later):

      opts = [transport_opts: [ciphers: :ssl.cipher_suites(:default, :"tlsv1.2")]]
      {:ok, conn} = Mint.HTTP.connect(:https, "httpbin.org", 443, opts)

  """
  @spec connect(Types.scheme(), String.t(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, Types.error()}
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
        Mint.Negotiate.connect(scheme, hostname, port, opts)
    end
  end

  @doc false
  @spec upgrade(
          module(),
          Mint.Types.socket(),
          Types.scheme(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, Types.error()}
  def upgrade(old_transport, transport_state, scheme, hostname, port, opts),
    do: Mint.Negotiate.upgrade(old_transport, transport_state, scheme, hostname, port, opts)

  @doc false
  @impl true
  @spec initiate(
          module(),
          Mint.Types.socket(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, Types.error()}
  def initiate(transport, transport_state, hostname, port, opts),
    do: Mint.Negotiate.initiate(transport, transport_state, hostname, port, opts)

  @doc """
  Closes the given connection.

  This function closes the socket wrapped by the given connection. Once the socket
  is closed, the connection goes into the "closed" state and `open?/1` returns `false`.
  You can throw away a closed connection.

  Closing a connection does not guarantee that data that is in flight gets delivered
  to the server.

  Always returns `{:ok, conn}` where `conn` is the updated connection.

  ## Examples

      {:ok, conn} = Mint.HTTP.close(conn)

  """
  @impl true
  @spec close(t()) :: {:ok, t()}
  def close(conn), do: conn_module(conn).close(conn)

  @doc """
  Checks whether the connection is open.

  This function returns `true` if the connection is open, `false` otherwise. It should
  be used to check that a connection is open before sending requests or performing
  operations that involve talking to the server.

  The `type` argument can be used to tell whether the connection is closed only for reading,
  only for writing, or for both. In HTTP/1, a closed connection is always closed for
  both reading and writing. In HTTP/2, the connection can be closed only for writing but
  not for reading, meaning that you cannot send any more data to the server but you can
  still receive data from the server. See the "Closed connection" section in the module
  documentation of `Mint.HTTP2`.

  If a connection is not open for reading and writing, it has become useless and you should
  get rid of it. If you still need a connection to the server, start a new connection
  with `connect/4`.

  ## Examples

      {:ok, conn} = Mint.HTTP.connect(:http, "httpbin.org", 80)
      Mint.HTTP.open?(conn)
      #=> true

  """
  @impl true
  @spec open?(t(), :read | :write | :read_write) :: boolean()
  def open?(conn, type \\ :read_write), do: conn_module(conn).open?(conn, type)

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
      In HTTP/1, you can't open a request if the body of another request is
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

  In HTTP/1, you can't open a request if the body of another request is streaming.
  See `Mint.HTTP1.request/5` for more information.

  For a quick discussion on HTTP/2 streams and requests, see the `Mint.HTTP2` module and
  `Mint.HTTP2.request/5`.

  ## Examples

      Mint.HTTP.request(conn, "GET", "/", _headers = [])
      Mint.HTTP.request(conn, "POST", "/path", [{"content-type", "application/json"}], "{}")

  """
  @impl true
  @spec request(
          t(),
          method :: String.t(),
          path :: String.t(),
          Types.headers(),
          body :: iodata() | nil | :stream
        ) ::
          {:ok, t(), Types.request_ref()}
          | {:error, t(), Types.error()}
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

  When streaming the request body, Mint cannot send a precalculated `content-length`
  request header. It is up to you set the correct headers depending on how you stream
  the body, either by setting the `content-length` header yourself or by using the
  appropriate transfer encoding if using HTTP/1.

  ## Examples

  Let's see an example of streaming an empty JSON object (`{}`) by streaming one curly
  brace at a time.

      headers = [{"content-type", "application/json"}, {"content-length", "2"}]
      {:ok, conn, request_ref} = Mint.HTTP.request(conn, "POST", "/", headers, :stream)
      {:ok, conn} = Mint.HTTP.stream_request_body(conn, request_ref, "{")
      {:ok, conn} = Mint.HTTP.stream_request_body(conn, request_ref, "}")
      {:ok, conn} = Mint.HTTP.stream_request_body(conn, request_ref, :eof)

  """
  @impl true
  @spec stream_request_body(t(), Types.request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), Types.error()}
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
      with `header_name` and `header_value` being strings. Only one `:headers`
      response is returned per request.

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
      and will never be returned by an HTTP/1 connection. See `Mint.HTTP2.ping/2`
      for more information.

    * `{:push_promise, request_ref, promised_request_ref, headers}` - returned when
      the server sends a server push to the client. This response type is HTTP/2 specific
      and will never be returned by an HTTP/1 connection. See `Mint.HTTP2` for more
      information on server pushes.

  ## Examples

  Let's assume we have a function called `receive_next_and_stream/1` that takes
  a connection and then receives the next message, calls `stream/2` with that message
  as an argument, and then returns the result of `stream/2`:

      defp receive_next_and_stream(conn) do
        receive do
          message -> Mint.HTTP.stream(conn, message)
        end
      end

  Now, we can see an example of a workflow involving `stream/2`.

      {:ok, conn, request_ref} = Mint.HTTP.request(conn, "GET", "/", _headers = [])

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
  @spec stream(t(), term()) ::
          {:ok, t(), [Types.response()]}
          | {:error, t(), Types.error(), [Types.response()]}
          | :unknown
  def stream(conn, message), do: conn_module(conn).stream(conn, message)

  @doc """
  Returns the number of open requests.

  Open requests are requests that have not yet received a `:done` response.
  This function returns the number of open requests for both HTTP/1 and HTTP/2,
  but for HTTP/2 only client-initiated requests are considered as open requests.
  See `Mint.HTTP2.open_request_count/1` for more information.

  ## Examples

      {:ok, conn, _ref} = Mint.HTTP.request(conn, "GET", "/", [])
      Mint.HTTP.open_request_count(conn)
      #=> 1

  """
  @impl true
  @spec open_request_count(t()) :: non_neg_integer()
  def open_request_count(conn), do: conn_module(conn).open_request_count(conn)

  @doc """
  Assigns a new private key and value in the connection.

  This storage is meant to be used to associate metadata with the connection and
  it can be useful when handling multiple connections.

  The given `key` must be an atom, while the given `value` can be an arbitrary
  term. The return value of this function is an updated connection.

  See also `get_private/3` and `delete_private/2`.

  ## Examples

  Let's see an example of putting a value and then getting it:

      conn = Mint.HTTP.put_private(conn, :client_name, "Mint")
      Mint.HTTP.get_private(conn, :client_name)
      #=> "Mint"

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

      conn = Mint.HTTP.put_private(conn, :client_name, "Mint")

      Mint.HTTP.get_private(conn, :client_name)
      #=> "Mint"

      Mint.HTTP.get_private(conn, :non_existent)
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

      conn = Mint.HTTP.put_private(conn, :client_name, "Mint")

      Mint.HTTP.get_private(conn, :client_name)
      #=> "Mint"

      conn = Mint.HTTP.delete_private(conn, :client_name)
      Mint.HTTP.get_private(conn, :client_name)
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

      socket = Mint.HTTP.get_socket(conn)

  """
  @impl true
  @spec get_socket(t()) :: Mint.Types.socket()
  def get_socket(conn), do: conn_module(conn).get_socket(conn)

  ## Helpers

  defp conn_module(%UnsafeProxy{}), do: UnsafeProxy
  defp conn_module(%Mint.HTTP1{}), do: Mint.HTTP1
  defp conn_module(%Mint.HTTP2{}), do: Mint.HTTP2
end
