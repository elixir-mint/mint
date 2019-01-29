defmodule XHTTP2 do
  @moduledoc """
  Processless HTTP client with support for HTTP/2.

  This module provides a data structure that represents an HTTP/2 connection to
  a given server. The connection is represented as an opaque struct `%XHTTP2{}`.
  The connection is a data structure and is not backed by a process, and all the
  connection handling happens in the process that creates the struct.

  This module and data structure work exactly like the ones described in the `XHTTP`
  module, with the exception that `XHTTP2` specifically deals with HTTP/2 while
  `XHTTP` deals seamlessly with HTTP/1.1 and HTTP/2. For more information on
  how to use the data structure and client architecture, see `XHTTP`.

  ## HTTP/2 streams and requests

  HTTP/2 introduces the concept of **streams**. A stream is an isolated conversation
  between the client and the server. Each stream is unique and identified by a unique
  **stream ID**, which means that there's no order when data comes on different streams
  since they can be identified uniquely. A stream closely corresponds to a request, so
  in this documentation and client we will mostly refer to streams as "requests".
  We mentioned data on streams can come in arbitrary order, and streams are requests,
  so the practical effect of this is that performing request A and then request B
  does not mean that the response to request A will come before the response to request B.
  This is why we identify each request with a unique reference returned by `request/5`.
  See `request/5` for more information.
  """

  use Bitwise, skip_operators: true

  import XHTTPCore.Util
  import XHTTP2.Frame, except: [encode: 1, decode_next: 1]

  alias XHTTP2.{
    Frame,
    HPACK
  }

  require Logger

  @behaviour XHTTPCore.Conn

  ## Constants

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @transport_opts [alpn_advertised_protocols: ["h2"]]

  @default_window_size 65_535
  @max_window_size 2_147_483_647

  @default_max_frame_size 16_384
  @valid_max_frame_size_range @default_max_frame_size..16_777_215
  ## XHTTP2ection

  defstruct [
    # Transport things.
    :transport,
    :socket,

    # Host things.
    :hostname,
    :port,
    :scheme,

    # XHTTP2ection state (open, closed, and so on).
    :state,

    # Fields of the connection.
    buffer: "",
    window_size: @default_window_size,
    encode_table: HPACK.new(4096),
    decode_table: HPACK.new(4096),

    # Queue for sent PING frames.
    ping_queue: :queue.new(),

    # Queue for sent SETTINGS frames.
    client_settings_queue: :queue.new(),

    # Stream-set-related things.
    next_stream_id: 3,
    streams: %{},
    open_stream_count: 0,
    ref_to_stream_id: %{},

    # SETTINGS-related things for server.
    enable_push: true,
    server_max_concurrent_streams: 100,
    initial_window_size: @default_window_size,
    max_frame_size: @default_max_frame_size,

    # SETTINGS-related things for client.
    client_max_frame_size: @default_max_frame_size,
    client_max_concurrent_streams: 100,

    # Headers being processed (when headers are split into multiple frames with CONTINUATIONS, all
    # the continuation frames must come one right after the other).
    headers_being_processed: nil,

    # Private store
    private: %{}
  ]

  ## Types

  @type scheme :: :http | :https | module()
  @type request_ref() :: XHTTPCore.Conn.request_ref()
  @type socket_message() :: XHTTPCore.Conn.socket_message()
  @type response() :: XHTTPCore.Conn.response()
  @type status() :: XHTTPCore.Conn.response()
  @type headers() :: XHTTPCore.Conn.headers()
  @type settings() :: keyword()
  @type stream_id() :: pos_integer()

  @opaque t() :: %XHTTP2{
            transport: module(),
            socket: XHTTPCore.Transport.socket(),
            state: :open | :closed | :went_away,
            buffer: binary(),
            window_size: pos_integer(),
            encode_table: HPACK.Table.t(),
            decode_table: HPACK.Table.t(),
            ping_queue: :queue.queue(),
            client_settings_queue: :queue.queue(),
            next_stream_id: stream_id(),
            streams: %{optional(stream_id()) => map()},
            open_stream_count: non_neg_integer(),
            ref_to_stream_id: %{optional(reference()) => stream_id()},
            enable_push: boolean(),
            server_max_concurrent_streams: non_neg_integer(),
            initial_window_size: pos_integer(),
            max_frame_size: pos_integer(),
            headers_being_processed: {stream_id(), iodata(), boolean()} | nil
          }

  ## Public interface

  @doc """
  Creates a new HTTP/2 connection to a given server.

  Creates a new `%XHTTP2{}` struct and establishes the connection to the given server,
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

    * `:client_settings` - (keyword) a list of client HTTP/2 settings to send to the
      server. See `put_settings/2` for more information. This is HTTP/2 specific.

  ## Examples

      {:ok, conn} = XHTTP2.connect(:https, "http2.golang.org", 443)

  """
  @spec connect(scheme(), String.t(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def connect(scheme, hostname, port, opts \\ []) do
    transport = scheme_to_transport(scheme)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    case negotiate(hostname, port, transport, transport_opts) do
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
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def upgrade(old_transport, socket, scheme, hostname, port, opts) do
    new_transport = scheme_to_transport(scheme)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    case new_transport.upgrade(socket, old_transport, hostname, port, transport_opts) do
      {:ok, {new_transport, socket}} ->
        initiate(new_transport, socket, hostname, port, opts)

      {:error, reason} ->
        {:error, reason}
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

      {:ok, conn} = XHTTP2.connect(:https, "http2.golang.org", 443)
      XHTTP2.open?(conn)
      #=> true

  """
  @impl true
  @spec open?(t()) :: boolean()
  def open?(%XHTTP2{state: state} = _conn), do: state == :open

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

  ## Examples

      XHTTP2.request(conn, "GET", "/", _headers = [])
      XHTTP2.request(conn, "POST", "/path", [{"Content-Type", "application/json"}], "{}")

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
  def request(%XHTTP2{} = conn, method, path, headers, body \\ nil)
      when is_binary(method) and is_binary(path) and is_list(headers) do
    headers = [
      {":method", method},
      {":path", path},
      {":scheme", conn.scheme},
      {":authority", "#{conn.hostname}:#{conn.port}"}
      | headers
    ]

    {conn, stream_id, ref} = open_stream(conn)

    conn =
      case body do
        :stream ->
          send_headers(conn, stream_id, headers, [:end_headers])

        nil ->
          send_headers(conn, stream_id, headers, [:end_stream, :end_headers])

        _iodata ->
          # TODO: Optimize here by sending a single packet on the network.
          conn = send_headers(conn, stream_id, headers, [:end_headers])
          conn = send_data(conn, stream_id, body, [:end_stream])
          conn
      end

    {:ok, conn, ref}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
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

      headers = [{"Content-Type", "application/json"}]
      {:ok, request_ref, conn} = XHTTP2.request(conn, "POST", "/", headers, :stream)
      {:ok, conn} = XHTTP2.stream_request_body(conn, request_ref, "{")
      {:ok, conn} = XHTTP2.stream_request_body(conn, request_ref, "}")
      {:ok, conn} = XHTTP2.stream_request_body(conn, request_ref, :eof)

  """
  @impl true
  @spec stream_request_body(t(), request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(%XHTTP2{} = conn, request_ref, chunk) when is_reference(request_ref) do
    stream_id = Map.fetch!(conn.ref_to_stream_id, request_ref)

    conn =
      if chunk == :eof do
        send_data(conn, stream_id, "", [:end_stream])
      else
        send_data(conn, stream_id, chunk, [])
      end

    {:ok, conn}
  end

  @doc """
  Pings the server.

  This function is specific to HTTP/2 connections. It sends a **ping** request to
  the server `conn` is connected to. A `{:ok, conn, request_ref}` tuple is returned,
  where `conn` is the updated connection and `request_ref` is a unique reference that
  identifies this ping request. The response to a ping request is returned by `stream/2`
  as a `{:pong, request_ref}` tuple. If there's an error, this function returns
  `{:error, conn, reason}` where `conn` is the updated connection and `reason` is the
  error reason.

  `payload` must be an 8-byte binary with arbitrary content. When the server responds to
  a ping request, it will use that same payload. By default, the payload is an 8-byte
  binary with all bits set to `0`.

  Pinging can be used to measure the latency with the server and to ensure the connection
  is alive and well.

  ## Examples

      {:ok, conn, ref} = XHTTP2.ping(conn)

  """
  @spec ping(t(), <<_::8>>) :: {:ok, t(), request_ref()} | {:error, t(), term()}
  def ping(%XHTTP2{} = conn, payload \\ :binary.copy(<<0>>, 8))
      when byte_size(payload) == 8 do
    {conn, ref} = send_ping(conn, payload)
    {:ok, conn, ref}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @doc """
  Sets the given HTTP/2 settings on the server.

  This function is HTTP/2-specific.

  This function takes a connection and a keyword list of HTTP/2 settings and sends
  the values of those settings to the server. The settings won't be effective until
  the server acknowledges them, which will be handled transparently by `stream/2`.

  This function returns `{:ok, conn}` when sending the settings to the server is
  successful, with `conn` being the updated connection. If there's an error, this
  function returns `{:error, conn, reason}` with `conn` being the updated connection
  and `reason` being the reason of the error.

  ## Supported settings

  These are the settings that you can send to the server. You can see the meaning
  of these settings [in the corresponding section in the HTTP/2
  RFC](https://http2.github.io/http2-spec/#rfc.section.6.5.2).

    * `:header_table_size` - (integer) corresponds to `SETTINGS_HEADER_TABLE_SIZE`.

    * `:enable_push` - (boolean) corresponds to `SETTINGS_ENABLE_PUSH`.

    * `:max_concurrent_streams` - (integer) corresponds to `SETTINGS_MAX_CONCURRENT_STREAMS`.

    * `:initial_window_size` - (integer smaller than `#{inspect(@max_window_size)}`)
      corresponds to `SETTINGS_INITIAL_WINDOW_SIZE`.

    * `:max_frame_size` - (integer in the range `#{inspect(@valid_max_frame_size_range)}`)
      corresponds to `SETTINGS_MAX_FRAME_SIZE`.

    * `:max_header_list_size` - (integer) corresponds to `SETTINGS_MAX_HEADER_LIST_SIZE`.

  ## Examples

      {:ok, conn} = XHTTP2.put_settings(conn, max_frame_size: 100)

  """
  @spec put_settings(t(), keyword()) :: {:ok, t()} | {:error, t(), reason :: term()}
  def put_settings(%XHTTP2{} = conn, settings) when is_list(settings) do
    conn = send_settings(conn, settings)
    {:ok, conn}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error}
  end

  @doc """
  Gets the value of the given HTTP/2 setting.

  This function returns the value of the given HTTP/2 setting and it's HTTP/2
  specific. For more information on HTTP/2 settings, see [the related section in
  the RFC](https://http2.github.io/http2-spec/#rfc.section.6.5.2).

  ## Supported settings

  The possible settings that can be retrieved are:

    * `:enable_push` - a boolean that tells whether push promises are enabled.

    * `:max_concurrent_streams` - an integer that tells what is the maximum
      number of streams that the server declared it supports. As mentioned in the
      module documentation, HTTP/2 streams are equivalent to requests, so knowing
      the maximum number of streams that the server supports can be usefule to know
      how many concurrent requests can be open at any time.

    * `:initial_window_size` - an integer that tells what is the value of
      the initial HTTP/2 window size declared by the server.

    * `:max_frame_size` - an integer that tells what is the maximum
      size of an HTTP/2 frame declared by the server.

  Any other atom passed as `name` will raise an error.

  ## Examples

      XHTTP2.get_setting(conn, :max_concurrent_streams)
      #=> 500

  """
  @spec get_setting(t(), atom()) :: term()
  def get_setting(%XHTTP2{} = conn, name) when is_atom(name) do
    case name do
      :enable_push -> conn.enable_push
      :max_concurrent_streams -> conn.server_max_concurrent_streams
      :initial_window_size -> conn.initial_window_size
      :max_frame_size -> conn.max_frame_size
      other -> raise ArgumentError, "unknown HTTP/2 setting: #{inspect(other)}"
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
  element is a unique reference that identifies the request that the response belongs to.
  This is the term returned by `request/5`. After these two elements, there can be
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

    * `{:pong, request_ref}` - returned when a server replies to a ping
      request sent by the client. See `ping/2` for more information. This
      response type is HTTP/2-specific.

    * `{:error, request_ref, reason}` - returned when there is an error that
      only affects the request and not the whole connection. For example, if the
      server sends bad data on a given request, that request will be closed an an error
      for that request will be returned among the responses, but the connection will
      remain alive and well.

  Responses are not grouped in any particular order. For example, sometimes `stream/2`
  might return a `:status` and a `:headers` response together in the same list of responses,
  while sometimes they might be returned from separate `stream/2` calls. This holds for
  all responses.

  ## Examples

  Let's assume we have a function called `receive_next_and_stream/1` that takes
  a connection and then receives the next message, calls `stream/2` with that message
  as an argument, and then returns the result of `stream/2`:

      defp receive_next_and_stream(conn) do
        receive do
          message -> XHTTP2.stream(conn, message)
        end
      end

  Now, we can see an example of a workflow involving `stream/2`.

      {:ok, request_ref, conn} = XHTTP2.request(conn, "GET", "/", _headers = [])

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

  def stream(%XHTTP2{socket: socket} = conn, {tag, socket, reason})
      when tag in [:tcp_error, :ssl_error] do
    {:error, %{conn | state: :closed}, reason, []}
  end

  def stream(%XHTTP2{socket: socket} = conn, {tag, socket})
      when tag in [:tcp_closed, :ssl_closed] do
    {:error, %{conn | state: :closed}, :closed, []}
  end

  def stream(%XHTTP2{transport: transport, socket: socket} = conn, {tag, socket, data})
      when tag in [:tcp, :ssl] do
    {conn, responses} = handle_new_data(conn, conn.buffer <> data, [])
    _ = transport.setopts(socket, active: :once)
    {:ok, conn, Enum.reverse(responses)}
  catch
    :throw, {:xhttp, conn, error} -> {:error, conn, error, []}
    :throw, {:xhttp, conn, error, responses} -> {:error, conn, error, responses}
  end

  def stream(%XHTTP2{}, _message) do
    :unknown
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

      conn = XHTTP2.put_private(conn, :client_name, "XHTTP")
      XHTTP2.get_private(conn, :client_name)
      #=> "XHTTP"

  """
  @impl true
  @spec put_private(t(), atom(), term()) :: t()
  def put_private(%XHTTP2{private: private} = conn, key, value) when is_atom(key) do
    %{conn | private: Map.put(private, key, value)}
  end

  @doc """
  Gets a private value from the connection.

  Retrieves a private value previously set with `put_private/3` from the connection.
  `key` is the key under which the value to retrieve is stored. `default` is a default
  value returned in case there's no value under the given key.

  See also `put_private/3` and `delete_private/2`.

  ## Examples

      conn = XHTTP2.put_private(conn, :client_name, "XHTTP")

      XHTTP2.get_private(conn, :client_name)
      #=> "XHTTP"

      XHTTP2.get_private(conn, :non_existent)
      #=> nil

  """
  @impl true
  @spec get_private(t(), atom(), term()) :: term()
  def get_private(%XHTTP2{private: private} = _conn, key, default \\ nil) when is_atom(key) do
    Map.get(private, key, default)
  end

  @doc """
  Deletes a value in the private store.

  Deletes the private value stored under `key` in the connection. Returns the
  updated connection.

  See also `put_private/3` and `get_private/3`.

  ## Examples

      conn = XHTTP2.put_private(conn, :client_name, "XHTTP")

      XHTTP2.get_private(conn, :client_name)
      #=> "XHTTP"

      conn = XHTTP2.delete_private(conn, :client_name)
      XHTTP2.get_private(conn, :client_name)
      #=> nil

  """
  @impl true
  @spec delete_private(t(), atom()) :: t()
  def delete_private(%XHTTP2{private: private} = conn, key) when is_atom(key) do
    %{conn | private: Map.delete(private, key)}
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  # SETTINGS parameters are not negotiated. We keep client settings and server settings separate.
  @doc false
  @impl true
  @spec initiate(
          module(),
          XHTTPCore.Transport.socket(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def initiate(transport, socket, hostname, port, opts) do
    client_settings_params = Keyword.get(opts, :client_settings, [])
    validate_settings!(client_settings_params)

    conn = %XHTTP2{
      hostname: hostname,
      port: port,
      transport: transport,
      socket: socket,
      # TODO: should we replace this with the scheme given in connect?
      scheme: Keyword.get(opts, :scheme, "https"),
      state: :open
    }

    with :ok <- inet_opts(transport, socket),
         client_settings = settings(stream_id: 0, params: client_settings_params),
         preface = [@connection_preface, Frame.encode(client_settings)],
         :ok <- transport.send(socket, preface),
         conn = update_in(conn.client_settings_queue, &:queue.in(client_settings_params, &1)),
         {:ok, server_settings, buffer, socket} <- receive_server_settings(transport, socket),
         server_settings_ack =
           settings(stream_id: 0, params: [], flags: set_flag(:settings, :ack)),
         :ok <- transport.send(socket, Frame.encode(server_settings_ack)),
         conn = put_in(conn.buffer, buffer),
         conn = put_in(conn.socket, socket),
         conn = apply_server_settings(conn, settings(server_settings, :params)),
         :ok <- transport.setopts(socket, active: :once) do
      {:ok, conn}
    else
      error ->
        transport.close(socket)
        error
    end
  end

  @doc """
  Gets the underlying TCP/SSL socket from the connection.

  Right now there is no built-in way to tell if the socket being retrieved
  is a `:gen_tcp` or an `:ssl` socket. You can store the transport (`:http`
  or `:https`) you're using in the private store when starting the connection.
  See `put_private/3` and `get_private/3`.

  ## Examples

      socket = XHTTP2.get_socket(conn)

  """
  @impl true
  @spec get_socket(t()) :: XHTTPCore.Transport.socket()
  def get_socket(%XHTTP2{socket: socket} = _conn) do
    socket
  end

  ## Helpers

  defp negotiate(hostname, port, transport, transport_opts) do
    with {:ok, socket} <- transport.connect(hostname, port, transport_opts),
         {:ok, protocol} <- transport.negotiated_protocol(socket) do
      if protocol == "h2" do
        {:ok, socket}
      else
        {:error, {:bad_alpn_protocol, protocol}}
      end
    end
  end

  defp receive_server_settings(transport, socket) do
    case recv_next_frame(transport, socket, _buffer = "") do
      {:ok, settings(), _buffer, _socket} = result -> result
      {:ok, _frame, _buffer, _socket} -> {:error, :protocol_error}
      {:error, _reason} = error -> error
    end
  end

  defp recv_next_frame(transport, socket, buffer) do
    case Frame.decode_next(buffer, @default_max_frame_size) do
      {:ok, frame, rest} ->
        {:ok, frame, rest, socket}

      :more ->
        with {:ok, data} <- transport.recv(socket, 0) do
          recv_next_frame(transport, socket, buffer <> data)
        end

      {:error, {kind, _info}} when kind in [:frame_size_error, :protocol_error] ->
        {:error, kind}
    end
  end

  defp open_stream(%XHTTP2{server_max_concurrent_streams: mcs} = conn) do
    if conn.open_stream_count >= mcs do
      throw({:xhttp, conn, {:max_concurrent_streams_reached, mcs}})
    end

    stream = %{
      id: conn.next_stream_id,
      ref: make_ref(),
      state: :idle,
      window_size: conn.initial_window_size
    }

    conn = put_in(conn.streams[stream.id], stream)
    conn = put_in(conn.ref_to_stream_id[stream.ref], stream.id)
    conn = update_in(conn.next_stream_id, &(&1 + 2))
    {conn, stream.id, stream.ref}
  end

  defp send_headers(conn, stream_id, headers, enabled_flags) do
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:idle])

    headers = Enum.map(headers, fn {name, value} -> {:store_name, name, value} end)
    {hbf, conn} = get_and_update_in(conn.encode_table, &HPACK.encode(headers, &1))

    payload = headers_to_encoded_frames(conn, stream_id, hbf, enabled_flags)
    conn = send!(conn, payload)

    stream_state = if :end_stream in enabled_flags, do: :half_closed_local, else: :open

    conn = put_in(conn.streams[stream_id].state, stream_state)
    conn = update_in(conn.open_stream_count, &(&1 + 1))
    conn
  end

  defp headers_to_encoded_frames(conn, stream_id, hbf, enabled_flags) do
    if IO.iodata_length(hbf) > conn.max_frame_size do
      hbf
      |> IO.iodata_to_binary()
      |> split_payload_in_chunks(conn.max_frame_size)
      |> split_hbf_to_encoded_frames(stream_id, enabled_flags)
    else
      Frame.encode(
        headers(stream_id: stream_id, hbf: hbf, flags: set_flags(:headers, enabled_flags))
      )
    end
  end

  defp split_hbf_to_encoded_frames({[first_chunk | chunks], last_chunk}, stream_id, enabled_flags) do
    flags = set_flags(:headers, enabled_flags -- [:end_headers])
    first_frame = Frame.encode(headers(stream_id: stream_id, hbf: first_chunk, flags: flags))

    middle_frames =
      Enum.map(chunks, fn chunk ->
        Frame.encode(continuation(stream_id: stream_id, hbf: chunk))
      end)

    flags =
      if :end_headers in enabled_flags do
        set_flag(:continuation, :end_headers)
      else
        0x00
      end

    last_frame = Frame.encode(continuation(stream_id: stream_id, hbf: last_chunk, flags: flags))

    [first_frame, middle_frames, last_frame]
  end

  defp send_data(conn, stream_id, data, enabled_flags) do
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:open])

    data_size = IO.iodata_length(data)

    cond do
      data_size >= stream.window_size ->
        throw({:xhttp, conn, {:exceeds_stream_window_size, stream.window_size}})

      data_size >= conn.window_size ->
        throw({:xhttp, conn, {:exceeds_connection_window_size, conn.window_size}})

      data_size > conn.max_frame_size ->
        {chunks, last_chunk} =
          data
          |> IO.iodata_to_binary()
          |> split_payload_in_chunks(conn.max_frame_size)

        conn =
          Enum.reduce(chunks, conn, fn chunk, acc ->
            send_data(acc, stream_id, chunk, [])
          end)

        send_data(conn, stream_id, last_chunk, enabled_flags)

      true ->
        frame = data(stream_id: stream_id, flags: set_flags(:data, enabled_flags), data: data)
        conn = send!(conn, Frame.encode(frame))
        conn = update_in(conn.streams[stream_id].window_size, &(&1 - data_size))
        conn = update_in(conn.window_size, &(&1 - data_size))

        conn =
          if :end_stream in enabled_flags do
            put_in(conn.streams[stream_id].state, :half_closed_local)
          else
            conn
          end

        conn
    end
  end

  defp split_payload_in_chunks(binary, chunk_size),
    do: split_payload_in_chunks(binary, chunk_size, [])

  defp split_payload_in_chunks(chunk, chunk_size, acc) when byte_size(chunk) <= chunk_size do
    {Enum.reverse(acc), chunk}
  end

  defp split_payload_in_chunks(binary, chunk_size, acc) do
    <<chunk::size(chunk_size)-binary, rest::binary>> = binary
    split_payload_in_chunks(rest, chunk_size, [chunk | acc])
  end

  defp send_ping(conn, payload) do
    frame = Frame.ping(stream_id: 0, opaque_data: payload)
    conn = send!(conn, Frame.encode(frame))
    ref = make_ref()
    conn = update_in(conn.ping_queue, &:queue.in({ref, payload}, &1))
    {conn, ref}
  end

  defp send_settings(conn, settings) do
    validate_settings!(settings)
    frame = settings(stream_id: 0, params: settings)
    conn = send!(conn, Frame.encode(frame))
    conn = update_in(conn.client_settings_queue, &:queue.in(settings, &1))
    conn
  end

  defp validate_settings!(settings) do
    unless Keyword.keyword?(settings) do
      raise ArgumentError, "settings must be a keyword list"
    end

    Enum.each(settings, fn
      {:header_table_size, value} ->
        unless is_integer(value) do
          raise ArgumentError, ":header_table_size must be an integer, got: #{inspect(value)}"
        end

      {:enable_push, value} ->
        case value do
          true ->
            raise ArgumentError,
                  "push promises are not supported yet, so :enable_push must be false"

          false ->
            :ok

          _other ->
            raise ArgumentError, ":enable_push must be a boolean, got: #{inspect(value)}"
        end

      {:max_concurrent_streams, value} ->
        unless is_integer(value) do
          raise ArgumentError,
                ":max_concurrent_streams must be an integer, got: #{inspect(value)}"
        end

      {:initial_window_size, value} ->
        unless is_integer(value) and value <= @max_window_size do
          raise ArgumentError,
                ":initial_window_size must be an integer < #{@max_window_size}, " <>
                  "got: #{inspect(value)}"
        end

      {:max_frame_size, value} ->
        unless is_integer(value) and value in @valid_max_frame_size_range do
          raise ArgumentError,
                ":max_frame_size must be an integer in #{inspect(@valid_max_frame_size_range)}, " <>
                  "got: #{inspect(value)}"
        end

      {:max_header_list_size, value} ->
        unless is_integer(value) do
          raise ArgumentError, ":max_header_list_size must be an integer, got: #{inspect(value)}"
        end

      {name, _value} ->
        raise ArgumentError, "unknown setting parameter #{inspect(name)}"
    end)
  end

  ## Frame handling

  defp handle_new_data(%XHTTP2{} = conn, data, responses) do
    case Frame.decode_next(data, conn.client_max_frame_size) do
      {:ok, frame, rest} ->
        Logger.debug(fn -> "Got frame: #{inspect(frame)}" end)
        assert_valid_frame(conn, frame)
        {conn, responses} = handle_frame(conn, frame, responses)
        handle_new_data(conn, rest, responses)

      :more ->
        {%{conn | buffer: data}, responses}

      {:error, :payload_too_big} ->
        # TODO: sometimes, this could be handled with RST_STREAM instead of a GOAWAY frame (for
        # example, if the payload of a DATA frame is too big).
        # http://httpwg.org/specs/rfc7540.html#rfc.section.4.2
        debug_data = "frame payload exceeds connection's max frame size"
        send_connection_error!(conn, :frame_size_error, debug_data)

      {:error, {:frame_size_error, frame}} ->
        debug_data = "error with size of frame: #{inspect(frame)}"
        send_connection_error!(conn, :frame_size_error, debug_data)

      {:error, {:protocol_error, info}} ->
        debug_data = "error when decoding frame: #{inspect(info)}"
        send_connection_error!(conn, :protocol_error, debug_data)
    end
  catch
    :throw, {:xhttp, conn, error} ->
      throw({:xhttp, conn, error, responses})
  end

  defp assert_valid_frame(conn, frame) do
    assert_frame_on_right_level(conn, elem(frame, 0), elem(frame, 1))
    assert_frame_doesnt_interrupt_header_streaming(conn, frame)
  end

  # http://httpwg.org/specs/rfc7540.html#HttpSequence
  defp assert_frame_doesnt_interrupt_header_streaming(conn, frame) do
    case {conn.headers_being_processed, frame} do
      {nil, continuation()} ->
        debug_data = "CONTINUATION received outside of headers streaming"
        send_connection_error!(conn, :protocol_error, debug_data)

      {nil, _frame} ->
        :ok

      {{stream_id, _, _}, continuation(stream_id: stream_id)} ->
        :ok

      _other ->
        debug_data = "headers are streaming but got a frame that is not related to that"
        send_connection_error!(conn, :protocol_error, debug_data)
    end
  end

  stream_level_frames = [:data, :headers, :priority, :rst_stream, :push_promise, :continuation]
  connection_level_frames = [:settings, :ping, :goaway]

  defp assert_frame_on_right_level(conn, frame, 0)
       when frame in unquote(stream_level_frames) do
    debug_data = "frame #{frame} not allowed at the connection level (stream_id = 0)"
    send_connection_error!(conn, :protocol_error, debug_data)
  end

  defp assert_frame_on_right_level(conn, frame, stream_id)
       when frame in unquote(connection_level_frames) and stream_id != 0 do
    debug_data = "frame #{frame} only allowed at the connection level"
    send_connection_error!(conn, :protocol_error, debug_data)
  end

  defp assert_frame_on_right_level(_conn, _frame, _stream_id) do
    :ok
  end

  defp handle_frame(conn, data() = frame, resps), do: handle_data(conn, frame, resps)

  defp handle_frame(conn, headers() = frame, resps), do: handle_headers(conn, frame, resps)

  defp handle_frame(conn, priority() = frame, resps), do: handle_priority(conn, frame, resps)

  defp handle_frame(conn, rst_stream() = frame, resps), do: handle_rst_stream(conn, frame, resps)

  defp handle_frame(conn, settings() = frame, resps), do: handle_settings(conn, frame, resps)

  # TODO: implement PUSH_PROMISE
  defp handle_frame(_, push_promise(), _resps), do: raise("PUSH_PROMISE handling not implemented")

  defp handle_frame(conn, Frame.ping() = frame, resps), do: handle_ping(conn, frame, resps)

  defp handle_frame(conn, goaway() = frame, resps), do: handle_goaway(conn, frame, resps)

  defp handle_frame(conn, window_update() = frame, resps),
    do: handle_window_update(conn, frame, resps)

  defp handle_frame(conn, continuation() = frame, resps),
    do: handle_continuation(conn, frame, resps)

  # DATA

  defp handle_data(conn, frame, responses) do
    data(stream_id: stream_id, flags: flags, data: data, padding: padding) = frame
    stream = fetch_stream!(conn, stream_id)

    assert_stream_in_state(conn, stream, [:open, :half_closed_local])

    conn = refill_client_windows(conn, stream_id, byte_size(data) + byte_size(padding || ""))

    responses = [{:data, stream.ref, data} | responses]

    if flag_set?(flags, :data, :end_stream) do
      conn = put_in(conn.streams[stream_id].state, :half_closed_remote)
      conn = update_in(conn.open_stream_count, &(&1 - 1))
      {conn, [{:done, stream.ref} | responses]}
    else
      {conn, responses}
    end
  end

  defp refill_client_windows(conn, stream_id, data_size) do
    connection_frame = window_update(stream_id: 0, window_size_increment: data_size)
    stream_frame = window_update(stream_id: stream_id, window_size_increment: data_size)
    send!(conn, [Frame.encode(connection_frame), Frame.encode(stream_frame)])
  end

  # HEADERS

  defp handle_headers(conn, frame, responses) do
    headers(stream_id: stream_id, flags: flags, hbf: hbf) = frame
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:open, :half_closed_local])
    end_stream? = flag_set?(flags, :headers, :end_stream)

    if flag_set?(flags, :headers, :end_headers) do
      decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?)
    else
      conn = put_in(conn.headers_being_processed, {stream_id, hbf, end_stream?})
      {conn, responses}
    end
  end

  defp decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?) do
    case decode_hbf(conn, hbf) do
      {:ok, status, headers, conn} ->
        responses = [{:headers, stream.ref, headers}, {:status, stream.ref, status} | responses]

        if end_stream? do
          conn = put_in(conn.streams[stream.id].state, :half_closed_remote)
          conn = update_in(conn.open_stream_count, &(&1 - 1))
          {conn, [{:done, stream.ref} | responses]}
        else
          {conn, responses}
        end

      # http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.6
      {:error, :missing_status_header, conn} ->
        conn = close_stream!(conn, stream.id, :protocol_error)
        reason = {:protocol_error, :missing_status_header}
        responses = [{:error, stream.ref, reason} | responses]
        {conn, responses}
    end
  end

  defp decode_hbf(conn, hbf) do
    case HPACK.decode(hbf, conn.decode_table) do
      {:ok, headers, decode_table} ->
        conn = put_in(conn.decode_table, decode_table)

        case headers do
          [{":status", status} | headers] -> {:ok, String.to_integer(status), headers, conn}
          _other -> {:error, :missing_status_header, conn}
        end

      {:error, reason} ->
        debug_data = "unable to decode headers: #{inspect(reason)}"
        send_connection_error!(conn, :compression_error, debug_data)
    end
  end

  # PRIORITY

  defp handle_priority(conn, frame, responses) do
    Logger.warn(fn -> "Ignoring PRIORITY frame: #{inspect(frame)}" end)
    {conn, responses}
  end

  # RST_STREAM

  defp handle_rst_stream(conn, frame, responses) do
    rst_stream(stream_id: stream_id, error_code: error_code) = frame
    stream = fetch_stream!(conn, stream_id)
    conn = put_in(conn.streams[stream_id].state, :closed)
    {conn, [{:error, stream.ref, {:rst_stream, error_code}} | responses]}
  end

  # SETTINGS

  defp handle_settings(conn, frame, responses) do
    settings(flags: flags, params: params) = frame

    if flag_set?(flags, :settings, :ack) do
      {{:value, params}, conn} = get_and_update_in(conn.client_settings_queue, &:queue.out/1)
      conn = apply_client_settings(conn, params)
      {conn, responses}
    else
      conn = apply_server_settings(conn, params)
      frame = settings(flags: set_flag(:settings, :ack), params: [])
      conn = send!(conn, Frame.encode(frame))
      {conn, responses}
    end
  end

  defp apply_server_settings(conn, server_settings) do
    Enum.reduce(server_settings, conn, fn
      {:header_table_size, header_table_size}, conn ->
        update_in(conn.encode_table, &HPACK.resize(&1, header_table_size))

      {:enable_push, enable_push?}, conn ->
        put_in(conn.enable_push, enable_push?)

      {:max_concurrent_streams, max_concurrent_streams}, conn ->
        put_in(conn.server_max_concurrent_streams, max_concurrent_streams)

      {:initial_window_size, initial_window_size}, conn ->
        if initial_window_size > @max_window_size do
          debug_data = "INITIAL_WINDOW_SIZE setting parameter is too big"
          send_connection_error!(conn, :flow_control_error, debug_data)
        end

        update_initial_window_size(conn, initial_window_size)

      {:max_frame_size, max_frame_size}, conn ->
        if max_frame_size not in @valid_max_frame_size_range do
          debug_data = "MAX_FRAME_SIZE setting parameter outside of allowed range"
          send_connection_error!(conn, :protocol_error, debug_data)
        end

        put_in(conn.max_frame_size, max_frame_size)

      {:max_header_list_size, max_header_list_size}, conn ->
        Logger.debug(fn ->
          "Ignoring MAX_HEADERS_LIST_SIZE parameter with value #{max_header_list_size}"
        end)

        conn
    end)
  end

  defp apply_client_settings(conn, client_settings) do
    Enum.reduce(client_settings, conn, fn
      {:max_frame_size, value}, conn ->
        put_in(conn.client_max_frame_size, value)

      {:max_concurrent_streams, value}, conn ->
        put_in(conn.client_max_concurrent_streams, value)
    end)
  end

  defp update_initial_window_size(conn, new_iws) do
    diff = new_iws - conn.initial_window_size

    conn =
      update_in(conn.streams, fn streams ->
        for {stream_id, stream} <- streams,
            stream.state in [:open, :half_closed_remote],
            into: streams do
          window_size = stream.window_size + diff

          if window_size > @max_window_size do
            debug_data = "INITIAL_WINDOW_SIZE setting parameter makes some window sizes too big"
            send_connection_error!(conn, :flow_control_error, debug_data)
          end

          {stream_id, %{stream | window_size: window_size}}
        end
      end)

    put_in(conn.initial_window_size, new_iws)
  end

  # PING

  defp handle_ping(conn, Frame.ping() = frame, responses) do
    Frame.ping(flags: flags, opaque_data: opaque_data) = frame

    if flag_set?(flags, :ping, :ack) do
      handle_ping_ack(conn, opaque_data, responses)
    else
      ack = Frame.ping(stream_id: 0, flags: set_flag(:ping, :ack), opaque_data: opaque_data)
      conn = send!(conn, Frame.encode(ack))
      {conn, responses}
    end
  end

  defp handle_ping_ack(conn, opaque_data, responses) do
    case :queue.out(conn.ping_queue) do
      {{:value, {ref, ^opaque_data}}, ping_queue} ->
        conn = put_in(conn.ping_queue, ping_queue)
        {conn, [{:pong, ref} | responses]}

      {{:value, _}, _} ->
        Logger.error("Received PING ack that doesn't match next PING request in the queue")
        throw({:xhttp, conn, :protocol_error, responses})

      {:empty, _ping_queue} ->
        Logger.error("Received PING ack but no PING requests had been sent")
        throw({:xhttp, conn, :protocol_error, responses})
    end
  end

  # GOAWAY

  defp handle_goaway(conn, frame, responses) do
    goaway(
      last_stream_id: last_stream_id,
      error_code: error_code,
      debug_data: debug_data
    ) = frame

    unprocessed_stream_ids = Enum.filter(conn.streams, fn {id, _} -> id > last_stream_id end)

    {conn, responses} =
      Enum.reduce(unprocessed_stream_ids, {conn, responses}, fn {id, stream}, {conn, responses} ->
        conn = update_in(conn.streams, &Map.delete(&1, id))
        conn = update_in(conn.open_stream_count, &(&1 - 1))
        conn = update_in(conn.ref_to_stream_id, &Map.delete(&1, stream.ref))
        conn = put_in(conn.state, :went_away)
        response = {:error, stream.ref, {:goaway, error_code, debug_data}}
        {conn, [response | responses]}
      end)

    {conn, responses}
  end

  # WINDOW_UPDATE

  defp handle_window_update(
         conn,
         window_update(stream_id: 0, window_size_increment: wsi),
         responses
       ) do
    case conn.window_size do
      ws when ws + wsi > @max_window_size ->
        send_connection_error!(conn, :flow_control_error, "window size too big")

      ws ->
        conn = put_in(conn.window_size, ws)
        {conn, responses}
    end
  end

  defp handle_window_update(
         conn,
         window_update(stream_id: stream_id, window_size_increment: wsi),
         responses
       ) do
    stream = fetch_stream!(conn, stream_id)

    case conn.streams[stream_id].window_size do
      ws when ws + wsi > @max_window_size ->
        conn = close_stream!(conn, stream_id, :flow_control_error)
        {conn, [{:error, stream.ref, :flow_control_error} | responses]}

      ws ->
        conn = put_in(conn.streams[stream_id].window_size, ws + wsi)
        {conn, responses}
    end
  end

  # CONTINUATION

  defp handle_continuation(conn, frame, responses) do
    continuation(stream_id: stream_id, flags: flags, hbf: hbf_chunk) = frame
    stream = fetch_stream!(conn, stream_id)

    {^stream_id, hbf_acc, end_stream?} = conn.headers_being_processed

    if flag_set?(flags, :continuation, :end_headers) do
      hbf = IO.iodata_to_binary([hbf_acc, hbf_chunk])
      decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?)
    else
      conn = put_in(conn.headers_being_processed, {stream_id, [hbf_acc, hbf_chunk], end_stream?})
      {conn, responses}
    end
  end

  ## General helpers

  defp send_connection_error!(conn, error_code, debug_data) do
    frame =
      goaway(stream_id: 0, last_stream_id: 2, error_code: error_code, debug_data: debug_data)

    conn = send!(conn, Frame.encode(frame))
    :ok = conn.transport.close(conn.socket)
    conn = put_in(conn.state, :closed)
    throw({:xhttp, conn, error_code})
  end

  defp close_stream!(conn, stream_id, error_code) do
    frame = rst_stream(stream_id: stream_id, error_code: error_code)
    conn = send!(conn, Frame.encode(frame))
    put_in(conn.streams[stream_id].state, :closed)
  end

  defp fetch_stream!(conn, stream_id) do
    case Map.fetch(conn.streams, stream_id) do
      {:ok, stream} -> stream
      :error -> throw({:xhttp, conn, {:stream_not_found, stream_id}})
    end
  end

  defp assert_stream_in_state(conn, %{state: state}, expected_states) do
    if state not in expected_states do
      throw({:xhttp, conn, {:stream_not_in_expected_state, expected_states, state}})
    end
  end

  defp send!(%XHTTP2{transport: transport, socket: socket} = conn, bytes) do
    case transport.send(socket, bytes) do
      :ok -> conn
      {:error, :closed} -> throw({:xhttp, %{conn | state: :closed}, :closed})
      {:error, reason} -> throw({:xhttp, conn, reason})
    end
  end
end
