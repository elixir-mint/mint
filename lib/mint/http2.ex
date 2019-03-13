defmodule Mint.HTTP2 do
  @moduledoc """
  Processless HTTP client with support for HTTP/2.

  This module provides a data structure that represents an HTTP/2 connection to
  a given server. The connection is represented as an opaque struct `%Mint.HTTP2{}`.
  The connection is a data structure and is not backed by a process, and all the
  connection handling happens in the process that creates the struct.

  This module and data structure work exactly like the ones described in the `Mint`
  module, with the exception that `Mint.HTTP2` specifically deals with HTTP/2 while
  `Mint` deals seamlessly with HTTP/1.1 and HTTP/2. For more information on
  how to use the data structure and client architecture, see `Mint`.

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

  ## HTTP/2 settings

  HTTP/2 supports settings negotiation between servers and clients. The server advertises
  its settings to the client and the client advertises its settings to the server. A peer
  (server or client) has to acknowledge the settings advertised by the other peer before
  those settings come into action (that's why it's called a negotiation).

  A first settings negotiation happens right when the connection starts.
  Servers and clients can renegotiate settings at any time during the life of the
  connection.

  Mint users don't need to care about settings acknowledgements directly since they're
  handled transparently by `stream/2`.

  To retrieve the server settings, you can use `get_server_setting/2`. Doing so is often
  useful to be able to tune your requests based on the server settings.

  To communicate client settings to the server, use `put_settings/2` or pass them when
  starting up a connection with `connect/4`. Note that the server needs to acknowledge
  the settings sent through `put_setting/2` before those settings come into effect. The
  server ack is processed transparently by `stream/2`, but this means that if you change
  a setting through `put_settings/2` and try to retrieve the value of that setting right
  after with `get_client_setting/2`, you'll likely get the old value of that setting. Once
  the server acknowledges the new settings, the updated value will be returned by
  `get_client_setting/2`.

  ## Server push

  HTTP/2 supports [server push](https://en.wikipedia.org/wiki/HTTP/2_Server_Push), which
  is a way for a server to send a response to a client without the client needing to make
  the corresponding request. The server sends a `:push_promise` response to a normal request:
  this creates a new request reference. Then, the server sends normal responses for the newly
  created request reference.

  Let's see an example. We will ask the server for `"/index.html"` and the server will
  send us a push promise for `"/style.css"`.

      {:ok, conn} = Mint.HTTP2.connect(:https, "example.com", 443)
      {:ok, conn, request_ref} = Mint.HTTP2.request(conn, "GET", "/index.html", _headers = [])

      next_message =
        receive do
          msg -> msg
        end

      {:ok, conn, responses} = Mint.HTTP2.stream(conn, next_message)

      [
        {:push_promise, ^request_ref, promised_request_ref, promised_headers},
        {:status, ^request_ref, 200},
        {:headers, ^request_ref, []},
        {:data, ^request_ref, "<html>..."},
        {:done, ^request_ref}
      ] = responses

      promised_headers
      #=> [{":method", "GET"}, {":path", "/style.css"}]

  As you can see in the example above, when the server sends a push promise then a
  `:push_promise` response is returned as a response to a request. The `:push_promise`
  response contains a `promised_request_ref` and some `promised_headers`. The
  `promised_request_ref` is the new request ref that pushed responses will be tagged with.
  `promised_headers` are headers that tell the client *what request* the promised response
  will respond to. The idea is that the server tells the client a request the client will
  want to make and then preemptively sends a response for that request. Promised headers
  will always include `:method`, `:path`, and `:authority`.

      next_message =
        receive do
          msg -> msg
        end

      {:ok, conn, responses} = Mint.HTTP2.stream(conn, next_message)

      [
        {:status, ^promised_request_ref, 200},
        {:headers, ^promised_request_ref, []},
        {:data, ^promised_request_ref, "body { ... }"},
        {:done, ^promised_request_ref}
      ]

  The response to a promised request is like a response to any normal request.

  ### Disabling server pushes

  HTTP/2 exposes a boolean setting for enabling or disabling server pushes with `:enable_push`.
  You can pass this option when connecting or in `put_settings/2`. By default server push
  is enabled.
  """

  use Bitwise, skip_operators: true

  import Mint.Core.Util
  import Mint.HTTP2.Frame, except: [encode: 1, decode_next: 1]

  alias Mint.Types
  alias Mint.Core.Util

  alias Mint.HTTP2.{
    Frame,
    HPACK
  }

  require Logger
  require Integer

  @behaviour Mint.Core.Conn

  ## Constants

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @transport_opts [alpn_advertised_protocols: ["h2"]]

  @default_window_size 65_535
  @max_window_size 2_147_483_647

  @default_max_frame_size 16_384
  @valid_max_frame_size_range @default_max_frame_size..16_777_215

  @user_agent "mint/" <> Mix.Project.config()[:version]

  # HTTP/2 connection struct.
  defstruct [
    # Transport things.
    :transport,
    :socket,

    # Host things.
    :hostname,
    :port,
    :scheme,

    # Connection state (open, closed, and so on).
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

    # Settings that the server communicates to the client.
    server_settings: %{
      enable_push: true,
      max_concurrent_streams: 100,
      initial_window_size: @default_window_size,
      max_frame_size: @default_max_frame_size,
      max_header_list_size: :infinity
    },

    # Settings that the client communicates to the server.
    client_settings: %{
      max_concurrent_streams: 100,
      max_frame_size: @default_max_frame_size,
      enable_push: true
    },

    # Headers being processed (when headers are split into multiple frames with CONTINUATIONS, all
    # the continuation frames must come one right after the other).
    headers_being_processed: nil,

    # Private store.
    private: %{}
  ]

  ## Types

  @typedoc """
  HTTP/2 setting with its value.

  This type represents both server settings as well as client settings. To retrieve
  server settings use `get_server_settings/2` and to retrieve client settings use
  `get_client_setting/2`. To send client settings to the server, see `put_settings/2`.

  The supported settings are the following:

    * `:header_table_size` - (integer) corresponds to `SETTINGS_HEADER_TABLE_SIZE`.

    * `:enable_push` - (boolean) corresponds to `SETTINGS_ENABLE_PUSH`. Sets whether
      push promises are supported. If you don't want to support push promises,
      use `put_settings/2` to tell the server that your client doesn't want push promises.

    * `:max_concurrent_streams` - (integer) corresponds to `SETTINGS_MAX_CONCURRENT_STREAMS`.
      Tells what is the maximum number of streams that the peer sending this (client or server)
      supports. As mentioned in the module documentation, HTTP/2 streams are equivalent to
      requests, so knowing the maximum number of streams that the server supports can be useful
      to know how many concurrent requests can be open at any time. Use `get_server_setting/2`
      to find out how many concurrent streams the server supports.

    * `:initial_window_size` - (integer smaller than `#{inspect(@max_window_size)}`)
      corresponds to `SETTINGS_INITIAL_WINDOW_SIZE`. Tells what is the value of
      the initial HTTP/2 window size for the peer that sends this setting.

    * `:max_frame_size` - (integer in the range `#{inspect(@valid_max_frame_size_range)}`)
      corresponds to `SETTINGS_MAX_FRAME_SIZE`. Tells what is the maximum size of an HTTP/2
      frame for the peer that sends this setting.

    * `:max_header_list_size` - (integer) corresponds to `SETTINGS_MAX_HEADER_LIST_SIZE`.

  """
  @type setting() ::
          {:enable_push, boolean()}
          | {:max_concurrent_streams, pos_integer()}
          | {:initial_window_size, 1..2_147_483_647}
          | {:max_frame_size, 16_384..16_777_215}
          | {:max_header_list_size, :infinity | pos_integer()}

  @typedoc """
  HTTP/2 settings.

  See `t:setting/0`.
  """
  @type settings() :: [setting()]

  @opaque t() :: %Mint.HTTP2{}

  ## Public interface

  @doc """
  Same as `Mint.HTTP.connect/4`, but forces a HTTP/2 connection.
  """
  @spec connect(Types.scheme(), String.t(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def connect(scheme, hostname, port, opts \\ []) do
    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    case negotiate(hostname, port, scheme, transport_opts) do
      {:ok, socket} ->
        initiate(scheme, socket, hostname, port, opts)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc false
  @spec upgrade(
          Types.scheme(),
          Mint.Core.Transport.socket(),
          Types.scheme(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def upgrade(old_scheme, socket, new_scheme, hostname, port, opts) do
    transport = scheme_to_transport(new_scheme)

    transport_opts =
      opts
      |> Keyword.get(:transport_opts, [])
      |> Keyword.merge(@transport_opts)

    case transport.upgrade(socket, old_scheme, hostname, port, transport_opts) do
      {:ok, socket} ->
        initiate(new_scheme, socket, hostname, port, opts)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  See `Mint.HTTP.close/1`.
  """
  @impl true
  @spec close(t()) :: {:ok, t()}
  def close(conn)

  def close(%__MODULE__{state: :open} = conn) do
    conn = send_connection_error!(conn, :no_error, "connection peacefully closed by client")
    {:ok, conn}
  catch
    # We could have an error sending the GOAWAY frame, but we want to ignore that since
    # we're closing the connection anyways.
    {:mint, conn, _reason} ->
      conn = put_in(conn.state, :closed)
      {:ok, conn}
  end

  def close(%__MODULE__{state: :closed} = conn) do
    {:ok, conn}
  end

  @doc """
  See `Mint.HTTP.open?/1`.
  """
  @impl true
  @spec open?(t()) :: boolean()
  def open?(%Mint.HTTP2{state: state} = _conn), do: state == :open

  @doc """
  See `Mint.HTTP.request/5`.

  In HTTP/2, opening a request means opening a new HTTP/2 stream (see the
  module documentation). This means that a request could fail because the
  maximum number of concurrent streams allowed by the server has been reached.
  In that case, the error reason `{:max_concurrent_streams_reached, value}` is
  returned where `value` is the maximum number of concurrent streams possible.
  If you want to avoid incurring in this error, you can retrieve the value of
  the maximum number of concurrent streams supported by the server through
  `get_server_setting/2` (passing in the `:max_concurrent_streams` setting name).
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
          | {:error, t(), term()}
  def request(%Mint.HTTP2{} = conn, method, path, headers, body \\ nil)
      when is_binary(method) and is_binary(path) and is_list(headers) do
    headers = [
      {":method", method},
      {":path", path},
      {":scheme", conn.scheme},
      {":authority", "#{conn.hostname}:#{conn.port}"}
      | add_default_headers(headers)
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
    :throw, {:mint, conn, error} -> {:error, conn, error}
  end

  @doc """
  See `Mint.HTTP.stream_request_body/3`.
  """
  @impl true
  @spec stream_request_body(t(), Types.request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(%Mint.HTTP2{} = conn, request_ref, chunk)
      when is_reference(request_ref) do
    stream_id = Map.fetch!(conn.ref_to_stream_id, request_ref)

    conn =
      if chunk == :eof do
        send_data(conn, stream_id, "", [:end_stream])
      else
        send_data(conn, stream_id, chunk, [])
      end

    {:ok, conn}
  catch
    :throw, {:mint, conn, error} -> {:error, conn, error}
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

      {:ok, conn, ref} = Mint.HTTP2.ping(conn)

  """
  @spec ping(t(), <<_::8>>) :: {:ok, t(), Types.request_ref()} | {:error, t(), term()}
  def ping(%Mint.HTTP2{} = conn, payload \\ :binary.copy(<<0>>, 8))
      when byte_size(payload) == 8 do
    {conn, ref} = send_ping(conn, payload)
    {:ok, conn, ref}
  catch
    :throw, {:mint, conn, error} -> {:error, conn, error}
  end

  @doc """
  Communicates the given client settings to the server.

  This function is HTTP/2-specific.

  This function takes a connection and a keyword list of HTTP/2 settings and sends
  the values of those settings to the server. The settings won't be effective until
  the server acknowledges them, which will be handled transparently by `stream/2`.

  This function returns `{:ok, conn}` when sending the settings to the server is
  successful, with `conn` being the updated connection. If there's an error, this
  function returns `{:error, conn, reason}` with `conn` being the updated connection
  and `reason` being the reason of the error.

  ## Supported settings

  See `t:setting/0` for the supported settings. You can see the meaning
  of these settings [in the corresponding section in the HTTP/2
  RFC](https://http2.github.io/http2-spec/#rfc.section.6.5.2).

  See the "HTTP/2 settings" section in the module documentation for more information.

  ## Examples

      {:ok, conn} = Mint.HTTP2.put_settings(conn, max_frame_size: 100)

  """
  @spec put_settings(t(), settings()) :: {:ok, t()} | {:error, t(), reason :: term()}
  def put_settings(%Mint.HTTP2{} = conn, settings) when is_list(settings) do
    conn = send_settings(conn, settings)
    {:ok, conn}
  catch
    :throw, {:mint, conn, error} -> {:error, conn, error}
  end

  @doc """
  Gets the value of the given HTTP/2 server settings.

  This function returns the value of the given HTTP/2 setting that the server
  advertised to the client. This function is HTTP/2 specific.
  For more information on HTTP/2 settings, see [the related section in
  the RFC](https://http2.github.io/http2-spec/#rfc.section.6.5.2).

  See the "HTTP/2 settings" section in the module documentation for more information.

  ## Supported settings

  The possible settings that can be retrieved are described in `t:setting/0`.
  Any other atom passed as `name` will raise an error.

  ## Examples

      Mint.HTTP2.get_server_setting(conn, :max_concurrent_streams)
      #=> 500

  """
  @spec get_server_setting(t(), atom()) :: term()
  def get_server_setting(%Mint.HTTP2{} = conn, name) when is_atom(name) do
    get_setting(conn.server_settings, name)
  end

  @doc """
  Gets the value of the given HTTP/2 client setting.

  This function returns the value of the given HTTP/2 setting that the client
  advertised to the server. Client settings can be advertised through `put_settings/2`
  or when starting up a connection.

  Client settings have to be acknowledged by the server before coming into effect.

  This function is HTTP/2 specific. For more information on HTTP/2 settings, see
  [the related section in the RFC](https://http2.github.io/http2-spec/#rfc.section.6.5.2).

  See the "HTTP/2 settings" section in the module documentation for more information.

  ## Supported settings

  The possible settings that can be retrieved are described in `t:setting/0`.
  Any other atom passed as `name` will raise an error.

  ## Examples

      Mint.HTTP2.get_client_setting(conn, :max_concurrent_streams)
      #=> 500

  """
  @spec get_client_setting(t(), atom()) :: term()
  def get_client_setting(%Mint.HTTP2{} = conn, name) when is_atom(name) do
    get_setting(conn.client_settings, name)
  end

  defp get_setting(settings, name) do
    case Map.fetch(settings, name) do
      {:ok, value} -> value
      :error -> raise ArgumentError, "unknown HTTP/2 setting: #{inspect(name)}"
    end
  end

  @doc """
  Cancels an in-flight request.

  This function is HTTP/2 specific. It cancels an in-flight request. The server could have
  already sent responses for the request you want to cancel: those responses will be parsed
  by the connection but not returned to the user. No more responses
  to a request will be returned after you call `cancel_request/2` on that request.

  If there's no error in canceling the request, `{:ok, conn}` is returned where `conn` is
  the updated connection. If there's an error, `{:error, conn, reason}` is returned where
  `conn` is the updated connection and `reason` is the error reason.

  ## Examples

      {:ok, conn, ref} = Mint.HTTP2.request(conn, "GET", "/", _headers = [])
      {:ok, conn} = Mint.HTTP2.cancel_request(conn, ref)

  """
  if Version.match?(System.version(), ">= 1.7.0") do
    @doc since: "0.2.0"
  end

  @spec cancel_request(t(), Types.request_ref()) :: {:ok, t()} | {:error, t(), term()}
  def cancel_request(%Mint.HTTP2{} = conn, request_ref) when is_reference(request_ref) do
    case Map.fetch(conn.ref_to_stream_id, request_ref) do
      {:ok, stream_id} ->
        conn = close_stream!(conn, stream_id, _error_code = :cancel)
        {:ok, conn}

      :error ->
        {:ok, conn}
    end
  catch
    :throw, {:mint, conn, error} -> {:error, conn, error}
  end

  @doc """
  See `Mint.HTTP.stream/2`.
  """
  @impl true
  @spec stream(t(), term()) ::
          {:ok, t(), [Types.response()]}
          | {:error, t(), term(), [Types.response()]}
          | :unknown
  def stream(conn, message)

  def stream(%Mint.HTTP2{socket: socket} = conn, {tag, socket, reason})
      when tag in [:tcp_error, :ssl_error] do
    {:error, %{conn | state: :closed}, reason, _responses = []}
  end

  def stream(%Mint.HTTP2{socket: socket} = conn, {tag, socket})
      when tag in [:tcp_closed, :ssl_closed] do
    {:error, %{conn | state: :closed}, :closed, _responses = []}
  end

  def stream(%Mint.HTTP2{transport: transport, socket: socket} = conn, {tag, socket, data})
      when tag in [:tcp, :ssl] do
    {conn, responses} = handle_new_data(conn, conn.buffer <> data, [])
    _ = transport.setopts(socket, active: :once)
    {:ok, conn, Enum.reverse(responses)}
  catch
    :throw, {:mint, conn, error, responses} -> {:error, conn, error, responses}
  end

  def stream(%Mint.HTTP2{}, _message) do
    :unknown
  end

  @doc """
  See `Mint.HTTP.put_private/3`.
  """
  @impl true
  @spec put_private(t(), atom(), term()) :: t()
  def put_private(%Mint.HTTP2{private: private} = conn, key, value) when is_atom(key) do
    %{conn | private: Map.put(private, key, value)}
  end

  @doc """
  See `Mint.HTTP.get_private/3`.
  """
  @impl true
  @spec get_private(t(), atom(), term()) :: term()
  def get_private(%Mint.HTTP2{private: private} = _conn, key, default \\ nil) when is_atom(key) do
    Map.get(private, key, default)
  end

  @doc """
  See `Mint.HTTP.delete_private/2`.
  """
  @impl true
  @spec delete_private(t(), atom()) :: t()
  def delete_private(%Mint.HTTP2{private: private} = conn, key) when is_atom(key) do
    %{conn | private: Map.delete(private, key)}
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  # SETTINGS parameters are not negotiated. We keep client settings and server settings separate.
  @doc false
  @impl true
  @spec initiate(
          Types.scheme(),
          Mint.Core.Transport.socket(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def initiate(scheme, socket, hostname, port, opts) do
    transport = scheme_to_transport(scheme)
    client_settings_params = Keyword.get(opts, :client_settings, [])
    validate_settings!(client_settings_params)

    conn = %Mint.HTTP2{
      hostname: hostname,
      port: port,
      transport: scheme_to_transport(scheme),
      socket: socket,
      scheme: Atom.to_string(scheme),
      state: :open
    }

    with :ok <- inet_opts(transport, socket),
         client_settings = settings(stream_id: 0, params: client_settings_params),
         preface = [@connection_preface, Frame.encode(client_settings)],
         :ok <- transport.send(socket, preface),
         conn = update_in(conn.client_settings_queue, &:queue.in(client_settings_params, &1)),
         {:ok, server_settings, buffer, socket} <- receive_server_settings(transport, socket),
         server_settings_ack =
           settings(stream_id: 0, params: [], flags: set_flags(:settings, [:ack])),
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
  See `Mint.HTTP.get_socket/1`.
  """
  @impl true
  @spec get_socket(t()) :: Mint.Core.Transport.socket()
  def get_socket(%Mint.HTTP2{socket: socket} = _conn) do
    socket
  end

  ## Helpers

  defp negotiate(hostname, port, scheme, transport_opts) do
    transport = scheme_to_transport(scheme)

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

  defp open_stream(conn) do
    max_concurrent_streams = conn.server_settings.max_concurrent_streams

    if conn.open_stream_count >= max_concurrent_streams do
      throw({:mint, conn, {:max_concurrent_streams_reached, max_concurrent_streams}})
    end

    stream = %{
      id: conn.next_stream_id,
      ref: make_ref(),
      state: :idle,
      window_size: conn.server_settings.initial_window_size
    }

    conn = put_in(conn.streams[stream.id], stream)
    conn = put_in(conn.ref_to_stream_id[stream.ref], stream.id)
    conn = update_in(conn.next_stream_id, &(&1 + 2))
    {conn, stream.id, stream.ref}
  end

  defp send_headers(conn, stream_id, headers, enabled_flags) do
    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:idle])
    assert_headers_smaller_than_max_header_list_size(conn, headers)

    headers = Enum.map(headers, fn {name, value} -> {:store_name, name, value} end)
    {hbf, conn} = get_and_update_in(conn.encode_table, &HPACK.encode(headers, &1))

    payload = headers_to_encoded_frames(conn, stream_id, hbf, enabled_flags)
    conn = send!(conn, payload)

    stream_state = if :end_stream in enabled_flags, do: :half_closed_local, else: :open

    conn = put_in(conn.streams[stream_id].state, stream_state)
    conn = update_in(conn.open_stream_count, &(&1 + 1))
    conn
  end

  defp assert_headers_smaller_than_max_header_list_size(
         %{server_settings: %{max_header_list_size: :infinity}},
         _headers
       ) do
    :ok
  end

  defp assert_headers_smaller_than_max_header_list_size(conn, headers) do
    # The value is based on the uncompressed size of header fields, including the length
    # of the name and value in octets plus an overhead of 32 octets for each header field.
    total_size =
      Enum.reduce(headers, 0, fn {name, value}, acc ->
        acc + byte_size(name) + byte_size(value) + 32
      end)

    if total_size <= conn.server_settings.max_header_list_size do
      :ok
    else
      throw({:mint, conn, :max_header_list_size_exceeded})
    end
  end

  defp headers_to_encoded_frames(conn, stream_id, hbf, enabled_flags) do
    if IO.iodata_length(hbf) > conn.server_settings.max_frame_size do
      hbf
      |> IO.iodata_to_binary()
      |> split_payload_in_chunks(conn.server_settings.max_frame_size)
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
        set_flags(:continuation, [:end_headers])
      else
        set_flags(:continuation, [])
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
        throw({:mint, conn, {:exceeds_stream_window_size, stream.window_size}})

      data_size >= conn.window_size ->
        throw({:mint, conn, {:exceeds_connection_window_size, conn.window_size}})

      data_size > conn.server_settings.max_frame_size ->
        {chunks, last_chunk} =
          data
          |> IO.iodata_to_binary()
          |> split_payload_in_chunks(conn.server_settings.max_frame_size)

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
        unless is_boolean(value) do
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

  defp add_default_headers(headers) do
    Util.put_new_header(headers, "user-agent", @user_agent)
  end

  ## Frame handling

  defp handle_new_data(%Mint.HTTP2{} = conn, data, responses) do
    case Frame.decode_next(data, conn.client_settings.max_frame_size) do
      {:ok, frame, rest} ->
        _ = Logger.debug(fn -> "Got frame: #{inspect(frame)}" end)
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
    :throw, {:mint, conn, error} -> throw({:mint, conn, error, responses})
    :throw, {:mint, conn, error, responses} -> throw({:mint, conn, error, responses})
  end

  defp assert_valid_frame(conn, frame) do
    stream_id = elem(frame, 1)

    assert_frame_on_right_level(conn, elem(frame, 0), stream_id)
    assert_stream_id_is_allowed(conn, stream_id)
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

  defp assert_frame_on_right_level(conn, frame, _stream_id = 0)
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

  defp assert_stream_id_is_allowed(conn, stream_id) do
    if Integer.is_odd(stream_id) and stream_id >= conn.next_stream_id do
      debug_data = "frame with stream ID #{inspect(stream_id)} has not been opened yet"
      send_connection_error!(conn, :protocol_error, debug_data)
    else
      :ok
    end
  end

  for frame_name <- stream_level_frames ++ connection_level_frames ++ [:window_update] do
    function_name = :"handle_#{frame_name}"

    defp handle_frame(conn, Frame.unquote(frame_name)() = frame, responses) do
      unquote(function_name)(conn, frame, responses)
    end
  end

  # DATA

  defp handle_data(conn, frame, responses) do
    data(stream_id: stream_id, flags: flags, data: data, padding: padding) = frame

    # Regardless of whether we have the stream or not, we need to abide by flow
    # control rules so we still refill the client window for the stream_id we got.
    window_size_increment = byte_size(data) + byte_size(padding || "")
    conn = refill_client_windows(conn, stream_id, window_size_increment)

    case Map.fetch(conn.streams, stream_id) do
      {:ok, stream} ->
        assert_stream_in_state(conn, stream, [:open, :half_closed_local])
        responses = [{:data, stream.ref, data} | responses]

        if flag_set?(flags, :data, :end_stream) do
          conn = close_stream!(conn, stream.id, :no_error)
          {conn, [{:done, stream.ref} | responses]}
        else
          {conn, responses}
        end

      :error ->
        _ = Logger.debug(fn -> "Received DATA frame on closed stream ID #{stream_id}" end)
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

    stream = Map.get(conn.streams, stream_id)
    end_stream? = flag_set?(flags, :headers, :end_stream)

    if stream do
      assert_stream_in_state(conn, stream, [:open, :half_closed_local, :reserved_remote])
    end

    if flag_set?(flags, :headers, :end_headers) do
      decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?)
    else
      callback = &decode_hbf_and_add_responses(&1, &2, &3, &4, end_stream?)
      conn = put_in(conn.headers_being_processed, {stream_id, hbf, callback})
      {conn, responses}
    end
  end

  # Here, "stream" can be nil in case the stream was closed. In that case, we
  # still need to process the hbf so that the HPACK table is updated, but then
  # we don't add any responses.
  defp decode_hbf_and_add_responses(conn, responses, hbf, stream, end_stream?) do
    case decode_hbf(conn, hbf) do
      {conn, [{":status", status} | headers]} when not is_nil(stream) ->
        ref = stream.ref
        status = String.to_integer(status)
        new_responses = [{:headers, ref, headers}, {:status, ref, status} | responses]

        cond do
          end_stream? ->
            conn = close_stream!(conn, stream.id, :no_error)
            {conn, [{:done, ref} | new_responses]}

          # If this was a promised stream, it goes in the :half_closed_local state as
          # soon as it receives headers. We cannot send any frames other than
          # WINDOW_UPDATE, PRIORITY, or RST_STREAM in the :half_closed_local state.
          stream.state == :reserved_remote ->
            conn = put_in(conn.streams[stream.id].state, :half_closed_local)
            {conn, new_responses}

          true ->
            {conn, new_responses}
        end

      # http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.6
      {conn, _headers} when not is_nil(stream) ->
        conn = close_stream!(conn, stream.id, :protocol_error)
        responses = [{:error, stream.ref, {:protocol_error, :missing_status_header}} | responses]
        {conn, responses}

      {conn, _headers} when is_nil(stream) ->
        _ = Logger.debug(fn -> "Received HEADERS frame on closed stream ID" end)
        {conn, responses}
    end
  end

  defp decode_hbf(conn, hbf) do
    case HPACK.decode(hbf, conn.decode_table) do
      {:ok, headers, decode_table} ->
        conn = put_in(conn.decode_table, decode_table)
        {conn, headers}

      {:error, reason} ->
        debug_data = "unable to decode headers: #{inspect(reason)}"
        send_connection_error!(conn, :compression_error, debug_data)
    end
  end

  # PRIORITY

  # For now we ignore all PRIORITY frames. This shouldn't cause practical trouble.
  defp handle_priority(conn, frame, responses) do
    _ = Logger.warn(fn -> "Ignoring PRIORITY frame: #{inspect(frame)}" end)
    {conn, responses}
  end

  # RST_STREAM

  # If we receive RST_STREAM on a closed stream, we ignore it.
  defp handle_rst_stream(conn, frame, responses) do
    rst_stream(stream_id: stream_id, error_code: error_code) = frame

    case Map.fetch(conn.streams, stream_id) do
      {:ok, stream} ->
        # If we receive RST_STREAM then the stream is definitely closed.
        # We won't send anything else on the stream so we can simply delete
        # it, so that if we get things like DATA on that stream we error out.
        conn = delete_stream(conn, stream)

        # TODO: is this an error?
        response = {:error, stream.ref, {:rst_stream, error_code}}
        {conn, [response | responses]}

      :error ->
        {conn, responses}
    end
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
      frame = settings(flags: set_flags(:settings, [:ack]), params: [])
      conn = send!(conn, Frame.encode(frame))
      {conn, responses}
    end
  end

  defp apply_server_settings(conn, server_settings) do
    Enum.reduce(server_settings, conn, fn
      {:header_table_size, header_table_size}, conn ->
        update_in(conn.encode_table, &HPACK.resize(&1, header_table_size))

      {:enable_push, enable_push?}, conn ->
        put_in(conn.server_settings.enable_push, enable_push?)

      {:max_concurrent_streams, max_concurrent_streams}, conn ->
        put_in(conn.server_settings.max_concurrent_streams, max_concurrent_streams)

      {:initial_window_size, initial_window_size}, conn ->
        if initial_window_size > @max_window_size do
          debug_data = "INITIAL_WINDOW_SIZE setting parameter is too big"
          send_connection_error!(conn, :flow_control_error, debug_data)
        end

        update_server_initial_window_size(conn, initial_window_size)

      {:max_frame_size, max_frame_size}, conn ->
        if max_frame_size not in @valid_max_frame_size_range do
          debug_data = "MAX_FRAME_SIZE setting parameter outside of allowed range"
          send_connection_error!(conn, :protocol_error, debug_data)
        end

        put_in(conn.server_settings.max_frame_size, max_frame_size)

      {:max_header_list_size, max_header_list_size}, conn ->
        put_in(conn.server_settings.max_header_list_size, max_header_list_size)
    end)
  end

  defp apply_client_settings(conn, client_settings) do
    Enum.reduce(client_settings, conn, fn
      {:max_frame_size, value}, conn ->
        put_in(conn.client_settings.max_frame_size, value)

      {:max_concurrent_streams, value}, conn ->
        put_in(conn.client_settings.max_concurrent_streams, value)

      {:enable_push, value}, conn ->
        put_in(conn.client_settings.enable_push, value)
    end)
  end

  defp update_server_initial_window_size(conn, new_iws) do
    diff = new_iws - conn.server_settings.initial_window_size

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

    put_in(conn.server_settings.initial_window_size, new_iws)
  end

  # PUSH_PROMISE

  defp handle_push_promise(
         %Mint.HTTP2{client_settings: %{enable_push: false}} = conn,
         push_promise(),
         _responses
       ) do
    debug_data = "received PUSH_PROMISE frame when SETTINGS_ENABLE_PUSH was false"
    send_connection_error!(conn, :protocol_error, debug_data)
  end

  defp handle_push_promise(conn, push_promise() = frame, responses) do
    push_promise(
      stream_id: stream_id,
      flags: flags,
      promised_stream_id: promised_stream_id,
      hbf: hbf
    ) = frame

    # TODO: improve this by checking that the promised_stream_id is not in use or has been used
    # before.
    unless promised_stream_id > 0 and Integer.is_even(promised_stream_id) do
      debug_data = "invalid promised stream ID: #{inspect(promised_stream_id)}"
      send_connection_error!(conn, :protocol_error, debug_data)
    end

    stream = fetch_stream!(conn, stream_id)
    assert_stream_in_state(conn, stream, [:open, :half_closed_local])

    if flag_set?(flags, :push_promise, :end_headers) do
      decode_push_promise_headers_and_add_response(
        conn,
        responses,
        hbf,
        stream,
        promised_stream_id
      )
    else
      callback = &decode_push_promise_headers_and_add_response(&1, &2, &3, &4, promised_stream_id)
      conn = put_in(conn.headers_being_processed, {stream_id, hbf, callback})
      {conn, responses}
    end
  end

  defp decode_push_promise_headers_and_add_response(
         conn,
         responses,
         hbf,
         stream,
         promised_stream_id
       ) do
    {conn, headers} = decode_hbf(conn, hbf)

    promised_stream = %{
      id: promised_stream_id,
      ref: make_ref(),
      state: :reserved_remote,
      window_size: conn.server_settings.initial_window_size
    }

    conn = put_in(conn.streams[promised_stream.id], promised_stream)
    new_response = {:push_promise, stream.ref, promised_stream.ref, headers}
    {conn, [new_response | responses]}
  end

  # PING

  defp handle_ping(conn, Frame.ping() = frame, responses) do
    Frame.ping(flags: flags, opaque_data: opaque_data) = frame

    if flag_set?(flags, :ping, :ack) do
      handle_ping_ack(conn, opaque_data, responses)
    else
      ack = Frame.ping(stream_id: 0, flags: set_flags(:ping, [:ack]), opaque_data: opaque_data)
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
        _ = Logger.error("Received PING ack that doesn't match next PING request in the queue")
        throw({:mint, conn, :protocol_error, responses})

      {:empty, _ping_queue} ->
        _ = Logger.error("Received PING ack but no PING requests had been sent")
        throw({:mint, conn, :protocol_error, responses})
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
    new_window_size = conn.window_size + wsi

    if new_window_size > @max_window_size do
      send_connection_error!(conn, :flow_control_error, "window size too big")
    else
      conn = put_in(conn.window_size, new_window_size)
      {conn, responses}
    end
  end

  defp handle_window_update(
         conn,
         window_update(stream_id: stream_id, window_size_increment: wsi),
         responses
       ) do
    stream = fetch_stream!(conn, stream_id)
    new_window_size = conn.streams[stream_id].window_size + wsi

    if new_window_size > @max_window_size do
      conn = close_stream!(conn, stream_id, :flow_control_error)
      {conn, [{:error, stream.ref, :flow_control_error} | responses]}
    else
      conn = put_in(conn.streams[stream_id].window_size, new_window_size)
      {conn, responses}
    end
  end

  # CONTINUATION

  defp handle_continuation(conn, frame, responses) do
    continuation(stream_id: stream_id, flags: flags, hbf: hbf_chunk) = frame
    stream = Map.get(conn.streams, stream_id)

    if stream do
      assert_stream_in_state(conn, stream, [:open, :half_closed_local, :reserved_remote])
    end

    {^stream_id, hbf_acc, callback} = conn.headers_being_processed

    if flag_set?(flags, :continuation, :end_headers) do
      hbf = IO.iodata_to_binary([hbf_acc, hbf_chunk])
      conn = put_in(conn.headers_being_processed, nil)
      callback.(conn, responses, hbf, stream)
    else
      conn = put_in(conn.headers_being_processed, {stream_id, [hbf_acc, hbf_chunk], callback})
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
    throw({:mint, conn, error_code})
  end

  defp close_stream!(conn, stream_id, error_code) do
    stream = Map.fetch!(conn.streams, stream_id)

    # First of all we send a RST_STREAM with the given error code so that we
    # move the stream to the :closed state (that is, we remove it).
    rst_stream_frame = rst_stream(stream_id: stream_id, error_code: error_code)
    conn = send!(conn, Frame.encode(rst_stream_frame))

    delete_stream(conn, stream)
  end

  defp delete_stream(conn, stream) do
    conn = update_in(conn.open_stream_count, &(&1 - 1))
    conn = update_in(conn.streams, &Map.delete(&1, stream.id))
    conn = update_in(conn.ref_to_stream_id, &Map.delete(&1, stream.ref))
    conn
  end

  defp fetch_stream!(conn, stream_id) do
    case Map.fetch(conn.streams, stream_id) do
      {:ok, stream} -> stream
      :error -> throw({:mint, conn, {:stream_not_found, stream_id}})
    end
  end

  defp assert_stream_in_state(conn, %{state: state}, expected_states) do
    if state not in expected_states do
      throw({:mint, conn, {:stream_not_in_expected_state, expected_states, state}})
    end
  end

  defp send!(%Mint.HTTP2{transport: transport, socket: socket} = conn, bytes) do
    case transport.send(socket, bytes) do
      :ok -> conn
      {:error, :closed} -> throw({:mint, %{conn | state: :closed}, :closed})
      {:error, reason} -> throw({:mint, conn, reason})
    end
  end
end
