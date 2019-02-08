defmodule Mint.HTTP1 do
  @moduledoc """
  Processless HTTP client with support for HTTP/1 and HTTP/1.1.

  This module provides a data structure that represents an HTTP/1 or HTTP/1.1 connection to
  a given server. The connection is represented as an opaque struct `%Mint.HTTP1{}`.
  The connection is a data structure and is not backed by a process, and all the
  connection handling happens in the process that creates the struct.

  This module and data structure work exactly like the ones described in the `Mint`
  module, with the exception that `Mint.HTTP1` specifically deals with HTTP/1 and HTTP/1.1 while
  `Mint` deals seamlessly with HTTP/1, HTTP/1.1, and HTTP/2. For more information on
  how to use the data structure and client architecture, see `Mint`.
  """

  import Mint.Core.Util

  alias Mint.HTTP1.{Parse, Request, Response}

  require Logger

  @behaviour Mint.Core.Conn

  @opaque t() :: %__MODULE__{}

  @type scheme :: :http | :https | module()
  @type request_ref() :: Mint.Core.Conn.request_ref()
  @type socket_message() :: Mint.Core.Conn.socket_message()
  @type response() :: Mint.Core.Conn.response()
  @type status() :: Mint.Core.Conn.response()
  @type headers() :: Mint.Core.Conn.headers()

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
  Same as `Mint.HTTP.connect/4`, but forces an HTTP/1 or HTTP/1.1 connection.

  This function doesn't support proxying.
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
          Mint.Core.Transport.socket(),
          scheme(),
          String.t(),
          :inet.port_number(),
          keyword()
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
          Mint.Core.Transport.socket(),
          String.t(),
          :inet.port_number(),
          keyword()
        ) :: {:ok, t()} | {:error, term()}
  def initiate(transport, socket, hostname, _port, _opts) do
    with :ok <- inet_opts(transport, socket),
         :ok <- transport.setopts(socket, active: :once) do
      conn = %__MODULE__{
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
  See `Mint.HTTP.open?/1`.
  """
  @impl true
  @spec open?(t()) :: boolean()
  def open?(%__MODULE__{state: state}), do: state == :open

  @doc """
  See `Mint.HTTP.request/5`.

  In HTTP/1 and HTTP/1.1, you can't open a new request if you're streaming the body of
  another request. If you try, the error reason `{:error, :request_body_is_streaming}` is
  returned.
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

  def request(
        %__MODULE__{request: %{state: :stream_request}} = conn,
        _method,
        _path,
        _headers,
        _body
      ) do
    {:error, conn, :request_body_is_streaming}
  end

  def request(%__MODULE__{} = conn, method, path, headers, body) do
    %__MODULE__{host: host, transport: transport, socket: socket} = conn
    iodata = Request.encode(method, path, host, headers, body || "")

    case transport.send(socket, iodata) do
      :ok ->
        request_ref = make_ref()
        state = if body == :stream, do: :stream_request, else: :status
        request = new_request(request_ref, state, method)

        if conn.request == nil do
          conn = %__MODULE__{conn | request: request}
          {:ok, conn, request_ref}
        else
          requests = :queue.in(request, conn.requests)
          conn = %__MODULE__{conn | requests: requests}
          {:ok, conn, request_ref}
        end

      {:error, :closed} ->
        {:error, %{conn | state: :closed}, :closed}

      {:error, reason} ->
        {:error, conn, reason}
    end
  catch
    :throw, {:mint, reason} ->
      {:error, conn, reason}
  end

  @doc """
  See `Mint.HTTP.stream_request_body/3`.
  """
  @impl true
  @spec stream_request_body(t(), request_ref(), iodata() | :eof) ::
          {:ok, t()} | {:error, t(), term()}
  def stream_request_body(
        %__MODULE__{request: %{state: :stream_request, ref: ref}} = conn,
        ref,
        :eof
      ) do
    {:ok, put_in(conn.request.state, :status)}
  end

  def stream_request_body(
        %__MODULE__{request: %{state: :stream_request, ref: ref}} = conn,
        ref,
        body
      ) do
    case conn.transport.send(conn.socket, body) do
      :ok -> {:ok, conn}
      {:error, :closed} -> {:error, %{conn | state: :closed}, :closed}
      {:error, reason} -> {:error, conn, reason}
    end
  end

  @doc """
  See `Mint.HTTP.stream/2`.
  """
  @impl true
  @spec stream(t(), socket_message()) ::
          {:ok, t(), [response()]}
          | {:error, t(), term(), [response()]}
          | :unknown
  def stream(conn, message)

  def stream(%__MODULE__{request: %{state: :stream_request}} = conn, _message) do
    # TODO: Close connection
    {:error, conn, :request_body_not_streamed, []}
  end

  def stream(%__MODULE__{transport: transport, socket: socket} = conn, {tag, socket, data})
      when tag in [:tcp, :ssl] do
    result = handle_data(conn, data)
    _ = transport.setopts(socket, active: :once)
    result
  end

  def stream(%__MODULE__{socket: socket} = conn, {tag, socket})
      when tag in [:tcp_closed, :ssl_closed] do
    handle_close(conn)
  end

  def stream(%__MODULE__{socket: socket} = conn, {tag, socket, reason})
      when tag in [:tcp_error, :ssl_error] do
    handle_error(conn, reason)
  end

  def stream(%__MODULE__{}, _message) do
    :unknown
  end

  defp handle_data(%__MODULE__{request: nil} = conn, data) do
    # TODO: Figure out if we should keep buffering even though there are no
    # requests in flight
    {:ok, put_in(conn.buffer, conn.buffer <> data), []}
  end

  defp handle_data(%__MODULE__{request: request} = conn, data) do
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

  defp handle_close(%__MODULE__{request: request} = conn) do
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
  See `Mint.HTTP.put_private/3`.
  """
  @impl true
  @spec put_private(t(), atom(), term()) :: t()
  def put_private(%__MODULE__{private: private} = conn, key, value) when is_atom(key) do
    %{conn | private: Map.put(private, key, value)}
  end

  @doc """
  See `Mint.HTTP.get_private/3`.
  """
  @impl true
  @spec get_private(t(), atom(), term()) :: term()
  def get_private(%__MODULE__{private: private} = _conn, key, default \\ nil) when is_atom(key) do
    Map.get(private, key, default)
  end

  @doc """
  See `Mint.HTTP.delete_private/2`.
  """
  @impl true
  @spec delete_private(t(), atom()) :: t()
  def delete_private(%__MODULE__{private: private} = conn, key) when is_atom(key) do
    %{conn | private: Map.delete(private, key)}
  end

  @doc """
  See `Mint.HTTP.get_socket/1`.
  """
  @impl true
  @spec get_socket(t()) :: Mint.Core.Transport.socket()
  def get_socket(%__MODULE__{socket: socket} = _conn) do
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
