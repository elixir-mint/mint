defmodule Mint.HTTP2Test do
  use ExUnit.Case, async: true

  import Mint.HTTP2.Frame, except: [inspect: 1]
  import ExUnit.CaptureLog
  import Mox

  alias Mint.{
    Core.Transport,
    HTTPError,
    HTTP2,
    HTTP2.Frame,
    HTTP2.TestServer,
    TransportError
  }

  require Mint.HTTP

  @moduletag :capture_log

  @recv_timeout 300
  @server_pdict_key {__MODULE__, :http2_test_server}

  setup :start_server_async
  setup :maybe_change_default_scheme_port
  setup :start_connection
  setup :maybe_set_transport_mock

  defmacrop assert_recv_frames([]) do
    quote do
      receive do
        {:ssl, _socket, data} ->
          result = Mint.HTTP2.Frame.decode_next(data)
          flunk("Expected no frames, but got data that decodes to: #{inspect(result)}")
      after
        100 -> :ok
      end
    end
  end

  defmacrop assert_recv_frames(frames) when is_list(frames) do
    quote do: unquote(frames) = recv_next_frames(unquote(length(frames)))
  end

  defmacrop assert_http2_error(error, expected_reason) do
    quote do
      error = unquote(error)

      assert %HTTPError{reason: unquote(expected_reason)} = error

      message = Exception.message(error)
      refute message =~ "got FunctionClauseError"
      assert message != inspect(error.reason)
    end
  end

  defmacrop assert_transport_error(error, expected_reason) do
    quote do
      error = unquote(error)

      assert %TransportError{reason: unquote(expected_reason)} = error

      message = Exception.message(error)
      refute message =~ "got FunctionClauseError"
      assert message != inspect(error.reason)
    end
  end

  describe "Mint.HTTP.is_connection_message/2" do
    test "the guard works with HTTP2 connections", %{conn: conn} do
      import Mint.HTTP, only: [is_connection_message: 2]

      assert is_connection_message(conn, {:tcp, conn.socket, "foo"}) == true
      assert is_connection_message(conn, {:tcp_closed, conn.socket}) == true
      assert is_connection_message(conn, {:tcp_error, conn.socket, :nxdomain}) == true

      assert is_connection_message(conn, {:tcp, :not_a_socket, "foo"}) == false
      assert is_connection_message(conn, {:tcp_closed, :not_a_socket}) == false

      assert is_connection_message(_conn = %HTTP2{}, {:tcp, conn.socket, "foo"}) == false

      # If the first argument is not a connection struct, we return false.
      assert is_connection_message(%{socket: conn.socket}, {:tcp, conn.socket, "foo"}) == false
      assert is_connection_message(%URI{}, {:tcp, conn.socket, "foo"}) == false
    end
  end

  describe "performing the initial handshake" do
    @tag :no_connection
    test "client deals with server sending GOAWAY as the first frame",
         %{server_port: port, server_socket_task: server_socket_task} do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", port,
                 transport_opts: [verify: :verify_none],
                 mode: :passive
               )

      assert {:ok, server_socket} = Task.await(server_socket_task)
      assert :ok = TestServer.perform_http2_handshake(server_socket)
      # :ok = :ssl.setopts(server_socket, active: true)

      frame = goaway(last_stream_id: 0, error_code: :internal_error, debug_data: "Some error")
      :ok = :ssl.send(server_socket, [Frame.encode(frame)])

      # :ping ->
      #   frame = ping(opaque_data: :binary.copy(<<0>>, 8))
      #   :ok = :ssl.send(server_socket, [Frame.encode(frame)])
      #   conn

      assert {:error, conn, error, _responses = []} = HTTP2.recv(conn, 0, 1000)
      assert_http2_error error, {:server_closed_connection, :internal_error, "Some error"}
      refute HTTP2.open?(conn)
    end

    @tag :no_connection
    test "client deals with server sending PING as the first frame",
         %{server_port: port, server_socket_task: server_socket_task} do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", port,
                 transport_opts: [verify: :verify_none],
                 mode: :passive
               )

      assert {:ok, server_socket} = Task.await(server_socket_task)
      assert :ok = TestServer.perform_http2_handshake(server_socket)

      frame = ping(opaque_data: :binary.copy(<<0>>, 8))
      :ok = :ssl.send(server_socket, [Frame.encode(frame)])

      assert {:error, conn, error, _responses = []} = HTTP2.recv(conn, 0, 1000)
      assert_http2_error error, {:protocol_error, "received invalid frame ping during handshake"}
      refute HTTP2.open?(conn)
    end
  end

  describe "open?/1" do
    test "returns true if the state is :open or :handshaking", %{conn: conn} do
      assert HTTP2.open?(%{conn | state: :open})
      assert HTTP2.open?(%{conn | state: :handshaking})
    end
  end

  describe "connect/4" do
    @describetag :no_connection

    test "raises an error if the :log option is not a boolean", %{server_port: port} do
      message = "the :log option must be a boolean, got: \"not a boolean\""

      assert_raise ArgumentError, message, fn ->
        HTTP2.connect(:https, "localhost", port,
          log: "not a boolean",
          transport_opts: [verify: :verify_none]
        )
      end
    end

    test "raises an error if the :mode option is not :active or :passive", %{server_port: port} do
      message = "the :mode option must be either :active or :passive, got: :invalid"

      assert_raise ArgumentError, message, fn ->
        HTTP2.connect(:https, "localhost", port,
          mode: :invalid,
          transport_opts: [verify: :verify_none]
        )
      end
    end

    test "closes the transport socket if anything goes wrong during the setup",
         %{server_port: port} do
      {:ok, socket} = :ssl.connect(~c"localhost", port, verify: :verify_none)

      TransportMock
      |> expect(:getopts, fn ^socket, _opts -> {:error, Transport.SSL.wrap_error(:einval)} end)
      |> expect(:close, fn ^socket -> :ok end)

      assert {:error, error} = HTTP2.initiate(TransportMock, socket, "localhost", port, [])
      assert_transport_error error, :einval
    end

    test "bubbles up errors returned by negotiate/4" do
      assert {:error, error} = HTTP2.connect(:http, "localhost", 65_535)
      assert_transport_error error, :econnrefused
    end
  end

  describe "handling unknown frames from the server" do
    test "handle origin frame from the server", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      origin_payload =
        Base.decode16!("001c68747470733a2f2f6472616e642e636c6f7564666c6172652e636f6d",
          case: :lower
        )

      frame = HTTP2.Frame.encode_raw(12, 0, 0, origin_payload)

      {:ok, conn, responses} =
        HTTP2.stream(
          conn,
          {:ssl, conn.socket, IO.iodata_to_binary(frame)}
        )

      assert responses == []

      hbf = server_encode_headers([{":status", "200"}])

      assert {:ok, %HTTP2{} = _conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers, :end_stream])
                 )
               ])

      assert responses == [
               {:status, ref, 200},
               {:headers, ref, []},
               {:done, ref}
             ]

      assert HTTP2.open?(conn)
    end
  end

  describe "stream/2 with unknown messages or error messages" do
    test "unknown message", %{conn: conn} do
      assert HTTP2.stream(conn, :unknown_message) == :unknown
    end

    test "socket error messages are treated as errors", %{conn: conn} do
      message = {:ssl_error, conn.socket, :etimeout}

      assert {:error, %HTTP2{} = conn, %TransportError{reason: :etimeout}, []} =
               HTTP2.stream(conn, message)

      refute HTTP2.open?(conn)
    end
  end

  describe "closed streams" do
    test "server closes a stream with RST_STREAM", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 rst_stream(stream_id: stream_id, error_code: :protocol_error)
               ])

      assert [{:error, ^ref, error}] = responses
      assert_http2_error error, {:server_closed_request, :protocol_error}

      assert HTTP2.open?(conn)
    end

    test "when server sends frames after sending RST_STREAM, they are ignored",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 rst_stream(stream_id: stream_id, error_code: :cancel),
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert [{:error, ^ref, error}] = responses
      assert_http2_error error, {:server_closed_request, :cancel}

      assert HTTP2.open?(conn)
    end

    test "client closes a stream with cancel_request/2", %{conn: conn} do
      {conn, ref} = open_request(conn)
      {:ok, conn} = HTTP2.cancel_request(conn, ref)

      assert_recv_frames [
        headers(stream_id: stream_id),
        rst_stream(stream_id: stream_id, error_code: :cancel)
      ]

      # If the server replies next, we ignore the replies.
      assert {:ok, %HTTP2{} = conn, []} =
               stream_frames(conn, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers]},
                 data(stream_id: stream_id, data: "hello", flags: set_flags(:data, [:end_stream]))
               ])

      assert HTTP2.open?(conn)
    end

    @tag :with_transport_mock
    test "cancel_request/2 bubbles up errors", %{conn: conn} do
      stub_with(TransportMock, Transport.SSL)

      {conn, ref} = open_request(conn)

      expect(TransportMock, :send, fn _socket, _data ->
        {:error, Transport.SSL.wrap_error(:einval)}
      end)

      assert {:error, %HTTP2{} = conn, error} = HTTP2.cancel_request(conn, ref)
      assert_transport_error error, :einval
      assert HTTP2.open?(conn)
    end

    test "client closes a non-existent request with cancel_request/2", %{conn: conn} do
      assert {:ok, ^conn} = HTTP2.cancel_request(conn, make_ref())
    end

    test "receiving a RST_STREAM on a closed stream is ignored", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert Enum.empty?(conn.streams)

      assert {:ok, %HTTP2{} = conn, []} =
               stream_frames(conn, [
                 rst_stream(stream_id: stream_id, error_code: :no_error),
                 rst_stream(stream_id: stream_id, error_code: :no_error)
               ])

      assert HTTP2.open?(conn)
    end

    test "doesn't send RST_STREAM when stream is declared ended in both sides", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert conn.streams[stream_id].state == :half_closed_local

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert_recv_frames([])
      assert is_nil(conn.streams[stream_id])
      assert HTTP2.open?(conn)
    end
  end

  describe "stream state transitions" do
    test "if client receives HEADERS after receiving a END_STREAM flag, it ignores it",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]},
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert HTTP2.open?(conn)
    end

    test "if client receives DATA after receiving a END_STREAM flag, it ignores it",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]},
                 data(stream_id: stream_id, data: "hello", flags: set_flags(:data, [:end_stream]))
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert HTTP2.open?(conn)
    end
  end

  describe "server closes the connection" do
    test "with GOAWAY with :protocol_error", %{conn: conn} do
      {conn, _ref} = open_request(conn)
      {conn, ref1} = open_request(conn)
      {conn, ref2} = open_request(conn)

      assert_recv_frames [headers(stream_id: first_stream_id), headers(), headers()]

      assert {:error, %HTTP2{} = conn, error, responses} =
               stream_frames(conn, [
                 goaway(
                   last_stream_id: first_stream_id,
                   error_code: :protocol_error,
                   debug_data: "debug data"
                 )
               ])

      assert_http2_error error, {
        :server_closed_connection,
        :protocol_error,
        "debug data"
      }

      assert [{:error, server_ref1, error1}, {:error, server_ref2, error2}] = responses
      assert MapSet.new([server_ref1, server_ref2]) == MapSet.new([ref1, ref2])

      assert_http2_error error1, :unprocessed
      assert_http2_error error2, :unprocessed

      assert HTTP2.open_request_count(conn) == 1

      refute HTTP2.open?(conn, :write)
      assert HTTP2.open?(conn, :read)
    end

    test "with GOAWAY with :no_error and responses after the GOAWAY frame", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 goaway(last_stream_id: stream_id, error_code: :no_error, debug_data: ""),
                 headers(
                   stream_id: stream_id,
                   hbf: server_encode_headers([{":status", "200"}]),
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 data(stream_id: stream_id, data: "hello", flags: set_flags(:data, [:end_stream]))
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:data, ^ref, "hello"}, {:done, ^ref}] =
               responses

      # the client would normally send two window_updates and a rst_stream, but since the
      # connection is now read-only, it should send nothing
      assert_recv_frames []

      assert HTTP2.open_request_count(conn) == 0

      refute HTTP2.open?(conn, :write)
      assert HTTP2.open?(conn, :read)
    end

    test "with GOAWAY followed by another GOAWAY then the error reason is from the last GOAWAY",
         %{conn: conn} do
      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 goaway(last_stream_id: 1, error_code: :no_error, debug_data: "1"),
                 goaway(last_stream_id: 1, error_code: :flow_control_error, debug_data: "2"),
                 goaway(last_stream_id: 1, error_code: :protocol_error, debug_data: "3")
               ])

      assert_http2_error error, {:server_closed_connection, :protocol_error, "3"}

      refute HTTP2.open?(conn, :write)
      assert HTTP2.open?(conn, :read)
    end

    test "with direct socket close and no in-flight requests", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, []} = HTTP2.stream(conn, {:ssl_closed, conn.socket})
      refute HTTP2.open?(conn)
    end

    test "with direct socket close and in-flight requests", %{conn: conn} do
      {conn, _ref} = open_request(conn)
      assert {:error, %HTTP2{} = conn, error, []} = HTTP2.stream(conn, {:ssl_closed, conn.socket})
      assert %TransportError{reason: :closed} = error
      refute HTTP2.open?(conn)
    end
  end

  describe "closed connection" do
    test "client closes the connection with close/1", %{conn: conn} do
      assert {:ok, conn} = HTTP2.close(conn)

      assert_recv_frames [goaway(error_code: :no_error)]

      refute HTTP2.open?(conn)

      # We can close the connection again and it's a no-op.
      assert {:ok, ^conn} = HTTP2.close(conn)
      refute HTTP2.open?(conn)
    end

    test "close/1 an already closed connection with default inet_backend does not cause error",
         %{conn: conn} do
      assert HTTP2.open?(conn)
      # ignore the returned conn, otherwise transport.close/1 will not be called
      assert {:ok, _conn} = HTTP2.close(conn)
      assert {:ok, conn} = HTTP2.close(conn)
      refute HTTP2.open?(conn)
    end

    @tag :with_transport_mock
    test "close/1 still succeeds if the transport returns an error when sending the GOAWAY frame",
         %{conn: conn} do
      TransportMock
      |> expect(:send, fn _socket, _data -> {:error, Transport.SSL.wrap_error(:timeout)} end)
      |> expect(:close, fn _socket -> :ok end)

      assert {:ok, conn} = HTTP2.close(conn)
      refute HTTP2.open?(conn)
    end

    test "request/5 returns error if the connection is closed",
         %{conn: conn} do
      assert {:error, %HTTP2{} = conn, _error, []} =
               stream_frames(conn, [
                 goaway(
                   stream_id: 0,
                   last_stream_id: 3,
                   error_code: :protocol_error,
                   debug_data: "debug data"
                 )
               ])

      expected_window_size = HTTP2.get_window_size(conn, :connection)
      test_bodies = [nil, :stream, "XX"]

      conn =
        Enum.reduce(test_bodies, conn, fn body, conn ->
          assert {:error, %HTTP2{} = conn, error} = HTTP2.request(conn, "GET", "/", [], body)
          assert_http2_error error, :closed_for_writing
          assert HTTP2.open_request_count(conn) == 0
          assert HTTP2.get_window_size(conn, :connection) == expected_window_size
          conn
        end)

      assert {:ok, conn} = HTTP2.close(conn)

      Enum.reduce(test_bodies, conn, fn body, conn ->
        assert {:error, %HTTP2{} = conn, error} = HTTP2.request(conn, "GET", "/", [], body)
        assert_http2_error error, :closed
        assert HTTP2.open_request_count(conn) == 0
        assert HTTP2.get_window_size(conn, :connection) == expected_window_size
        conn
      end)
    end

    test "close/1 properly closes socket on active connection", %{conn: conn} do
      # Check socket status, before close it should be opened
      assert {:ok, _info} = conn |> HTTP2.get_socket() |> :ssl.connection_information()

      # Closed successfully
      assert {:ok, conn} = HTTP2.close(conn)
      refute HTTP2.open?(conn)

      # Check socket status again, after close it should be closed
      assert {:error, :closed} = conn |> HTTP2.get_socket() |> :ssl.connection_information()
    end

    test "close/1 properly closes socket on erroneous connection", %{conn: conn} do
      # Check socket status, before close it should be opened
      assert {:ok, _info} = conn |> HTTP2.get_socket() |> :ssl.connection_information()

      # Closed successfully
      assert {:ok, conn} = HTTP2.close(conn)
      refute HTTP2.open?(conn)

      # Check socket status again, after close it should be closed
      assert {:error, :closed} = conn |> HTTP2.get_socket() |> :ssl.connection_information()
    end

    @tag :no_connection
    test "close/1 can close the connection right after starting",
         %{server_port: port, server_socket_task: server_socket_task} do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", port,
                 transport_opts: [verify: :verify_none],
                 mode: :passive
               )

      assert {:ok, server_socket} = Task.await(server_socket_task)
      :ok = :ssl.setopts(server_socket, active: true)

      assert {:ok, %HTTP2{} = conn} = HTTP2.close(conn)
      refute HTTP2.open?(conn)

      assert_receive {:ssl_closed, ^server_socket}
    end

    @tag :with_transport_mock
    test "close/1 works just fine if sending the GOAWAY errors out", %{conn: conn} do
      TransportMock
      |> expect(:send, fn _socket, _data -> {:error, Transport.SSL.wrap_error(:closed)} end)
      |> expect(:close, fn _socket -> :ok end)

      assert {:ok, %HTTP2{} = conn} = HTTP2.close(conn)
      refute HTTP2.open?(conn)
    end
  end

  describe "client errors" do
    @tag server_settings: [max_concurrent_streams: 1]
    test "when the client tries to open too many concurrent requests", %{conn: conn} do
      {conn, _ref} = open_request(conn)
      assert HTTP2.open_request_count(conn) == 1
      expected_window_size = HTTP2.get_window_size(conn, :connection)

      Enum.reduce([nil, :stream, "XX"], conn, fn body, conn ->
        assert {:error, %HTTP2{} = conn, error} = HTTP2.request(conn, "GET", "/", [], body)
        assert_http2_error error, :too_many_concurrent_requests

        assert HTTP2.open_request_count(conn) == 1
        assert HTTP2.open?(conn)
        assert HTTP2.get_window_size(conn, :connection) == expected_window_size
        conn
      end)
    end

    @tag :with_transport_mock
    test "when an SSL timeout is triggered on request", %{conn: conn} do
      stub_with(TransportMock, Transport.SSL)

      expected_window_size = HTTP2.get_window_size(conn, :connection)

      Enum.reduce([nil, :stream, "XX"], conn, fn body, conn ->
        expect(TransportMock, :send, fn _socket, data ->
          assert :ok = Transport.SSL.send(conn.socket, data)
          {:error, Transport.SSL.wrap_error(:timeout)}
        end)

        assert {:error, %HTTP2{} = conn, error} = HTTP2.request(conn, "GET", "/", [], body)
        assert_transport_error error, :timeout

        assert HTTP2.open_request_count(conn) == 0
        assert HTTP2.open?(conn)
        assert HTTP2.get_window_size(conn, :connection) == expected_window_size
        conn
      end)
    end

    @tag :with_transport_mock
    test "when an SSL timeout is triggered on stream request body", %{conn: conn} do
      stub_with(TransportMock, Transport.SSL)

      # Open a streaming request.
      {conn, ref} = open_request(conn, :stream)

      assert_recv_frames [headers()]

      expected_window_size = HTTP2.get_window_size(conn, :connection)

      expect(TransportMock, :send, fn _socket, data ->
        assert :ok = Mint.Core.Transport.SSL.send(conn.socket, data)
        {:error, Transport.SSL.wrap_error(:timeout)}
      end)

      data = :binary.copy(<<0>>, HTTP2.get_window_size(conn, {:request, ref}))
      assert {:error, %HTTP2{} = conn, error} = HTTP2.stream_request_body(conn, ref, data)
      assert_transport_error error, :timeout

      assert HTTP2.open_request_count(conn) == 1
      assert HTTP2.open?(conn)
      assert HTTP2.get_window_size(conn, :connection) == expected_window_size
    end
  end

  describe "headers and continuation" do
    test "server splits headers into multiple CONTINUATION frames", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> =
        server_encode_headers([{":status", "200"}, {"foo", "bar"}, {"baz", "bong"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 headers(stream_id: stream_id, hbf: hbf1, flags: set_flags(:headers, [])),
                 continuation(
                   stream_id: stream_id,
                   hbf: hbf2,
                   flags: set_flags(:continuation, [])
                 ),
                 continuation(
                   stream_id: stream_id,
                   hbf: hbf3,
                   flags: set_flags(:continuation, [:end_headers])
                 )
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, headers}] = responses
      assert headers == [{"foo", "bar"}, {"baz", "bong"}]

      assert HTTP2.open?(conn)
    end

    test "server sends a badly encoded header block fragment", %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: "not a good hbf",
                   flags: set_flags(:headers, [:end_headers])
                 )
               ])

      assert_http2_error error, {:compression_error, debug_data}
      assert debug_data =~ "unable to decode headers: :bad_binary_encoding"

      assert_recv_frames [goaway(error_code: :compression_error)]

      refute HTTP2.open?(conn)
    end

    test "server sends a CONTINUATION frame outside of headers streaming",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [continuation(stream_id: stream_id, hbf: "hbf")])

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "CONTINUATION received outside of headers streaming"

      assert_recv_frames [goaway(error_code: :protocol_error)]

      refute HTTP2.open?(conn)
    end

    test "server sends a non-CONTINUATION frame while streaming headers",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 headers(stream_id: stream_id, hbf: "hbf", flags: set_flags(:headers, [])),
                 data(stream_id: stream_id, data: "hello")
               ])

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "headers are streaming but got a :data frame"

      assert_recv_frames [goaway(error_code: :protocol_error)]

      refute HTTP2.open?(conn)
    end

    test "server sends HEADERS with END_STREAM but no END_HEADERS and then sends CONTINUATIONs",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> =
        server_encode_headers([{":status", "200"}, {"foo", "bar"}, {"baz", "bong"}])

      assert_recv_frames [headers(stream_id: stream_id)]

      {:ok, %HTTP2{} = conn, responses} =
        stream_frames(conn, [
          headers(stream_id: stream_id, hbf: hbf1, flags: set_flags(:headers, [:end_stream])),
          continuation(stream_id: stream_id, hbf: hbf2, flags: set_flags(:continuation, [])),
          continuation(
            stream_id: stream_id,
            hbf: hbf3,
            flags: set_flags(:continuation, [:end_headers])
          )
        ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, _headers}, {:done, ^ref}] = responses

      assert Enum.empty?(conn.streams)
      assert HTTP2.open?(conn)
    end

    test "server sends a response without a :status header", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 {:headers, stream_id, [{"foo", "bar"}, {"baz", "bong"}],
                  [:end_headers, :end_stream]}
               ])

      assert [{:error, ^ref, error}] = responses
      assert_http2_error error, :missing_status_header

      assert_recv_frames [rst_stream(error_code: :protocol_error)]

      assert HTTP2.open?(conn)
    end

    test "client has to split headers because of max frame size", %{conn: conn} do
      # This is an empirical number of headers so that the minimum max frame size (~16kb) fits
      # between 2 and 3 times (so that we can test the behaviour above).
      headers = for i <- 1..400, do: {"a#{i}", String.duplicate("a", 100)}
      assert {:ok, conn, _ref} = HTTP2.request(conn, "GET", "/", headers, nil)

      assert_recv_frames [
        headers(stream_id: stream_id, hbf: hbf1, flags: flags1),
        continuation(stream_id: stream_id, hbf: hbf2, flags: flags2),
        continuation(stream_id: stream_id, hbf: hbf3, flags: flags3)
      ]

      assert flag_set?(flags1, :headers, :end_stream)
      refute flag_set?(flags1, :headers, :end_headers)
      refute flag_set?(flags2, :continuation, :end_headers)
      assert flag_set?(flags3, :continuation, :end_headers)

      headers = server_decode_headers(hbf1 <> hbf2 <> hbf3)
      assert [{":method", "GET"}, {":path", "/"}, {":scheme", "https"} | _] = headers

      assert HTTP2.open?(conn)
    end

    @tag server_settings: [max_header_list_size: 20]
    test "an error is returned if client exceeds SETTINGS_MAX_HEADER_LIST_SIZE", %{conn: conn} do
      # With such a low max_header_list_size, even the default :special headers (such as
      # :method or :path) exceed the size.
      expected_window_size = HTTP2.get_window_size(conn, :connection)

      Enum.reduce([nil, :stream, "XX"], conn, fn body, conn ->
        assert {:error, %HTTP2{} = conn, error} = HTTP2.request(conn, "GET", "/", [], body)
        assert_http2_error error, {:max_header_list_size_exceeded, _, 20}

        assert HTTP2.open_request_count(conn) == 0
        assert HTTP2.open?(conn)
        assert HTTP2.get_window_size(conn, :connection) == expected_window_size
        conn
      end)
    end

    test ":authority pseudo-header includes port", %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(hbf: hbf)]

      assert {":authority", authority} =
               hbf
               |> server_decode_headers()
               |> List.keyfind(":authority", 0)

      assert authority == "#{conn.hostname}:#{conn.port}"

      assert HTTP2.open?(conn)
    end

    @tag :with_overridden_default_port
    test ":authority pseudo-header does not include port if it is the scheme's default",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(hbf: hbf)]

      assert {":authority", authority} =
               hbf
               |> server_decode_headers()
               |> List.keyfind(":authority", 0)

      assert authority == conn.hostname

      assert HTTP2.open?(conn)
    end

    test "when there's a request body, the content-length header is passed if not present",
         %{conn: conn} do
      {conn, _ref} = open_request(conn, "hello")

      assert_recv_frames [headers(hbf: hbf), data()]

      assert hbf
             |> server_decode_headers()
             |> List.keyfind("content-length", 0) == {"content-length", "5"}

      # Let's check that content-length is not overridden if already present.

      headers = [{"content-length", "10"}]
      assert {:ok, conn, _ref} = HTTP2.request(conn, "GET", "/", headers, "XX")

      assert_recv_frames [headers(hbf: hbf), data()]

      assert hbf
             |> server_decode_headers()
             |> List.keyfind("content-length", 0) == {"content-length", "10"}

      # Let's make sure content-length isn't added if the body is nil or :stream.

      {conn, _ref} = open_request(conn, nil)

      assert_recv_frames [headers(hbf: hbf)]

      refute hbf
             |> server_decode_headers()
             |> List.keymember?("content-length", 0)

      assert HTTP2.open?(conn)
    end

    test "the Cookie header is joined into a single value if present multiple times",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      hbf =
        server_encode_headers([
          {":status", "200"},
          {"accept", "text/plain"},
          {"cookie", "a=b"},
          {"Cookie", "c=d; e=f"},
          {"content-type", "application/json"},
          {"cookie", "g=h"},
          {"x-header", "value"}
        ])

      assert {:ok, %HTTP2{} = _conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers])
                 )
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, headers}] = responses

      assert [{"cookie", cookie}, {"accept", _}, {"content-type", _}, {"x-header", _}] = headers

      assert cookie == "a=b; c=d; e=f; g=h"
    end

    test "a CONNECT request omits :scheme and :path pseudo-headers", %{conn: conn} do
      assert {:ok, conn, _ref} = HTTP2.request(conn, "CONNECT", "/", [], nil)

      assert_recv_frames [headers(hbf: hbf)]

      refute hbf
             |> server_decode_headers()
             |> List.keymember?(":scheme", 0)

      refute hbf
             |> server_decode_headers()
             |> List.keymember?(":path", 0)

      assert HTTP2.open?(conn)
    end

    test "explicitly passed pseudo-headers are sorted to the front of the headers list", %{
      conn: conn
    } do
      headers = [
        {":scheme", conn.scheme},
        {":path", "/ws"},
        {":protocol", "websocket"}
      ]

      assert {:ok, conn, _ref} = HTTP2.request(conn, "CONNECT", "/", headers, :stream)

      assert_recv_frames [headers(hbf: hbf)]

      assert [
               {":method", "CONNECT"},
               {":authority", _},
               {":scheme", _},
               {":path", "/ws"},
               {":protocol", "websocket"},
               {"user-agent", _}
             ] = server_decode_headers(hbf)

      assert HTTP2.open?(conn)
    end
  end

  describe "interim responses (1xx)" do
    test "multiple before a single HEADERS", %{conn: conn} do
      info_status1 = Enum.random(100..199)
      info_status2 = Enum.random(100..199)

      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      <<info_hbf1_part1::1-bytes, info_hbf1_part2::binary>> =
        server_encode_headers([
          {":status", Integer.to_string(info_status1)},
          {"x-info-header1", "this is an info"}
        ])

      info_hbf2 =
        server_encode_headers([
          {":status", Integer.to_string(info_status2)},
          {"x-info-header2", "this is an info"}
        ])

      hbf =
        server_encode_headers([
          {":status", "200"},
          {"content-type", "application/json"}
        ])

      assert {:ok, %HTTP2{} = _conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: info_hbf1_part1,
                   flags: set_flags(:headers, [])
                 ),
                 continuation(
                   stream_id: stream_id,
                   hbf: info_hbf1_part2,
                   flags: set_flags(:continuation, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: info_hbf2,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers, :end_stream])
                 )
               ])

      assert [
               {:status, ^ref, ^info_status1},
               {:headers, ^ref, [{"x-info-header1", "this is an info"}]},
               {:status, ^ref, ^info_status2},
               {:headers, ^ref, [{"x-info-header2", "this is an info"}]},
               {:status, ^ref, 200},
               {:headers, ^ref, [{"content-type", "application/json"}]},
               {:done, ^ref}
             ] = responses

      assert HTTP2.open?(conn)
    end

    test "protocol error if interim response has END_STREAM set", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      info_hbf =
        server_encode_headers([
          {":status", "101"},
          {"x-info-header1", "this is an info"}
        ])

      assert {:ok, %HTTP2{} = _conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: info_hbf,
                   flags: set_flags(:headers, [:end_headers, :end_stream])
                 )
               ])

      assert [{:error, ^ref, error}] = responses

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "informational response (1xx) must not have the END_STREAM flag set"

      assert HTTP2.open?(conn)
    end

    test "protocol error if interim response HEADERS comes after final HEADERS", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      hbf = server_encode_headers([{":status", "200"}])
      info_hbf = server_encode_headers([{":status", "101"}])

      assert {:ok, %HTTP2{} = _conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: info_hbf,
                   flags: set_flags(:headers, [:end_headers])
                 )
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:error, ^ref, error}] = responses

      assert_http2_error error, {:protocol_error, debug_data}

      assert debug_data =~
               "informational response (1xx) must appear before final response, got a 101 status"

      assert HTTP2.open?(conn)
    end
  end

  describe "trailer headers" do
    test "sent by the server with a normal response", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      hbf = server_encode_headers([{":status", "200"}])

      <<trailer_hbf1::1-bytes, trailer_hbf2::binary>> =
        server_encode_headers([{"x-trailer", "some value"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 data(stream_id: stream_id, data: "some data", flags: set_flags(:data, [])),
                 headers(
                   stream_id: stream_id,
                   hbf: trailer_hbf1,
                   flags: set_flags(:headers, [:end_stream])
                 ),
                 continuation(
                   stream_id: stream_id,
                   hbf: trailer_hbf2,
                   flags: set_flags(:continuation, [:end_headers])
                 )
               ])

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:data, ^ref, "some data"},
               {:headers, ^ref, trailer_headers},
               {:done, ^ref}
             ] = responses

      assert trailer_headers == [{"x-trailer", "some value"}]
      assert HTTP2.open?(conn)
    end

    test "sent by the server directly after the \"opening\" headers (without data in between)",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      hbf = server_encode_headers([{":status", "200"}])
      trailer_hbf = server_encode_headers([{"x-trailer", "some value"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: trailer_hbf,
                   flags: set_flags(:headers, [:end_stream, :end_headers])
                 )
               ])

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:headers, ^ref, [{"x-trailer", "some value"}]},
               {:done, ^ref}
             ] = responses

      assert HTTP2.open?(conn)
    end

    test "with a push promise request", %{conn: conn} do
      promised_stream_id = 4

      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      promised_hbf = server_encode_headers([{":method", "GET"}])
      hbf1 = server_encode_headers([{":status", "200"}])
      hbf2 = server_encode_headers([{":status", "200"}])
      trailer_hbf = server_encode_headers([{"x-trailer", "some value"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 push_promise(
                   stream_id: stream_id,
                   hbf: promised_hbf,
                   promised_stream_id: promised_stream_id,
                   flags: set_flags(:push_promise, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: hbf1,
                   flags: set_flags(:headers, [:end_stream, :end_headers])
                 ),
                 # Promised stream with trailer headers.
                 headers(
                   stream_id: promised_stream_id,
                   hbf: hbf2,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: promised_stream_id,
                   hbf: trailer_hbf,
                   flags: set_flags(:headers, [:end_headers, :end_stream])
                 )
               ])

      assert [
               {:push_promise, ^ref, promised_ref, [{":method", "GET"}]},
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:done, ^ref},
               {:status, promised_ref, 200},
               {:headers, promised_ref, []},
               {:headers, promised_ref, [{"x-trailer", "some value"}]},
               {:done, promised_ref}
             ] = responses

      assert HTTP2.open?(conn)
    end

    test "protocol error if trailer headers don't have END_STREAM set", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      hbf = server_encode_headers([{":status", "200"}])
      trailer_hbf = server_encode_headers([{"x-trailer", "some value"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 data(stream_id: stream_id, data: "some data", flags: set_flags(:data, [])),
                 headers(
                   stream_id: stream_id,
                   hbf: trailer_hbf,
                   flags: set_flags(:headers, [:end_headers])
                 )
               ])

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:data, ^ref, "some data"},
               {:error, ^ref, error}
             ] = responses

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "trailer headers didn't set the END_STREAM flag"

      assert HTTP2.open?(conn)
    end

    test "unallowed headers are removed", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      hbf = server_encode_headers([{":status", "200"}])

      # Note that headers are lowercase in HTTP/2 responses because the spec
      # says so.
      trailer_hbf = server_encode_headers([{"x-trailer", "value"}, {"host", "example.com"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: trailer_hbf,
                   flags: set_flags(:headers, [:end_headers, :end_stream])
                 )
               ])

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:headers, ^ref, trailer_headers},
               {:done, ^ref}
             ] = responses

      assert trailer_headers == [{"x-trailer", "value"}]
      assert HTTP2.open?(conn)
    end
  end

  describe "server pushes" do
    test "a PUSH_PROMISE frame and a few CONTINUATION frames are received",
         %{conn: conn} do
      promised_stream_id = 4

      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      # Promised headers.
      headers = [{":method", "GET"}, {"foo", "bar"}, {"baz", "bong"}]

      <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = server_encode_headers(headers)

      # Normal headers.
      hbf = server_encode_headers([{":status", "200"}, {"push", "promise"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 push_promise(
                   stream_id: stream_id,
                   hbf: hbf1,
                   promised_stream_id: promised_stream_id
                 ),
                 continuation(stream_id: stream_id, hbf: hbf2),
                 continuation(
                   stream_id: stream_id,
                   hbf: hbf3,
                   flags: set_flags(:continuation, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_stream, :end_headers])
                 )
               ])

      assert [
               {:push_promise, ^ref, promised_ref, headers},
               {:status, ^ref, 200},
               {:headers, ^ref, [{"push", "promise"}]},
               {:done, ^ref}
             ] = responses

      assert is_reference(promised_ref)
      assert headers == [{":method", "GET"}, {"foo", "bar"}, {"baz", "bong"}]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: promised_stream_id,
                   hbf: hbf,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 data(
                   stream_id: promised_stream_id,
                   data: "hello",
                   flags: set_flags(:data, [:end_stream])
                 )
               ])

      assert [
               {:status, ^promised_ref, 200},
               {:headers, ^promised_ref, [{"push", "promise"}]},
               {:data, ^promised_ref, "hello"},
               {:done, ^promised_ref}
             ] = responses

      assert HTTP2.open?(conn)
    end

    @tag connect_options: [client_settings: [enable_push: false]]
    test "receiving PUSH_PROMISE frame when SETTINGS_ENABLE_PUSH is false causes an error",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      hbf = server_encode_headers([{":method", "GET"}])

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 push_promise(
                   stream_id: stream_id,
                   hbf: hbf,
                   promised_stream_id: 4,
                   flags: set_flags(:push_promise, [:end_headers])
                 )
               ])

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "received PUSH_PROMISE frame when SETTINGS_ENABLE_PUSH was false"

      assert_recv_frames [goaway(error_code: :protocol_error)]
      refute HTTP2.open?(conn)
    end

    test "if the server tries to reserve an already existing stream the connection errors",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      promised_headers_hbf = server_encode_headers([{":method", "GET"}])
      normal_headers_hbf = server_encode_headers([{":status", "200"}])

      assert {:error, %HTTP2{} = conn, error, _responses} =
               stream_frames(conn, [
                 push_promise(
                   stream_id: stream_id,
                   hbf: promised_headers_hbf,
                   promised_stream_id: 4,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 push_promise(
                   stream_id: stream_id,
                   hbf: promised_headers_hbf,
                   promised_stream_id: 4,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: normal_headers_hbf,
                   flags: set_flags(:headers, [:end_stream, :end_headers])
                 )
               ])

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "stream with ID 4 already exists and can't be reserved by the server"

      refute HTTP2.open?(conn)
    end

    @tag connect_options: [client_settings: [max_concurrent_streams: 1]]
    test "if the server reaches the max number of client streams, the client sends an error",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      promised_headers_hbf = server_encode_headers([{":method", "GET"}])
      normal_headers_hbf = server_encode_headers([{":status", "200"}])

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 push_promise(
                   stream_id: stream_id,
                   hbf: promised_headers_hbf,
                   promised_stream_id: 4,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 push_promise(
                   stream_id: stream_id,
                   hbf: promised_headers_hbf,
                   promised_stream_id: 6,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: stream_id,
                   hbf: normal_headers_hbf,
                   flags: set_flags(:headers, [:end_stream, :end_headers])
                 )
               ])

      assert [
               {:push_promise, ^ref, promised_ref1, _},
               {:push_promise, ^ref, _promised_ref2, _},
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:done, ^ref}
             ] = responses

      # Here we send headers for the two promised streams. Note that neither of the
      # header frames have the END_STREAM flag set otherwise we close the streams and
      # they don't count towards the open stream count.
      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: 4,
                   hbf: normal_headers_hbf,
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 headers(
                   stream_id: 6,
                   hbf: normal_headers_hbf,
                   flags: set_flags(:headers, [:end_headers])
                 )
               ])

      assert [{:status, ^promised_ref1, 200}, {:headers, ^promised_ref1, []}] = responses

      assert_recv_frames [
        rst_stream(stream_id: 6, error_code: :refused_stream)
      ]

      assert HTTP2.open?(conn)
    end
  end

  describe "misbehaving server" do
    test "sends a frame with the wrong stream id", %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers()]

      data = IO.iodata_to_binary(encode_raw(_ping = 0x06, 0x00, 3, <<0::64>>))
      assert {:error, %HTTP2{} = conn, error, []} = HTTP2.stream(conn, {:ssl, conn.socket, data})

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "frame :ping only allowed at the connection level"

      assert_recv_frames [goaway(error_code: :protocol_error)]

      refute HTTP2.open?(conn)
    end

    test "sends a frame with a bad size", %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers()]

      # Payload should be 8 bytes long, but is empty here.
      data = IO.iodata_to_binary(encode_raw(_ping = 0x06, 0x00, 3, <<>>))

      assert {:error, %HTTP2{} = conn, error, []} = HTTP2.stream(conn, {:ssl, conn.socket, data})

      assert_http2_error error, {:frame_size_error, debug_data}
      assert debug_data =~ "error with size of frame: :ping"

      assert_recv_frames [goaway(error_code: :frame_size_error)]
      refute HTTP2.open?(conn)
    end

    test "sends a frame on a stream with a stream ID bigger than client's biggest",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      bad_stream_id = stream_id + 10

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 {:headers, bad_stream_id, [{":status", "200"}], [:end_headers]}
               ])

      assert_http2_error error, {:protocol_error, debug_data}
      assert debug_data =~ "frame with stream ID #{bad_stream_id} has not been opened yet"

      assert_recv_frames [goaway(error_code: :protocol_error)]

      refute HTTP2.open?(conn)
    end
  end

  describe "flow control" do
    test "client sends data that goes over window size of a stream/connection when streaming",
         %{conn: conn} do
      # First we decrease the connection size by 5 bytes, so that the connection window
      # size is smaller than the stream window size.
      {conn, _ref} = open_request(conn, "XXXXX")

      assert_recv_frames [headers(), data()]

      # Then we open a streaming request.
      {conn, ref} = open_request(conn, :stream)

      assert_recv_frames [headers()]

      data = :binary.copy(<<0>>, HTTP2.get_window_size(conn, {:request, ref}) + 1)
      assert {:error, %HTTP2{} = conn, error} = HTTP2.stream_request_body(conn, ref, data)
      assert_http2_error error, {:exceeds_window_size, :request, window_size}
      assert is_integer(window_size) and window_size >= 0

      data = :binary.copy(<<0>>, HTTP2.get_window_size(conn, :connection) + 1)
      assert {:error, %HTTP2{} = conn, error} = HTTP2.stream_request_body(conn, ref, data)
      assert_http2_error error, {:exceeds_window_size, :connection, window_size}
      assert is_integer(window_size) and window_size >= 0

      assert HTTP2.open?(conn)
    end

    @tag server_settings: [initial_window_size: 1]
    test "if client's request goes over window size, no HEADER frames are sent", %{conn: conn} do
      expected_window_size = HTTP2.get_window_size(conn, :connection)
      assert {:error, %HTTP2{} = conn, error} = HTTP2.request(conn, "GET", "/", [], "XX")
      assert_http2_error error, {:exceeds_window_size, :request, 1}
      assert HTTP2.open?(conn)
      assert HTTP2.open_request_count(conn) == 0
      assert HTTP2.get_window_size(conn, :connection) == expected_window_size
      refute_receive {:ssl, _, _}
    end

    test "server sends a WINDOW_UPDATE with too big of a size on a stream",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 window_update(
                   stream_id: stream_id,
                   window_size_increment: _max_window_size = 2_147_483_647
                 )
               ])

      assert [{:error, ^ref, error}] = responses
      assert_http2_error error, {:flow_control_error, debug_data}
      assert debug_data =~ "window size too big"

      assert_recv_frames [rst_stream(stream_id: ^stream_id, error_code: :flow_control_error)]

      assert HTTP2.open?(conn)
    end

    test "server sends a WINDOW_UPDATE with too big of a size on the connection level",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: _stream_id)]

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 window_update(
                   stream_id: 0,
                   window_size_increment: _max_window_size = 2_147_483_647
                 )
               ])

      assert_http2_error error, {:flow_control_error, debug_data}
      assert debug_data =~ "window size too big"

      assert_recv_frames [goaway(error_code: :flow_control_error)]

      refute HTTP2.open?(conn)
    end

    test "server sends invalid WINDOW_UPDATE with 0 window size increment", %{conn: conn} do
      assert {:error, %HTTP2{} = conn, error, _responses = []} =
               stream_frames(conn, [window_update(stream_id: 0, window_size_increment: 0)])

      assert_http2_error error,
                         {:protocol_error,
                          "error when decoding frame: \"bad WINDOW_SIZE increment\""}

      refute HTTP2.open?(conn)
    end

    test "server sends invalid WINDOW_UPDATE on a stream that is in the half-closed (remote) state (RFC9113§5.1)",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:error, %HTTP2{} = conn, reason, responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id,
                   hbf: server_encode_headers([{":status", "200"}]),
                   flags: set_flags(:headers, [:end_headers])
                 ),
                 data(stream_id: stream_id, data: "", flags: set_flags(:data, [:end_stream])),
                 window_update(stream_id: stream_id, window_size_increment: 1000)
               ])

      assert Enum.reverse(responses) == [
               {:status, ref, 200},
               {:headers, ref, []},
               {:data, ref, ""},
               {:done, ref}
             ]

      assert_http2_error reason, {:stream_not_found, ^stream_id}

      # Conn stays open.
      assert HTTP2.open?(conn)
    end

    test "server violates client's max frame size", %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 data(stream_id: stream_id, data: :binary.copy(<<0>>, 100_000))
               ])

      assert_http2_error error, {:frame_size_error, debug_data}
      assert debug_data =~ "frame payload exceeds connection's max frame size"

      assert_recv_frames [goaway(error_code: :frame_size_error)]

      refute HTTP2.open?(conn)
    end

    test "client splits data automatically based on server's max frame size",
         %{conn: conn} do
      max_frame_size = HTTP2.get_server_setting(conn, :max_frame_size)

      body = :binary.copy(<<0>>, max_frame_size + 1)
      {conn, _ref} = open_request(conn, body)

      assert_recv_frames [
        headers(stream_id: stream_id),
        data(stream_id: stream_id, flags: flags1, data: data1),
        data(stream_id: stream_id, flags: flags2, data: data2)
      ]

      assert flags1 == set_flags(:data, [])
      assert data1 == :binary.copy(<<0>>, max_frame_size)

      assert flags2 == set_flags(:data, [:end_stream])
      assert data2 == <<0>>

      assert HTTP2.open?(conn)
    end

    test "window size of the connection and single requests can be read with get_window_size/2",
         %{conn: conn} do
      {conn, ref} = open_request(conn, :stream)

      initial_conn_window_size = HTTP2.get_window_size(conn, :connection)
      initial_request_window_size = HTTP2.get_window_size(conn, {:request, ref})

      assert is_integer(initial_conn_window_size) and initial_conn_window_size > 0
      assert is_integer(initial_request_window_size) and initial_request_window_size > 0

      body_chunk = "hello"
      {:ok, conn} = HTTP2.stream_request_body(conn, ref, body_chunk)

      new_conn_window_size = HTTP2.get_window_size(conn, :connection)
      new_request_window_size = HTTP2.get_window_size(conn, {:request, ref})

      assert new_conn_window_size == initial_conn_window_size - byte_size(body_chunk)
      assert new_request_window_size == initial_request_window_size - byte_size(body_chunk)
    end

    test "if the server sends an empty DATA frame, we don't send WINDOW_UPDATE back",
         %{conn: conn} do
      {conn, ref} = open_request(conn, :stream)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = _conn, responses} =
               stream_frames(conn, [
                 data(stream_id: stream_id, data: "", flags: set_flags(:data, [:end_stream]))
               ])

      assert_recv_frames [rst_stream(stream_id: ^stream_id, error_code: :no_error)]

      assert responses == [{:data, ref, ""}, {:done, ref}]
    end

    test "get_window_size/2 raises if the request is not found", %{conn: conn} do
      assert_raise ArgumentError, ~r/request with request reference .+ was not found/, fn ->
        HTTP2.get_window_size(conn, {:request, make_ref()})
      end
    end
  end

  describe "settings" do
    test "put_settings/2 can be used to send settings to server", %{conn: conn} do
      {:ok, conn} =
        HTTP2.put_settings(conn, max_concurrent_streams: 123, initial_window_size: 1_000)

      assert_recv_frames [settings() = frame]
      assert settings(frame, :params) == [max_concurrent_streams: 123, initial_window_size: 1_000]
      assert settings(frame, :flags) == set_flags(:settings, [])

      assert {:ok, %HTTP2{} = conn, []} =
               stream_frames(conn, [
                 settings(flags: set_flags(:settings, [:ack]), params: [])
               ])

      assert HTTP2.get_client_setting(conn, :initial_window_size) == 1_000
      assert HTTP2.open?(conn)
    end

    test "put_settings/2 raises an error if the argument is not a keyword list", %{conn: conn} do
      assert_raise ArgumentError, "settings must be a keyword list", fn ->
        HTTP2.put_settings(conn, [:setting1, :setting2])
      end
    end

    test "put_settings/2 fails with unknown or invalid settings", %{conn: conn} do
      assert_raise ArgumentError, ":header_table_size must be an integer, got: :oops", fn ->
        HTTP2.put_settings(conn, header_table_size: :oops)
      end

      assert_raise ArgumentError, "unknown setting parameter :oops", fn ->
        HTTP2.put_settings(conn, oops: 1)
      end

      assert_raise ArgumentError, ~r/:enable_connect_protocol is only valid for server/, fn ->
        HTTP2.put_settings(conn, enable_connect_protocol: true)
      end
    end

    @tag :with_transport_mock
    test "put_settings/2 returns an error if sending the SETTINGS frame returns an error",
         %{conn: conn} do
      expect(TransportMock, :send, fn _socket, _data ->
        {:error, Transport.SSL.wrap_error(:timeout)}
      end)

      assert {:error, %HTTP2{} = conn, error} =
               HTTP2.put_settings(conn, max_concurrent_streams: 10)

      assert_transport_error error, :timeout
      assert HTTP2.open?(conn)
    end

    test "get_server_setting/2 can be used to read server settings", %{conn: conn} do
      assert HTTP2.get_server_setting(conn, :max_concurrent_streams) == 100
      assert HTTP2.get_server_setting(conn, :enable_push) == true
      assert HTTP2.get_server_setting(conn, :enable_connect_protocol) == false
    end

    test "get_server_setting/2 fails with unknown settings", %{conn: conn} do
      assert_raise ArgumentError, "unknown HTTP/2 setting: :unknown", fn ->
        HTTP2.get_server_setting(conn, :unknown)
      end
    end

    test "server can update the initial window size and affect open streams",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers()]

      {:ok, %HTTP2{} = conn, []} =
        stream_frames(conn, [settings(params: [initial_window_size: 100])])

      assert HTTP2.get_server_setting(conn, :initial_window_size) == 100

      # This stream is half_closed_local, so there's not point in updating its window size since
      # we won't send anything on it anymore.
      assert HTTP2.get_window_size(conn, {:request, ref}) == 65535

      assert_recv_frames [settings(flags: flags)]
      assert flags == set_flags(:settings, [:ack])
    end

    @tag :no_connection
    test "protocol error when server sends an invalid setting",
         %{server_port: server_port, server_socket_task: server_socket_task} do
      ack_flags = Frame.set_flags(:settings, [:ack])

      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", server_port,
                 transport_opts: [verify: :verify_none]
               )

      {:ok, server_socket} = Task.await(server_socket_task)
      :ok = TestServer.perform_http2_handshake(server_socket)

      server = TestServer.new(server_socket)
      Process.put(@server_pdict_key, server)

      assert {:error, %HTTP2{} = conn, error, []} =
               stream_frames(conn, [
                 settings(params: [max_frame_size: 1]),
                 settings(flags: ack_flags, params: [])
               ])

      assert %Mint.HTTPError{reason: reason} = error

      assert reason ==
               {:protocol_error, "MAX_FRAME_SIZE setting parameter outside of allowed range"}

      refute HTTP2.open?(conn)
    end

    test "client ignores settings ACKs if client settings queue is empty", %{conn: conn} do
      log =
        capture_log(fn ->
          assert {:ok, %HTTP2{} = conn, []} =
                   stream_frames(conn, [settings(flags: set_flags(:settings, [:ack]), params: [])])

          assert HTTP2.open?(conn)
        end)

      assert log =~ "Received SETTINGS ACK but client is not waiting for ACKs"
    end

    test "server can send the :enable_push setting", %{conn: conn} do
      {:ok, %HTTP2{} = conn, []} = stream_frames(conn, [settings(params: [enable_push: false])])
      assert HTTP2.get_server_setting(conn, :enable_push) == false

      {:ok, %HTTP2{} = conn, []} = stream_frames(conn, [settings(params: [enable_push: true])])
      assert HTTP2.get_server_setting(conn, :enable_push) == true
    end

    test "if server sends an invalid :initial_window_size, we send a connection error",
         %{conn: conn} do
      assert {:error, %HTTP2{} = conn, error, responses} =
               stream_frames(conn, [
                 settings(params: [initial_window_size: 1_000_000_000_000_000])
               ])

      assert responses == []
      assert_http2_error error, {:flow_control_error, message}
      assert message =~ ~r/INITIAL_WINDOW_SIZE setting of \d+ is too big/

      refute HTTP2.open?(conn)
    end

    test "if server sends an invalid :max_frame_size, we send a connection error",
         %{conn: conn} do
      assert {:error, %HTTP2{} = conn, error, responses} =
               stream_frames(conn, [settings(params: [max_frame_size: 0])])

      assert responses == []
      assert_http2_error error, {:protocol_error, message}
      assert message == "MAX_FRAME_SIZE setting parameter outside of allowed range"

      refute HTTP2.open?(conn)
    end

    test "get_client_setting/2", %{conn: conn} do
      assert HTTP2.get_client_setting(conn, :max_concurrent_streams) == 100
    end
  end

  describe "stream_request_body/3" do
    test "streaming a request", %{conn: conn} do
      {conn, ref} = open_request(conn, :stream)
      assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, "foo")
      assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, "bar")
      assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, :eof)

      assert_recv_frames [
        headers(stream_id: stream_id) = headers,
        data(stream_id: stream_id, data: "foo") = data1,
        data(stream_id: stream_id, data: "bar") = data2,
        data(stream_id: stream_id, data: "") = data3
      ]

      refute flag_set?(headers(headers, :flags), :headers, :end_stream)
      refute flag_set?(data(data1, :flags), :data, :end_stream)
      refute flag_set?(data(data2, :flags), :data, :end_stream)
      assert flag_set?(data(data3, :flags), :data, :end_stream)

      assert HTTP2.open?(conn)
    end

    test "streaming a request on a request that wasn't opened with :stream errors out",
         %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert HTTP2.open_request_count(conn) == 1
      expected_window_size = HTTP2.get_window_size(conn, :connection)

      assert {:error, %HTTP2{} = conn, error} = HTTP2.stream_request_body(conn, ref, "foo")
      assert_http2_error error, :request_is_not_streaming

      assert HTTP2.get_window_size(conn, :connection) == expected_window_size
      assert HTTP2.open_request_count(conn) == 1

      assert HTTP2.open?(conn)
    end

    test "streaming to an unknown request returns an error", %{conn: conn} do
      assert HTTP2.open_request_count(conn) == 0
      expected_window_size = HTTP2.get_window_size(conn, :connection)

      assert {:error, %HTTP2{} = conn, error} = HTTP2.stream_request_body(conn, make_ref(), "x")
      assert_http2_error error, :unknown_request_to_stream

      assert HTTP2.get_window_size(conn, :connection) == expected_window_size
      assert HTTP2.open_request_count(conn) == 0
      assert HTTP2.open?(conn)
    end

    test "streaming a request with trailer headers", %{conn: conn} do
      {conn, ref} = open_request(conn, :stream)

      # Using 1000 headers will go over the default max_frame_size so that the
      # HEADERS frame for the trailer headers will also be split into a HEADERS
      # plus CONTINUATION frames.
      trailer_headers = for index <- 1..1000, do: {"my-trailer-#{index}", "value"}

      assert {:ok, _conn} = HTTP2.stream_request_body(conn, ref, {:eof, trailer_headers})

      assert_recv_frames [
        headers(stream_id: stream_id) = headers,
        headers(stream_id: stream_id, hbf: trailer_hbf1) = trailer_headers1,
        continuation(stream_id: stream_id, hbf: trailer_hbf2) = trailer_headers2
      ]

      assert flag_set?(headers(headers, :flags), :headers, :end_headers)
      refute flag_set?(headers(headers, :flags), :headers, :end_stream)

      refute flag_set?(headers(trailer_headers1, :flags), :headers, :end_headers)
      assert flag_set?(headers(trailer_headers1, :flags), :headers, :end_stream)

      assert flag_set?(continuation(trailer_headers2, :flags), :continuation, :end_headers)

      assert server_decode_headers(trailer_hbf1 <> trailer_hbf2) == trailer_headers
    end

    test "unallowed trailer headers cause an error", %{conn: conn} do
      {conn, ref} = open_request(conn, :stream)

      assert HTTP2.open_request_count(conn) == 1
      expected_window_size = HTTP2.get_window_size(conn, :connection)

      trailer_headers = [{"x-trailer", "value"}, {"Host", "example.com"}]

      assert {:error, %HTTP2{} = _conn, error} =
               HTTP2.stream_request_body(conn, ref, {:eof, trailer_headers})

      assert_http2_error error, {:unallowed_trailing_header, "Host"}

      assert HTTP2.get_window_size(conn, :connection) == expected_window_size
      assert HTTP2.open_request_count(conn) == 1
    end

    test "streaming to a closed connection returns an error", %{conn: conn} do
      {conn, ref} = open_request(conn, :stream)
      {:ok, closed_conn} = HTTP2.close(conn)
      assert {:error, conn, error} = HTTP2.stream_request_body(closed_conn, ref, :eof)
      assert_http2_error error, :closed
      refute HTTP2.open?(conn)
    end

    test "streaming to a connection that got GOAWAY returns an error", %{conn: conn} do
      {conn, ref} = open_request(conn, :stream)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:error, conn, _goaway_error, _responses} =
               stream_frames(conn, [
                 goaway(
                   last_stream_id: stream_id,
                   error_code: :protocol_error,
                   debug_data: "debug data"
                 )
               ])

      assert {:error, _conn, error} = HTTP2.stream_request_body(conn, ref, :eof)
      assert_http2_error error, :closed_for_writing
    end
  end

  describe "open_request_count/1" do
    test "returns the number of client-initiated open streams", %{conn: conn} do
      assert HTTP2.open_request_count(conn) == 0

      {conn, _ref} = open_request(conn)
      assert HTTP2.open_request_count(conn) == 1

      {conn, _ref} = open_request(conn)
      assert HTTP2.open_request_count(conn) == 2

      assert_recv_frames [headers(stream_id: stream_id1), headers()]

      assert {:ok, %HTTP2{} = conn, _responses} =
               stream_frames(conn, [
                 headers(
                   stream_id: stream_id1,
                   hbf: server_encode_headers([{":status", "200"}]),
                   flags: set_flags(:headers, [:end_headers, :end_stream])
                 )
               ])

      assert HTTP2.open_request_count(conn) == 1
    end
  end

  describe "connection modes" do
    @tag connect_options: [mode: :passive]
    test "starting a connection with :passive mode and using recv/3", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      data =
        server_encode_frames([
          headers(
            stream_id: stream_id,
            hbf: server_encode_headers([{":status", "200"}]),
            flags: set_flags(:headers, [:end_headers, :end_stream])
          )
        ])

      :ok = :ssl.send(server_get_socket(), data)

      assert {:ok, conn, responses} = HTTP2.recv(conn, 0, 100)

      assert responses == [
               {:status, ref, 200},
               {:headers, ref, []},
               {:done, ref}
             ]

      assert HTTP2.open?(conn)
    end

    test "changing the mode of a connection with set_mode/2", %{conn: conn} do
      assert_raise ArgumentError, ~r"^can't use recv/3", fn ->
        HTTP2.recv(conn, 0, 100)
      end

      assert {:ok, %HTTP2{} = conn} = HTTP2.set_mode(conn, :passive)

      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      data =
        server_encode_frames([
          headers(
            stream_id: stream_id,
            hbf: server_encode_headers([{":status", "200"}]),
            flags: set_flags(:headers, [:end_headers, :end_stream])
          )
        ])

      :ok = :ssl.send(server_get_socket(), data)

      assert {:ok, conn, responses} = HTTP2.recv(conn, 0, 100)

      assert responses == [
               {:status, ref, 200},
               {:headers, ref, []},
               {:done, ref}
             ]

      assert {:ok, %HTTP2{} = conn} = HTTP2.set_mode(conn, :active)

      assert_raise ArgumentError, ~r"^can't use recv/3", fn ->
        HTTP2.recv(conn, 0, 100)
      end

      assert HTTP2.open?(conn)
    end

    @tag connect_options: [mode: :passive]
    test "closed socket is handled in recv/3", %{conn: conn} do
      :ok = :ssl.shutdown(conn.socket, :read)
      assert {:ok, conn, _responses = []} = HTTP2.recv(conn, 0, 1)
      refute HTTP2.open?(conn)
    end

    @tag connect_options: [mode: :passive]
    test "timeouts are bubbled up in recv/3", %{conn: conn} do
      assert {:error, conn, error, _responses = []} = HTTP2.recv(conn, 0, 0)
      assert_transport_error error, :timeout
      refute HTTP2.open?(conn)
    end

    @tag connect_options: [mode: :passive]
    @tag :with_transport_mock
    test "socket errors are bubbled up in recv/3", %{conn: conn} do
      expect(TransportMock, :recv, fn _socket, 0, 1000 -> {:error, :econnrefused} end)
      HTTP2.recv(conn, 0, 1000)
    end

    @tag connect_options: [mode: :passive]
    test "protocol errors are bubbled up in recv/3", %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers()]

      # Payload should be 8 bytes long, but is empty here.
      data = IO.iodata_to_binary(encode_raw(_ping = 0x06, 0x00, 3, <<>>))
      :ok = :ssl.send(server_get_socket(), data)

      assert {:error, %HTTP2{} = conn, error, []} = HTTP2.recv(conn, 0, 1000)

      assert_http2_error error, {:frame_size_error, debug_data}
      assert debug_data =~ "error with size of frame: :ping"

      assert_recv_frames [goaway(error_code: :frame_size_error)]
      refute HTTP2.open?(conn)
    end
  end

  describe "ping" do
    test "if we send a PING we then get a :pong reply", %{conn: conn} do
      assert {:ok, conn, ref} = HTTP2.ping(conn)

      assert_recv_frames [ping(opaque_data: opaque_data)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 ping(flags: set_flags(:ping, [:ack]), opaque_data: opaque_data)
               ])

      assert responses == [{:pong, ref}]

      assert HTTP2.open?(conn)
    end

    test "if the server sends a PING we reply automatically", %{conn: conn} do
      opaque_data = :binary.copy(<<0>>, 8)
      assert {:ok, %HTTP2{}, []} = stream_frames(conn, [ping(opaque_data: opaque_data)])
      assert_recv_frames [ping(opaque_data: ^opaque_data)]
    end

    test "if the server sends a PING ack but no PING requests are pending we emit a warning",
         %{conn: conn} do
      opaque_data = :binary.copy(<<0>>, 8)

      assert capture_log(fn ->
               assert {:ok, %HTTP2{}, []} =
                        stream_frames(conn, [
                          ping(opaque_data: opaque_data, flags: set_flags(:ping, [:ack]))
                        ])
             end) =~ "Received PING ack but no PING requests are pending"
    end

    test "if the server sends a PING ack but no PING requests match we emit a warning",
         %{conn: conn} do
      assert {:ok, conn, _ref} = HTTP2.ping(conn, <<1, 2, 3, 4, 5, 6, 7, 8>>)
      opaque_data = <<1, 2, 3, 4, 5, 6, 7, 0>>

      assert capture_log(fn ->
               assert {:ok, %HTTP2{}, []} =
                        stream_frames(conn, [
                          ping(opaque_data: opaque_data, flags: set_flags(:ping, [:ack]))
                        ])
             end) =~ "Received PING ack that doesn't match next PING request in the queue"
    end

    @tag :with_transport_mock
    test "if the transport returns an error then ping/2 returns that error", %{conn: conn} do
      expect(TransportMock, :send, fn _socket, _data ->
        {:error, Transport.SSL.wrap_error(:econnrefused)}
      end)

      assert {:error, %HTTP2{} = conn, error} = HTTP2.ping(conn)
      assert_transport_error error, :econnrefused
      assert HTTP2.open?(conn)
    end
  end

  describe "stream priority" do
    test "PRIORITY frames are ignored", %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert capture_log(fn ->
               assert {:ok, %HTTP2{} = conn, []} =
                        stream_frames(conn, [
                          priority(
                            stream_id: stream_id,
                            exclusive?: false,
                            stream_dependency: 1,
                            weight: 1
                          )
                        ])

               assert HTTP2.open?(conn)
             end) =~ "Ignoring PRIORITY frame"
    end
  end

  describe "controlling process" do
    test "changing the controlling process with controlling_process/2", %{conn: conn} do
      parent = self()
      ref = make_ref()

      new_pid =
        spawn_link(fn ->
          receive do
            message ->
              send(parent, {ref, message})
              Process.sleep(:infinity)
          end
        end)

      {conn, request_ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      data =
        server_encode_frames([
          headers(
            stream_id: stream_id,
            hbf: server_encode_headers([{":status", "200"}]),
            flags: set_flags(:headers, [:end_headers, :end_stream])
          )
        ])

      {:ok, %HTTP2{} = conn} = HTTP2.controlling_process(conn, new_pid)

      :ok = :ssl.send(server_get_socket(), data)

      assert_receive {^ref, message}
      assert {:ok, %HTTP2{} = conn, responses} = HTTP2.stream(conn, message)

      assert responses == [
               {:status, request_ref, 200},
               {:headers, request_ref, []},
               {:done, request_ref}
             ]

      assert HTTP2.open?(conn)
    end
  end

  test "put_private/3, get_private/3, and delete_private/2", %{conn: conn} do
    assert HTTP2.get_private(conn, :my_key) == nil
    assert HTTP2.get_private(conn, :my_key, :default) == :default

    # Setting the key.
    assert %HTTP2{} = conn = HTTP2.put_private(conn, :my_key, :my_value)
    assert HTTP2.get_private(conn, :my_key) == :my_value

    # Overriding the same key.
    assert %HTTP2{} = conn = HTTP2.put_private(conn, :my_key, :my_new_value)
    assert HTTP2.get_private(conn, :my_key) == :my_new_value

    # Deleting the key.
    assert %HTTP2{} = conn = HTTP2.delete_private(conn, :my_key)
    assert HTTP2.get_private(conn, :my_key) == nil
  end

  describe "logging" do
    @describetag capture_log: false

    test "logs debug messages for inbound frames", %{conn: conn} do
      previous_level = Logger.level()
      on_exit(fn -> Logger.configure(level: previous_level) end)

      Logger.configure(level: :debug)

      log =
        capture_log(fn ->
          assert {:ok, %HTTP2{} = _conn, []} =
                   stream_frames(conn, [ping(opaque_data: <<1, 2, 3, 4, 5, 6, 7, 8>>)])
        end)

      assert log =~
               "Received frame: PING[stream_id: 0, flags: 0, opaque_data: <<1, 2, 3, 4, 5, 6, 7, 8>>]"
    end
  end

  defp start_server_async(_context) do
    {:ok, port, server_socket_task} = TestServer.listen_and_accept()
    %{server_port: port, server_socket_task: server_socket_task}
  end

  defp start_connection(%{no_connection: true} = _context) do
    :ok
  end

  defp start_connection(%{server_port: port, server_socket_task: server_socket_task} = context) do
    ack_flags = Frame.set_flags(:settings, [:ack])

    conn_options =
      [transport_opts: [verify: :verify_none]]
      |> Keyword.merge(context[:connect_options] || [])
      |> Keyword.put_new(:log, true)

    assert {:ok, %HTTP2{} = conn} = HTTP2.connect(:https, "localhost", port, conn_options)
    {:ok, server_socket} = Task.await(server_socket_task)
    assert :ok = TestServer.perform_http2_handshake(server_socket)

    :ok =
      :ssl.send(server_socket, [
        Frame.encode(settings(params: context[:server_settings] || [])),
        Frame.encode(settings(flags: ack_flags, params: []))
      ])

    # We let the client process server settings and the ack here.
    assert {:ok, %HTTP2{} = conn, []} =
             (if conn_options[:mode] == :passive do
                HTTP2.recv(conn, 0, @recv_timeout)
              else
                assert_receive message, @recv_timeout
                HTTP2.stream(conn, message)
              end)

    # Before moving on, we await the SETTINGS ack from the client.
    {:ok, data} = :ssl.recv(server_socket, 0, @recv_timeout)
    assert {:ok, frame, ""} = Frame.decode_next(data)
    assert settings(flags: ^ack_flags, params: []) = frame

    :ok = :ssl.setopts(server_socket, active: true)

    server = TestServer.new(server_socket)
    Process.put(@server_pdict_key, server)

    [conn: conn]
  end

  defp maybe_set_transport_mock(%{conn: conn, with_transport_mock: _}) do
    verify_on_exit!()
    [conn: %{conn | transport: TransportMock}]
  end

  defp maybe_set_transport_mock(_context) do
    %{}
  end

  defp maybe_change_default_scheme_port(%{
         server_port: server_port,
         with_overridden_default_port: _
       }) do
    default_https_port = URI.default_port("https")

    on_exit(fn -> URI.default_port("https", default_https_port) end)

    :ok = URI.default_port("https", server_port)

    %{}
  end

  defp maybe_change_default_scheme_port(_context) do
    %{}
  end

  defp recv_next_frames(n) do
    server = Process.get(@server_pdict_key)
    TestServer.recv_next_frames(server, n)
  end

  defp stream_frames(conn, frames) do
    data = server_encode_frames(frames)
    HTTP2.stream(conn, {:ssl, conn.socket, data})
  end

  defp server_get_socket() do
    server = Process.get(@server_pdict_key)
    server.socket
  end

  defp server_encode_frames(frames) do
    server = Process.get(@server_pdict_key)
    {server, data} = TestServer.encode_frames(server, frames)
    Process.put(@server_pdict_key, server)
    data
  end

  defp server_encode_headers(headers) do
    server = Process.get(@server_pdict_key)
    {server, hbf} = TestServer.encode_headers(server, headers)
    Process.put(@server_pdict_key, server)
    hbf
  end

  defp server_decode_headers(hbf) do
    server = Process.get(@server_pdict_key)
    {server, headers} = TestServer.decode_headers(server, hbf)
    Process.put(@server_pdict_key, server)
    headers
  end

  defp open_request(conn, body \\ nil) do
    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], body)
    assert is_reference(ref)
    {conn, ref}
  end
end
