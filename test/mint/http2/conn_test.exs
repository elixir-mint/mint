defmodule Mint.HTTP2Test do
  use ExUnit.Case, async: true

  import Mint.HTTP2.Frame
  import ExUnit.CaptureLog

  alias Mint.{
    HTTPError,
    HTTP2,
    HTTP2.TestServer,
    TransportError
  }

  setup :start_connection

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

  describe "stream/2 with unknown messages or error messages" do
    test "unknown message", %{conn: conn} do
      assert HTTP2.stream(conn, :unknown_message) == :unknown
    end

    test "closed-socket messages are treated as errors", %{conn: conn} do
      assert {:error, %HTTP2{} = conn, %TransportError{reason: :closed}, []} =
               HTTP2.stream(conn, {:ssl_closed, conn.socket})

      refute HTTP2.open?(conn)
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
      assert_http2_error error, {:rst_stream, :protocol_error}

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
      assert_http2_error error, {:rst_stream, :cancel}

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

    test "receiving a RST_STREAM on a closed stream is ignored", %{conn: conn} do
      {conn, ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert_recv_frames [rst_stream(stream_id: ^stream_id)]

      assert {:ok, %HTTP2{} = conn, []} =
               stream_frames(conn, [
                 rst_stream(stream_id: stream_id, error_code: :no_error),
                 rst_stream(stream_id: stream_id, error_code: :no_error)
               ])

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

  describe "closing the connection" do
    test "server closes the connection with GOAWAY", %{conn: conn} do
      {conn, _ref1} = open_request(conn)
      {conn, ref2} = open_request(conn)
      {conn, ref3} = open_request(conn)

      assert_recv_frames [headers(), headers(), headers()]

      assert {:ok, %HTTP2{} = conn, responses} =
               stream_frames(conn, [
                 goaway(
                   stream_id: 0,
                   last_stream_id: 3,
                   error_code: :protocol_error,
                   debug_data: "debug data"
                 )
               ])

      assert [
               {:error, ^ref2, error2},
               {:error, ^ref3, error3}
             ] = responses

      assert_http2_error error2, {:goaway, :protocol_error, "debug data"}
      assert_http2_error error3, {:goaway, :protocol_error, "debug data"}

      :ssl.close(server_get_socket())

      assert_receive message

      assert {:error, %HTTP2{} = conn, %TransportError{reason: :closed}, []} =
               HTTP2.stream(conn, message)

      refute HTTP2.open?(conn)
    end

    test "client closes the connection with close/1", %{conn: conn} do
      assert {:ok, conn} = HTTP2.close(conn)

      assert_recv_frames [goaway(error_code: :no_error)]

      refute HTTP2.open?(conn)
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

      assert_recv_frames [rst_stream(error_code: :no_error)]

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
      assert_http2_error error, {:protocol_error, :missing_status_header}

      assert_recv_frames [rst_stream(error_code: :protocol_error)]

      assert HTTP2.open?(conn)
    end

    test "client has to split headers because of max frame size", %{conn: conn} do
      # This is an empirical number of headers so that the minimum max frame size (~16kb) fits
      # between 2 and 3 times (so that we can test the behaviour above).
      headers = for i <- 1..400, do: {"a#{i}", String.duplicate("a", 100)}
      assert {:ok, conn, _ref} = HTTP2.request(conn, "GET", "/", headers)

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

      assert {:error, %HTTP2{} = conn, error} = HTTP2.request(conn, "GET", "/", [])

      assert_http2_error error, {:max_header_list_size_exceeded, _, 20}

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

      assert {:error, %HTTP2{} = conn, error, responses} =
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
               {:push_promise, ^ref, promised_ref2, _},
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:done, ^ref}
             ] = responses

      assert_recv_frames [rst_stream(stream_id: ^stream_id, error_code: :no_error)]

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
      assert_http2_error error, :flow_control_error

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

    test "get_window_size/2 raises if the request is not found", %{conn: conn} do
      assert_raise ArgumentError, ~r/request with request reference .+ was not found/, fn ->
        HTTP2.get_window_size(conn, {:request, make_ref()})
      end
    end
  end

  describe "settings" do
    test "put_settings/2 can be used to send settings to server", %{conn: conn} do
      {:ok, conn} = HTTP2.put_settings(conn, max_concurrent_streams: 123)

      assert_recv_frames [settings() = frame]
      assert settings(frame, :params) == [max_concurrent_streams: 123]
      assert settings(frame, :flags) == set_flags(:settings, [])

      assert {:ok, %HTTP2{} = conn, []} =
               stream_frames(conn, [
                 settings(flags: set_flags(:settings, [:ack]), params: [])
               ])

      assert HTTP2.open?(conn)
    end

    test "put_settings/2 fails with unknown settings", %{conn: conn} do
      assert_raise ArgumentError, ":header_table_size must be an integer, got: :oops", fn ->
        HTTP2.put_settings(conn, header_table_size: :oops)
      end

      assert_raise ArgumentError, "unknown setting parameter :oops", fn ->
        HTTP2.put_settings(conn, oops: 1)
      end
    end

    test "get_server_setting/2 can be used to read server settings", %{conn: conn} do
      assert HTTP2.get_server_setting(conn, :max_concurrent_streams) == 100
      assert HTTP2.get_server_setting(conn, :enable_push) == true
    end

    test "get_server_setting/2 fails with unknown settings", %{conn: conn} do
      assert_raise ArgumentError, "unknown HTTP/2 setting: :unknown", fn ->
        HTTP2.get_server_setting(conn, :unknown)
      end
    end

    test "server can update the initial window size and affect open streams",
         %{conn: conn} do
      {conn, _ref} = open_request(conn)

      assert_recv_frames [headers(stream_id: stream_id)]

      {:ok, %HTTP2{} = conn, []} =
        stream_frames(conn, [settings(params: [initial_window_size: 100])])

      # TODO: likely not ideal to peek into the connection here.
      assert conn.server_settings.initial_window_size == 100
      # This stream is half_closed_local, so there's not point in updating its window size since
      # we won't send anything on it anymore.
      assert conn.streams[stream_id].window_size == 65535

      assert_recv_frames [settings() = frame]
      assert settings(frame, :flags) == set_flags(:settings, [:ack])
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

      assert {:error, %HTTP2{} = conn, error} = HTTP2.stream_request_body(conn, ref, "foo")
      assert_http2_error error, :request_is_not_streaming

      assert HTTP2.open?(conn)
    end

    test "streaming to an unknown request returns an error", %{conn: conn} do
      assert {:error, %HTTP2{} = conn, error} = HTTP2.stream_request_body(conn, make_ref(), "x")
      assert_http2_error error, :unknown_request_to_stream
      assert HTTP2.open?(conn)
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
      assert {:ok, %HTTP2{} = conn, []} = stream_frames(conn, [ping(opaque_data: opaque_data)])
      assert_recv_frames [ping(opaque_data: ^opaque_data)]
    end

    test "if the server sends a PING ack but no PING requests are pending we emit a warning",
         %{conn: conn} do
      opaque_data = :binary.copy(<<0>>, 8)

      assert capture_log(fn ->
               assert {:ok, %HTTP2{} = conn, []} =
                        stream_frames(conn, [
                          ping(opaque_data: opaque_data, flags: set_flags(:ping, [:ack]))
                        ])
             end) =~ "Received PING ack but no PING requests are pending"
    end

    @tag :focus
    test "if the server sends a PING ack but no PING requests match we emit a warning",
         %{conn: conn} do
      assert {:ok, conn, ref} = HTTP2.ping(conn, <<1, 2, 3, 4, 5, 6, 7, 8>>)
      opaque_data = <<1, 2, 3, 4, 5, 6, 7, 0>>

      assert capture_log(fn ->
               assert {:ok, %HTTP2{} = conn, []} =
                        stream_frames(conn, [
                          ping(opaque_data: opaque_data, flags: set_flags(:ping, [:ack]))
                        ])
             end) =~ "Received PING ack that doesn't match next PING request in the queue"
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

  @pdict_key {__MODULE__, :http2_test_server}

  defp start_connection(context) do
    default_options = [transport_opts: [verify: :verify_none]]
    options = Keyword.merge(default_options, context[:connect_options] || [])
    {conn, server} = TestServer.connect(options, context[:server_settings] || [])

    Process.put(@pdict_key, server)

    [conn: conn]
  end

  defp recv_next_frames(n) do
    server = Process.get(@pdict_key)
    TestServer.recv_next_frames(server, n)
  end

  defp stream_frames(conn, frames) do
    server = Process.get(@pdict_key)
    {server, data} = TestServer.encode_frames(server, frames)
    Process.put(@pdict_key, server)
    HTTP2.stream(conn, {:ssl, conn.socket, data})
  end

  defp server_encode_headers(headers) do
    server = Process.get(@pdict_key)
    {server, hbf} = TestServer.encode_headers(server, headers)
    Process.put(@pdict_key, server)
    hbf
  end

  defp server_decode_headers(hbf) do
    server = Process.get(@pdict_key)
    {server, headers} = TestServer.decode_headers(server, hbf)
    Process.put(@pdict_key, server)
    headers
  end

  defp server_get_socket() do
    server = Process.get(@pdict_key)
    TestServer.get_socket(server)
  end

  defp open_request(conn, body \\ nil) do
    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], body)
    assert is_reference(ref)
    {conn, ref}
  end
end
