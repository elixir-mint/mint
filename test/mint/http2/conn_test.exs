defmodule Mint.HTTP2Test do
  use ExUnit.Case, async: true

  import Mint.HTTP2.Frame
  import ExUnit.CaptureLog

  alias Mint.{HTTP2, HTTP2.TestServer}

  setup :start_server
  setup :maybe_start_connection

  test "unknown message", %{conn: conn} do
    assert HTTP2.stream(conn, :unknown_message) == :unknown
  end

  test "closed-socket messages are treated as errors", %{conn: conn} do
    assert {:error, %HTTP2{} = conn, :closed, []} = HTTP2.stream(conn, {:ssl_closed, conn.socket})

    refute HTTP2.open?(conn)
  end

  test "socket error messages are treated as errors", %{conn: conn} do
    message = {:ssl_error, conn.socket, :etimeout}
    assert {:error, %HTTP2{} = conn, :etimeout, []} = HTTP2.stream(conn, message)
    refute HTTP2.open?(conn)
  end

  test "receiving a frame on a stream with a stream ID bigger than our biggest is an error",
       %{server: server, conn: conn} do
    stream_id = 3

    server
    |> TestServer.expect(fn state, headers(stream_id: ^stream_id) ->
      TestServer.send_headers(state, _stream_id = 5, [{":status", "200"}], [:end_headers])
    end)
    |> TestServer.expect(fn state, goaway(error_code: :protocol_error) -> state end)

    {conn, _ref} = open_request(conn)
    assert {:error, %HTTP2{} = conn, :protocol_error, []} = stream_until_responses_or_error(conn)
  end

  describe "closed streams (RST_STREAM)" do
    setup :verify_no_frames_left_on_server

    test "server closes a stream with RST_STREAM", %{conn: conn, server: server} do
      TestServer.expect(server, fn state, headers(stream_id: stream_id) ->
        TestServer.send_frame(
          state,
          rst_stream(stream_id: stream_id, error_code: :protocol_error)
        )
      end)

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:error, ^ref, {:rst_stream, :protocol_error}}] = responses
      assert HTTP2.open?(conn)
    end

    test "when server sends frames after sending RST_STREAM it is ignored",
         %{conn: conn, server: server} do
      TestServer.expect(server, fn state, headers(stream_id: stream_id) ->
        state
        |> TestServer.send_frame(rst_stream(stream_id: stream_id, error_code: :cancel))
        |> TestServer.send_headers(stream_id, [{":status", "200"}], [:end_headers, :end_stream])
      end)

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert responses == [{:error, ref, {:rst_stream, :cancel}}]

      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
    end

    test "closing a stream with cancel_request/2", %{conn: conn, server: server} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        headers = [{":status", "200"}]
        state = TestServer.send_headers(state, stream_id, headers, [:end_headers])

        flags = set_flag(:data, :end_stream)
        TestServer.send_frame(state, data(stream_id: stream_id, data: "hello", flags: flags))
      end)
      |> TestServer.expect(fn state, rst_stream() = frame ->
        assert rst_stream(error_code: :cancel) = frame
        state
      end)
      |> TestServer.allow_anything()

      {conn, ref} = open_request(conn)
      {:ok, conn} = HTTP2.cancel_request(conn, ref)

      assert {:ok, %HTTP2{} = conn, responses} = stream_next_message(conn)
      assert responses == []

      assert HTTP2.open?(conn)
    end

    test "if we cancel a stream and the server sends DATA after, we ignore the DATA",
         %{server: server, conn: conn} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        TestServer.send_headers(state, stream_id, [{":status", "200"}], [:end_headers])
      end)
      |> TestServer.expect(fn state, rst_stream(stream_id: stream_id) ->
        flags = set_flag(:data, :end_stream)
        TestServer.send_frame(state, data(stream_id: stream_id, data: "hello", flags: flags))
      end)
      |> TestServer.allow_anything()

      {conn, ref} = open_request(conn)
      {:ok, conn} = HTTP2.cancel_request(conn, ref)

      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
      assert HTTP2.open?(conn)
    end

    test "receiving a RST_STREAM on a closed stream is ignored", %{server: server, conn: conn} do
      stream_id = 3

      server
      |> TestServer.expect(fn state, headers(stream_id: ^stream_id) ->
        headers = [{":status", "200"}]
        TestServer.send_headers(state, stream_id, headers, [:end_headers, :end_stream])
      end)
      |> TestServer.expect(fn state, rst_stream(stream_id: ^stream_id) ->
        TestServer.send_frames(state, [
          rst_stream(stream_id: stream_id, error_code: :no_error),
          rst_stream(stream_id: stream_id, error_code: :no_error)
        ])
      end)
      |> TestServer.allow_anything()

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
    end
  end

  describe "stream state transition nooks and crannies" do
    test "if client receives DATA after receiving a END_STREAM flag, it errors",
         %{server: server, conn: conn} do
      stream_id = 3

      server
      |> TestServer.expect(fn state, headers(stream_id: ^stream_id) ->
        headers = [{":status", "200"}]
        state = TestServer.send_headers(state, stream_id, headers, [:end_headers, :end_stream])

        flags = set_flags(:data, [:end_stream])
        TestServer.send_frame(state, data(stream_id: stream_id, data: "hello", flags: flags))
      end)
      |> TestServer.allow_anything()

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
    end

    test "if client receives HEADERS after receiving a END_STREAM flag, it errors",
         %{server: server, conn: conn} do
      stream_id = 3

      server
      |> TestServer.expect(fn state, headers(stream_id: ^stream_id) ->
        headers = [{":status", "200"}]
        state = TestServer.send_headers(state, stream_id, headers, [:end_headers, :end_stream])
        TestServer.send_headers(state, stream_id, headers, [:end_headers, :end_stream])
      end)
      |> TestServer.allow_anything()

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
    end
  end

  test "server closes the connection with GOAWAY", %{server: server, conn: conn} do
    server
    |> TestServer.expect(fn state, headers(stream_id: 3) -> state end)
    |> TestServer.expect(fn state, headers(stream_id: 5) -> state end)
    |> TestServer.expect(fn state, headers(stream_id: 7) ->
      frame =
        goaway(
          stream_id: 0,
          last_stream_id: 3,
          error_code: :protocol_error,
          debug_data: "debug data"
        )

      TestServer.send_frame(state, frame)
      :ok = :ssl.close(state.socket)
      %{state | socket: nil}
    end)

    {conn, _ref1} = open_request(conn)
    {conn, ref2} = open_request(conn)
    {conn, ref3} = open_request(conn)

    assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)

    assert [
             {:error, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:error, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert {:error, %HTTP2{} = conn, :closed, []} = stream_until_responses_or_error(conn)
    refute HTTP2.open?(conn)
  end

  describe "headers and continuation" do
    setup :verify_no_frames_left_on_server

    test "server splits headers into multiple CONTINUATION frames", %{server: server, conn: conn} do
      TestServer.expect(server, fn state, headers(stream_id: stream_id) ->
        {state, hbf} =
          TestServer.encode_headers(state, [{":status", "200"}, {"foo", "bar"}, {"baz", "bong"}])

        <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)

        state = TestServer.send_frame(state, headers(stream_id: stream_id, hbf: hbf1))

        state = TestServer.send_frame(state, continuation(stream_id: stream_id, hbf: hbf2))

        state =
          TestServer.send_frame(
            state,
            continuation(
              stream_id: stream_id,
              hbf: hbf3,
              flags: set_flag(:continuation, :end_headers)
            )
          )

        state
      end)

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, headers}] = responses
      assert headers == [{"foo", "bar"}, {"baz", "bong"}]

      assert HTTP2.open?(conn)
    end

    test "server sends a badly encoded header block fragment", %{conn: conn, server: server} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        flags = set_flag(:headers, :end_headers)
        frame = headers(stream_id: stream_id, hbf: "not a good hbf", flags: flags)
        TestServer.send_frame(state, frame)
      end)
      |> TestServer.expect(fn state, goaway() ->
        state
      end)

      {conn, _ref} = open_request(conn)

      assert {:error, %HTTP2{} = conn, :compression_error, []} =
               stream_until_responses_or_error(conn)

      refute HTTP2.open?(conn)
    end

    test "server sends a CONTINUATION frame outside of headers streaming",
         %{conn: conn, server: server} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        TestServer.send_frame(state, continuation(stream_id: stream_id, hbf: "hbf"))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :protocol_error) ->
        state
      end)

      {conn, _ref} = open_request(conn)

      assert {:error, %HTTP2{} = conn, :protocol_error, []} =
               stream_until_responses_or_error(conn)

      refute HTTP2.open?(conn)
    end

    test "server sends a non-CONTINUATION frame while streaming headers",
         %{conn: conn, server: server} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        state = TestServer.send_frame(state, headers(stream_id: stream_id, hbf: "hbf"))
        state = TestServer.send_frame(state, data(stream_id: stream_id, data: "some data"))
        state
      end)
      |> TestServer.expect(fn state, goaway(error_code: :protocol_error) ->
        state
      end)

      {conn, _ref} = open_request(conn)

      assert {:error, %HTTP2{} = conn, :protocol_error, []} =
               stream_until_responses_or_error(conn)

      refute HTTP2.open?(conn)
    end

    test "server sends HEADERS with END_STREAM but no END_HEADERS and then sends CONTINUATIONs",
         %{conn: conn, server: server} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        headers = [
          {":status", "200"},
          {"foo", "bar"},
          {"baz", "bong"}
        ]

        {state, hbf} = TestServer.encode_headers(state, headers)

        <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)

        TestServer.send_frames(state, [
          headers(stream_id: stream_id, hbf: hbf1, flags: set_flag(:headers, :end_stream)),
          continuation(stream_id: stream_id, hbf: hbf2),
          continuation(
            stream_id: stream_id,
            hbf: hbf3,
            flags: set_flag(:continuation, :end_headers)
          )
        ])
      end)
      |> TestServer.expect(fn state, rst_stream(error_code: :no_error) -> state end)

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, _headers}, {:done, ^ref}] = responses
      assert HTTP2.open?(conn)
    end

    test "server sends a response without a :status header", %{conn: conn, server: server} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        {state, hbf} = TestServer.encode_headers(state, [{"foo", "bar"}, {"baz", "bong"}])
        flags = set_flags(:headers, [:end_headers, :end_stream])
        TestServer.send_frame(state, headers(stream_id: stream_id, hbf: hbf, flags: flags))
      end)
      |> TestServer.expect(fn state, rst_stream() -> state end)

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:error, ^ref, {:protocol_error, :missing_status_header}}] = responses

      assert HTTP2.open?(conn)
    end

    test "client has to split headers because of max frame size", %{conn: conn, server: server} do
      server
      |> TestServer.expect(fn state, headers(stream_id: 3, hbf: hbf, flags: flags) ->
        assert flag_set?(flags, :headers, :end_stream)
        refute flag_set?(flags, :headers, :end_headers)
        Map.put(state, :current_hbf, hbf)
      end)
      |> TestServer.expect(fn state, continuation(stream_id: 3, hbf: hbf, flags: flags) ->
        refute flag_set?(flags, :continuation, :end_headers)
        Map.update!(state, :current_hbf, &(&1 <> hbf))
      end)
      |> TestServer.expect(fn state, continuation(stream_id: 3, hbf: hbf, flags: flags) ->
        assert flag_set?(flags, :continuation, :end_headers)
        hbf = Map.fetch!(state, :current_hbf) <> hbf
        {state, headers} = TestServer.decode_headers(state, hbf)
        assert [{":method", "GET"} | _] = headers

        TestServer.send_headers(state, 3, [{":status", "200"}], [:end_stream, :end_headers])
      end)
      |> TestServer.expect(fn state, rst_stream(stream_id: 3, error_code: :no_error) -> state end)

      # This is an empirical number of headers so that the minimum max frame size (~16kb) fits
      # between 2 and 3 times (so that we can test the behaviour above).
      headers = for i <- 1..400, do: {"a#{i}", String.duplicate("a", 100)}
      assert {:ok, conn, ref} = HTTP2.request(conn, "GET", "/", headers)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert HTTP2.open?(conn)
    end
  end

  describe "server pushes" do
    test "a PUSH_PROMISE frame and a few CONTINUATION frames are received",
         %{conn: conn, server: server} do
      promised_stream_id = 4

      TestServer.expect(server, fn state, headers(stream_id: stream_id) ->
        # Promised headers.
        {state, hbf} =
          TestServer.encode_headers(state, [
            {":method", "GET"},
            {"foo", "bar"},
            {"baz", "bong"}
          ])

        <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)

        # Normal headers.
        {state, hbf} = TestServer.encode_headers(state, [{":status", "200"}])

        state =
          TestServer.send_frames(state, [
            push_promise(stream_id: stream_id, hbf: hbf1, promised_stream_id: promised_stream_id),
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

        # Push-promise headers.
        {state, hbf} = TestServer.encode_headers(state, [{":status", "200"}])

        TestServer.send_frames(state, [
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
      end)
      |> TestServer.expect(fn state, rst_stream(error_code: :no_error) -> state end)

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)

      assert [
               {:push_promise, ^ref, promised_ref, headers},
               {:status, ^ref, 200},
               {:headers, ^ref, []},
               {:done, ^ref}
             ] = responses

      assert is_reference(promised_ref)
      assert headers == [{":method", "GET"}, {"foo", "bar"}, {"baz", "bong"}]

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)

      assert [
               {:status, ^promised_ref, 200},
               {:headers, ^promised_ref, []},
               {:data, ^promised_ref, "hello"},
               {:done, ^promised_ref}
             ] = responses

      assert HTTP2.open?(conn)
    end

    @tag connect: false
    test "receiving PUSH_PROMISE frame when SETTINGS_ENABLE_PUSH is false causes an error",
         %{server: server, port: port} do
      options = [transport_opts: [verify: :verify_none], client_settings: [enable_push: false]]
      {:ok, conn} = HTTP2.connect(:https, "localhost", port, options)

      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        {state, hbf} = TestServer.encode_headers(state, [{":method", "GET"}])

        TestServer.send_frame(
          state,
          push_promise(
            stream_id: stream_id,
            hbf: hbf,
            promised_stream_id: 4,
            flags: set_flags(:push_promise, [:end_headers])
          )
        )
      end)
      |> TestServer.expect(fn state, goaway() = frame ->
        assert goaway(frame, :error_code) == :protocol_error
        state
      end)

      {conn, _ref} = open_request(conn)
      assert {:error, %HTTP2{}, :protocol_error, []} = stream_until_responses_or_error(conn)
    end
  end

  describe "frame encoding errors by the server" do
    setup :verify_no_frames_left_on_server

    test "server sends a frame with the wrong stream id", %{server: server, conn: conn} do
      server
      |> TestServer.expect(fn state, headers() ->
        TestServer.send(state, encode_raw(_ping = 0x06, 0x00, 3, <<0::64>>))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :protocol_error) -> state end)

      {conn, _ref} = open_request(conn)

      assert {:error, %HTTP2{} = conn, :protocol_error, []} =
               stream_until_responses_or_error(conn)

      refute HTTP2.open?(conn)
    end

    test "server sends a frame with a bad size", %{server: server, conn: conn} do
      server
      |> TestServer.expect(fn state, headers() ->
        # Payload should be 8 bytes long, but is empty here.
        TestServer.send(state, encode_raw(_ping = 0x06, 0x00, 3, <<>>))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :frame_size_error) -> state end)

      {conn, _ref} = open_request(conn)

      assert {:error, %HTTP2{} = conn, :frame_size_error, []} =
               stream_until_responses_or_error(conn)

      refute HTTP2.open?(conn)
    end
  end

  describe "flow control" do
    setup :verify_no_frames_left_on_server

    test "server sends a WINDOW_UPDATE with too big of a size on a stream",
         %{server: server, conn: conn} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        max_window_size = 2_147_483_647

        TestServer.send_frame(
          state,
          window_update(stream_id: stream_id, window_size_increment: max_window_size)
        )
      end)
      |> TestServer.expect(fn state, rst_stream() -> state end)

      {conn, ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:error, ^ref, :flow_control_error}] = responses
      assert HTTP2.open?(conn)
    end

    test "server sends a WINDOW_UPDATE with too big of a size on the connection level",
         %{server: server, conn: conn} do
      server
      |> TestServer.expect(fn state, headers() ->
        max_window_size = 2_147_483_647

        TestServer.send_frame(
          state,
          window_update(stream_id: 0, window_size_increment: max_window_size)
        )
      end)
      |> TestServer.expect(fn state, goaway(error_code: :flow_control_error) -> state end)

      {conn, _ref} = open_request(conn)

      assert {:error, %HTTP2{} = conn, :flow_control_error, []} =
               stream_until_responses_or_error(conn)

      refute HTTP2.open?(conn)
    end

    test "server violates client's max frame size", %{server: server, conn: conn} do
      server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        data = :binary.copy(<<0>>, 100_000)
        TestServer.send_frame(state, data(stream_id: stream_id, data: data))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :frame_size_error) -> state end)

      {conn, _ref} = open_request(conn)

      assert {:error, %HTTP2{} = conn, :frame_size_error, []} =
               stream_until_responses_or_error(conn)

      refute HTTP2.open?(conn)
    end

    test "client splits data automatically based on server's max frame size",
         %{server: server, conn: conn} do
      max_frame_size = HTTP2.get_setting(conn, :max_frame_size)

      server
      |> TestServer.expect(fn state, headers(stream_id: 3) -> state end)
      |> TestServer.expect(fn state, data(stream_id: 3, flags: 0x00, data: data) ->
        assert data == :binary.copy(<<0>>, max_frame_size)
        state
      end)
      |> TestServer.expect(fn state, data(stream_id: 3, flags: 0x01, data: data) ->
        assert data == <<0>>
        TestServer.send_headers(state, 3, [{":status", "200"}], [:end_headers, :end_stream])
      end)
      |> TestServer.expect(fn state, rst_stream(error_code: :no_error) -> state end)

      body = :binary.copy(<<0>>, max_frame_size + 1)

      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], body)

      assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses
      assert HTTP2.open?(conn)
    end
  end

  describe "settings" do
    setup :verify_no_frames_left_on_server

    test "client can send settings to server", %{server: server, conn: conn} do
      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)

      TestServer.expect(server, fn state, settings() = frame ->
        assert settings(params: [max_concurrent_streams: 123]) = frame
        frame = settings(stream_id: 0, flags: set_flag(:settings, :ack), params: [])
        TestServer.send_frame(state, frame)
      end)

      {:ok, conn} = HTTP2.put_settings(conn, max_concurrent_streams: 123)
      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
      assert HTTP2.open?(conn)
    end

    test "trying to send unknown settings fails", %{conn: conn} do
      assert_raise ArgumentError, ":header_table_size must be an integer, got: :oops", fn ->
        HTTP2.put_settings(conn, header_table_size: :oops)
      end

      assert_raise ArgumentError, "unknown setting parameter :oops", fn ->
        HTTP2.put_settings(conn, oops: 1)
      end
    end

    test "client can read server settings", %{conn: conn} do
      assert HTTP2.get_setting(conn, :max_concurrent_streams) == 100
      assert HTTP2.get_setting(conn, :enable_push) == true

      assert_raise ArgumentError, "unknown HTTP/2 setting: :unknown", fn ->
        HTTP2.get_setting(conn, :unknown)
      end
    end

    test "server can update the initial window size and affect open streams",
         %{server: server, conn: conn} do
      server
      |> TestServer.expect(fn state, headers(stream_id: 3) ->
        TestServer.send_frame(state, settings(params: [initial_window_size: 100]))
      end)
      |> TestServer.expect(fn state, settings(flags: 0x01, params: []) -> state end)

      {conn, _ref} = open_request(conn)

      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
      assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
      assert conn.initial_window_size == 100

      # This stream is half_closed_local, so there's not point in updating its window size since
      # we won't send anything on it anymore.
      assert conn.streams[3].window_size == 65535
    end
  end

  test "streaming a request", %{server: server, conn: conn} do
    server
    |> TestServer.expect(fn state, headers(stream_id: 3, flags: flags) ->
      refute flag_set?(flags, :headers, :end_stream)
      state
    end)
    |> TestServer.expect(fn state, data(stream_id: 3, data: data, flags: flags) ->
      refute flag_set?(flags, :data, :end_stream)
      assert data == "foo"
      state
    end)
    |> TestServer.expect(fn state, data(stream_id: 3, data: data, flags: flags) ->
      refute flag_set?(flags, :data, :end_stream)
      assert data == "bar"
      state
    end)
    |> TestServer.expect(fn state, data(stream_id: 3, data: data, flags: flags) ->
      assert flag_set?(flags, :data, :end_stream)
      assert data == ""

      TestServer.send_headers(state, 3, [{":status", "200"}], [:end_headers, :end_stream])
    end)

    {:ok, conn, ref} = HTTP2.request(conn, "GET", "/", [], :stream)
    assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, "foo")
    assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, "bar")
    assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, :eof)

    assert {:ok, %HTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
    assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses
    assert HTTP2.open?(conn)
  end

  test "close/1", %{conn: conn, server: server} do
    TestServer.expect(server, fn state, settings() ->
      frame = settings(stream_id: 0, flags: set_flag(:settings, :ack), params: [])
      TestServer.send_frame(state, frame)
    end)

    assert HTTP2.open?(conn)

    # Ensure the connection is established before closing
    {:ok, conn} = HTTP2.put_settings(conn, max_concurrent_streams: 10)
    {:ok, conn, []} = stream_next_message(conn)

    assert {:ok, conn} = HTTP2.close(conn)
    refute HTTP2.open?(conn)
  end

  test "PRIORITY frames are ignored", %{server: server, conn: conn} do
    TestServer.expect(server, fn state, headers(stream_id: stream_id) ->
      frame = priority(stream_id: stream_id, exclusive?: false, stream_dependency: 1, weight: 1)
      TestServer.send_frame(state, frame)
    end)

    {conn, _ref} = open_request(conn)
    assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)

    log =
      capture_log(fn ->
        assert {:ok, %HTTP2{} = conn, []} = stream_next_message(conn)
      end)

    assert log =~ "Ignoring PRIORITY frame"
  end

  defp stream_next_message(conn) do
    assert_receive message, 1000
    HTTP2.stream(conn, message)
  end

  defp stream_until_responses_or_error(conn) do
    case stream_next_message(conn) do
      {:ok, %HTTP2{} = conn, []} -> stream_until_responses_or_error(conn)
      other -> other
    end
  end

  defp start_server(_context) do
    {:ok, server} = TestServer.start_link()
    port = TestServer.port(server)
    TestServer.start_accepting(server)
    [port: port, server: server]
  end

  defp maybe_start_connection(context) do
    if context[:connect] == false do
      []
    else
      {:ok, conn} =
        HTTP2.connect(
          :https,
          "localhost",
          context.port,
          transport_opts: [verify: :verify_none]
        )

      [conn: conn]
    end
  end

  defp verify_no_frames_left_on_server(context) do
    assert TestServer.verify(context.server) == :ok
    :ok
  end

  defp open_request(conn) do
    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [])
    assert is_reference(ref)
    {conn, ref}
  end
end
