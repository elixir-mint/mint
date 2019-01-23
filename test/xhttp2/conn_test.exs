defmodule XHTTP2.XHTTP2Test do
  use ExUnit.Case, async: true

  import XHTTP2.Frame

  alias XHTTP2.TestServer

  setup context do
    if context[:connect] == false do
      []
    else
      {:ok, server} = TestServer.start_link()
      port = TestServer.port(server)
      TestServer.start_accepting(server)

      {:ok, conn} =
        XHTTP2.connect(
          :https,
          "localhost",
          port,
          transport_opts: [verify: :verify_none]
        )

      [conn: conn, server: server]
    end
  end

  test "unknown message", %{conn: conn} do
    assert XHTTP2.stream(conn, :unknown_message) == :unknown
  end

  test "closed-socket messages are treated as errors", %{conn: conn} do
    assert {:error, %XHTTP2{} = conn, :closed, []} =
             XHTTP2.stream(conn, {:ssl_closed, conn.socket})

    refute XHTTP2.open?(conn)
  end

  test "socket error messages are treated as errors", %{conn: conn} do
    message = {:ssl_error, conn.socket, :etimeout}
    assert {:error, %XHTTP2{} = conn, :etimeout, []} = XHTTP2.stream(conn, message)
    refute XHTTP2.open?(conn)
  end

  test "server closes a stream with RST_STREAM", context do
    TestServer.expect(context.server, fn state, headers(stream_id: stream_id) ->
      TestServer.send_frame(state, rst_stream(stream_id: stream_id, error_code: :protocol_error))
    end)

    {:ok, conn, ref} = XHTTP2.request(context.conn, "GET", "/", [])

    assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
    assert [{:error, ^ref, {:rst_stream, :protocol_error}}] = responses
    assert XHTTP2.open?(conn)
  end

  test "server closes the connection with GOAWAY", context do
    context.server
    |> TestServer.expect(fn state, headers(stream_id: 3) -> state end)
    |> TestServer.expect(fn state, headers(stream_id: 5) -> state end)
    |> TestServer.expect(fn state, headers(stream_id: 7) ->
      code = :protocol_error
      frame = goaway(stream_id: 0, last_stream_id: 3, error_code: code, debug_data: "debug data")
      TestServer.send_frame(state, frame)
      :ok = :ssl.close(state.socket)
      %{state | socket: nil}
    end)

    {:ok, conn, _ref1} = XHTTP2.request(context.conn, "GET", "/", [])
    {:ok, conn, ref2} = XHTTP2.request(conn, "GET", "/", [])
    {:ok, conn, ref3} = XHTTP2.request(conn, "GET", "/", [])

    assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)

    assert [
             {:error, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:error, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert {:error, %XHTTP2{} = conn, :closed, []} = stream_until_responses_or_error(conn)
    refute XHTTP2.open?(conn)
  end

  describe "headers and continuation" do
    test "server splits headers into multiple CONTINUATION frames", context do
      TestServer.expect(context.server, fn state, headers(stream_id: stream_id) ->
        headers = [
          {:store_name, ":status", "200"},
          {:store_name, "foo", "bar"},
          {:store_name, "baz", "bong"}
        ]

        {state, hbf} = TestServer.encode_headers(state, headers)

        <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)

        frame1 = headers(stream_id: stream_id, hbf: hbf1)
        state = TestServer.send_frame(state, frame1)

        frame2 = continuation(stream_id: stream_id, hbf: hbf2)
        state = TestServer.send_frame(state, frame2)

        frame3 = continuation(stream_id: stream_id, hbf: hbf3, flags: 0x04)
        state = TestServer.send_frame(state, frame3)

        state
      end)

      {:ok, conn, ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, _headers}] = responses

      assert XHTTP2.open?(conn)
    end

    test "server sends a badly encoded header block", context do
      context.server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        flags = set_flag(:headers, :end_headers)
        frame = headers(stream_id: stream_id, hbf: "not a good hbf", flags: flags)
        TestServer.send_frame(state, frame)
      end)
      |> TestServer.expect(fn state, goaway() ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:error, %XHTTP2{} = conn, :compression_error, []} =
               stream_until_responses_or_error(conn)

      refute XHTTP2.open?(conn)
    end

    test "server sends a CONTINUATION frame outside of headers streaming", context do
      context.server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        TestServer.send_frame(state, continuation(stream_id: stream_id, hbf: "hbf"))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :protocol_error) ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:error, %XHTTP2{} = conn, :protocol_error, []} =
               stream_until_responses_or_error(conn)

      refute XHTTP2.open?(conn)
    end

    test "server sends a non-CONTINUATION frame while streaming headers", context do
      context.server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        # Headers are streaming but we send a non-CONTINUATION frame.
        headers = headers(stream_id: stream_id, hbf: "hbf")
        data = data(stream_id: stream_id, data: "some data")
        TestServer.send(state, [encode(headers), encode(data)])
      end)
      |> TestServer.expect(fn state, goaway(error_code: :protocol_error) ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:error, %XHTTP2{} = conn, :protocol_error, []} =
               stream_until_responses_or_error(conn)

      refute XHTTP2.open?(conn)
    end

    test "server sends a HEADERS with END_STREAM set but not END_HEADERS", context do
      TestServer.expect(context.server, fn state, headers(stream_id: stream_id) ->
        headers = [
          {:store_name, ":status", "200"},
          {:store_name, "foo", "bar"},
          {:store_name, "baz", "bong"}
        ]

        {state, hbf} = TestServer.encode_headers(state, headers)

        <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)

        frame1 = headers(stream_id: stream_id, hbf: hbf1, flags: set_flag(:headers, :end_stream))
        state = TestServer.send_frame(state, frame1)

        frame2 = continuation(stream_id: stream_id, hbf: hbf2)
        state = TestServer.send_frame(state, frame2)

        flags = set_flag(:continuation, :end_headers)
        frame3 = continuation(stream_id: stream_id, hbf: hbf3, flags: flags)
        state = TestServer.send_frame(state, frame3)

        state
      end)

      {:ok, conn, ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, _headers}, {:done, ^ref}] = responses
      assert XHTTP2.open?(conn)
    end

    test "server sends a response without a :status header", context do
      context.server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        headers = [
          {:store_name, "foo", "bar"},
          {:store_name, "baz", "bong"}
        ]

        {state, hbf} = TestServer.encode_headers(state, headers)

        flags = set_flags(:headers, [:end_headers, :end_stream])
        TestServer.send_frame(state, headers(stream_id: stream_id, hbf: hbf, flags: flags))
      end)
      |> TestServer.expect(fn state, rst_stream() ->
        state
      end)

      {:ok, conn, ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:error, ^ref, {:protocol_error, :missing_status_header}}] = responses
      assert XHTTP2.open?(conn)
    end

    test "client has to split headers because of max frame size", context do
      context.server
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
        assert [{":method", "METH"} | _] = headers

        {state, hbf} = TestServer.encode_headers(state, [{:store_name, ":status", "200"}])

        flags = set_flags(:headers, [:end_stream, :end_headers])
        TestServer.send_frame(state, headers(stream_id: 3, hbf: hbf, flags: flags))
      end)

      # This is an empirical number of headers so that the minimum max frame size (~16kb) fits
      # between 2 and 3 times (so that we can test the behaviour above).
      headers = for i <- 1..400, do: {"a#{i}", String.duplicate("a", 100)}
      assert {:ok, conn, ref} = XHTTP2.request(context.conn, "METH", "/", headers)

      assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert XHTTP2.open?(conn)
    end
  end

  describe "frame encoding errors by the server" do
    test "server sends a frame with the wrong stream id", context do
      context.server
      |> TestServer.expect(fn state, headers() ->
        TestServer.send(state, encode_raw(_ping = 0x06, 0x00, 3, <<0::64>>))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :protocol_error) ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:error, %XHTTP2{} = conn, :protocol_error, []} =
               stream_until_responses_or_error(conn)

      refute XHTTP2.open?(conn)
    end

    test "server sends a frame with a bad size", context do
      context.server
      |> TestServer.expect(fn state, headers() ->
        # Payload should be 8 bytes long.
        TestServer.send(state, encode_raw(_ping = 0x06, 0x00, 3, <<>>))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :frame_size_error) ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:error, %XHTTP2{} = conn, :frame_size_error, []} =
               stream_until_responses_or_error(conn)

      refute XHTTP2.open?(conn)
    end
  end

  describe "flow control" do
    test "server sends a WINDOW_UPDATE with too big of a size on a stream", context do
      max_window_size = 2_147_483_647

      context.server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        frame = window_update(stream_id: stream_id, window_size_increment: max_window_size)
        TestServer.send_frame(state, frame)
      end)
      |> TestServer.expect(fn state, rst_stream() ->
        state
      end)

      {:ok, conn, ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:error, ^ref, :flow_control_error}] = responses
      assert XHTTP2.open?(conn)
    end

    test "server sends a WINDOW_UPDATE with too big of a size on the connection level", context do
      max_window_size = 2_147_483_647

      context.server
      |> TestServer.expect(fn state, headers() ->
        frame = window_update(stream_id: 0, window_size_increment: max_window_size)
        TestServer.send_frame(state, frame)
      end)
      |> TestServer.expect(fn state, goaway(error_code: :flow_control_error) ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:error, %XHTTP2{} = conn, :flow_control_error, []} =
               stream_until_responses_or_error(conn)

      refute XHTTP2.open?(conn)
    end

    test "server violates client's max frame size", context do
      context.server
      |> TestServer.expect(fn state, headers(stream_id: stream_id) ->
        data = :binary.copy(<<0>>, 100_000)
        TestServer.send_frame(state, data(stream_id: stream_id, data: data))
      end)
      |> TestServer.expect(fn state, goaway(error_code: :frame_size_error) ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:error, %XHTTP2{} = conn, :frame_size_error, []} =
               stream_until_responses_or_error(conn)

      refute XHTTP2.open?(conn)
    end

    test "client splits data automatically based on server's max frame size", context do
      max_frame_size = XHTTP2.get_setting(context.conn, :max_frame_size)

      context.server
      |> TestServer.expect(fn state, headers(stream_id: 3) ->
        state
      end)
      |> TestServer.expect(fn state, data(stream_id: 3, flags: 0x00, data: data) ->
        assert data == :binary.copy(<<0>>, max_frame_size)
        state
      end)
      |> TestServer.expect(fn state, data(stream_id: 3, flags: 0x01, data: data) ->
        assert data == <<0>>
        {state, hbf} = TestServer.encode_headers(state, [{:store_name, ":status", "200"}])
        flags = set_flags(:headers, [:end_stream, :end_headers])
        TestServer.send_frame(state, headers(stream_id: 3, hbf: hbf, flags: flags))
      end)

      body = :binary.copy(<<0>>, max_frame_size + 1)
      assert {:ok, %XHTTP2{} = conn, ref} = XHTTP2.request(context.conn, "GET", "/", [], body)

      assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses
      assert XHTTP2.open?(conn)
    end
  end

  describe "settings" do
    test "client can send settings to server", context do
      assert {:ok, %XHTTP2{} = conn, []} = stream_next_message(context.conn)

      TestServer.expect(context.server, fn state,
                                           settings(params: [max_concurrent_streams: 123]) ->
        frame = settings(stream_id: 0, flags: set_flag(:settings, :ack), params: [])
        TestServer.send_frame(state, frame)
      end)

      {:ok, conn} = XHTTP2.put_settings(conn, max_concurrent_streams: 123)
      assert {:ok, %XHTTP2{} = conn, []} = stream_next_message(conn)
      assert XHTTP2.open?(conn)
    end

    test "client can read server settings", %{conn: conn} do
      assert XHTTP2.get_setting(conn, :max_concurrent_streams) == 100
      assert XHTTP2.get_setting(conn, :enable_push) == true

      assert_raise ArgumentError, "unknown HTTP/2 setting: :unknown", fn ->
        XHTTP2.get_setting(conn, :unknown)
      end
    end

    test "server can update the initial window size and affect open streams", context do
      context.server
      |> TestServer.expect(fn state, headers(stream_id: 3) ->
        TestServer.send_frame(state, settings(params: [initial_window_size: 100]))
      end)
      |> TestServer.expect(fn state, settings(flags: 0x01, params: []) ->
        state
      end)

      {:ok, conn, _ref} = XHTTP2.request(context.conn, "GET", "/", [])

      assert {:ok, %XHTTP2{} = conn, []} = stream_next_message(conn)
      assert {:ok, %XHTTP2{} = conn, []} = stream_next_message(conn)
      assert conn.initial_window_size == 100

      # This stream is half_closed_local, so there's not point in updating its window size since
      # we won't send anything on it anymore.
      assert conn.streams[3].window_size == 65535
    end
  end

  test "streaming a request", context do
    context.server
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

      {state, hbf} = TestServer.encode_headers(state, [{:store_name, ":status", "200"}])
      flags = set_flags(:headers, [:end_headers, :end_stream])
      TestServer.send_frame(state, headers(stream_id: 3, hbf: hbf, flags: flags))
    end)

    {:ok, conn, ref} = XHTTP2.request(context.conn, "GET", "/", [], :stream)
    assert {:ok, conn} = XHTTP2.stream_request_body(conn, ref, "foo")
    assert {:ok, conn} = XHTTP2.stream_request_body(conn, ref, "bar")
    assert {:ok, conn} = XHTTP2.stream_request_body(conn, ref, :eof)

    assert {:ok, %XHTTP2{} = conn, responses} = stream_until_responses_or_error(conn)
    assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses
    assert XHTTP2.open?(conn)
  end

  defp stream_next_message(conn) do
    assert_receive message, 1000
    XHTTP2.stream(conn, message)
  end

  defp stream_until_responses_or_error(conn) do
    case stream_next_message(conn) do
      {:ok, %XHTTP2{} = conn, []} -> stream_until_responses_or_error(conn)
      other -> other
    end
  end
end
