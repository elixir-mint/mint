defmodule XHTTP2.ConnTest do
  use ExUnit.Case, async: true

  import XHTTP2.Frame

  alias XHTTP2.{
    Conn,
    Server,
    HPACK
  }

  setup context do
    if context[:connect] == false do
      []
    else
      {:ok, server} = Server.start()
      port = Server.port(server)
      Server.start_accepting(server)
      {:ok, conn} = Conn.connect("localhost", port, transport: :ssl)

      on_exit(fn ->
        Server.stop(server)
      end)

      [conn: conn, server: server]
    end
  end

  test "using an unknown transport raises an error" do
    message = "the :transport option must be either :gen_tcp or :ssl, got: :some_transport"

    assert_raise ArgumentError, message, fn ->
      Conn.connect("localhost", 80, transport: :some_transport)
    end
  end

  test "unknown message", %{conn: conn} do
    assert Conn.stream(conn, :unknown_message) == :unknown
  end

  test "closed-socket messages are treated as errors", %{conn: conn} do
    assert {:error, %Conn{} = conn, :closed, []} = Conn.stream(conn, {:ssl_closed, conn.socket})
    refute Conn.open?(conn)
  end

  test "socket error messages are treated as errors", %{conn: conn} do
    message = {:ssl_error, conn.socket, :etimeout}
    assert {:error, %Conn{} = conn, :etimeout, []} = Conn.stream(conn, message)
    refute Conn.open?(conn)
  end

  test "server closes a stream with RST_STREAM", context do
    Server.expect(context.server, fn state, headers(stream_id: stream_id) ->
      frame = rst_stream(stream_id: stream_id, error_code: :protocol_error)
      :ssl.send(state.socket, encode(frame))
    end)

    {:ok, conn, ref} = Conn.request(context.conn, "GET", "/", [])

    assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)
    assert [{:closed, ^ref, {:rst_stream, :protocol_error}}] = responses
    assert Conn.open?(conn)
  end

  test "server closes the connection with GOAWAY", context do
    context.server
    |> Server.expect(fn state, headers(stream_id: 3) -> state end)
    |> Server.expect(fn state, headers(stream_id: 5) -> state end)
    |> Server.expect(fn state, headers(stream_id: 7) ->
      code = :protocol_error
      frame = goaway(stream_id: 0, last_stream_id: 3, error_code: code, debug_data: "debug data")
      :ok = :ssl.send(state.socket, encode(frame))
      :ok = :ssl.close(state.socket)
      %{state | socket: nil}
    end)

    {:ok, conn, _ref1} = Conn.request(context.conn, "GET", "/", [])
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/", [])

    assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)

    assert [
             {:closed, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:closed, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert {:error, %Conn{} = conn, :closed, []} = stream_messages_until_error(conn)
    refute Conn.open?(conn)
  end

  describe "headers and continuation" do
    test "server splits headers into multiple CONTINUATION frames", context do
      Server.expect(context.server, fn state, headers(stream_id: stream_id) ->
        headers = [
          {:store_name, ":status", "200"},
          {:store_name, "foo", "bar"},
          {:store_name, "baz", "bong"}
        ]

        {hbf, encode_table} = HPACK.encode(headers, state.encode_table)
        state = put_in(state.encode_table, encode_table)

        <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)
        frame1 = headers(stream_id: stream_id, hbf: hbf1)
        :ok = :ssl.send(state.socket, encode(frame1))
        frame2 = continuation(stream_id: stream_id, hbf: hbf2)
        :ok = :ssl.send(state.socket, encode(frame2))
        frame3 = continuation(stream_id: stream_id, hbf: hbf3, flags: 0x04)
        :ok = :ssl.send(state.socket, encode(frame3))
        state
      end)

      {:ok, conn, ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:status, ^ref, "200"}, {:headers, ^ref, _headers}] = responses

      assert Conn.open?(conn)
    end

    test "server sends a badly encoded header block", context do
      context.server
      |> Server.expect(fn state, headers(stream_id: stream_id) ->
        flags = set_flag(:headers, :end_headers)
        frame = headers(stream_id: stream_id, hbf: "not a good hbf", flags: flags)
        :ssl.send(state.socket, encode(frame))
      end)
      |> Server.expect(fn state, goaway() -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:error, %Conn{} = conn, :compression_error, []} = stream_messages_until_error(conn)
      refute Conn.open?(conn)
    end

    test "server sends a CONTINUATION frame outside of headers streaming", context do
      context.server
      |> Server.expect(fn state, headers(stream_id: stream_id) ->
        frame = continuation(stream_id: stream_id, hbf: "hbf")
        :ssl.send(state.socket, encode(frame))
      end)
      |> Server.expect(fn state, goaway(error_code: :protocol_error) -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:error, %Conn{} = conn, :protocol_error, []} = stream_messages_until_error(conn)
      refute Conn.open?(conn)
    end

    test "server sends a non-CONTINUATION frame while streaming headers", context do
      context.server
      |> Server.expect(fn state, headers(stream_id: stream_id) ->
        # Headers are streaming but we send a non-CONTINUATION frame.
        headers = headers(stream_id: stream_id, hbf: "hbf")
        data = data(stream_id: stream_id, data: "some data")
        :ssl.send(state.socket, [encode(headers), encode(data)])
      end)
      |> Server.expect(fn state, goaway(error_code: :protocol_error) -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:error, %Conn{} = conn, :protocol_error, []} = stream_messages_until_error(conn)
      refute Conn.open?(conn)
    end

    test "server sends a HEADERS with END_STREAM set but not END_HEADERS", context do
      Server.expect(context.server, fn state, headers(stream_id: stream_id) ->
        headers = [
          {:store_name, ":status", "200"},
          {:store_name, "foo", "bar"},
          {:store_name, "baz", "bong"}
        ]

        {hbf, encode_table} = HPACK.encode(headers, state.encode_table)
        state = put_in(state.encode_table, encode_table)

        <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)
        frame1 = headers(stream_id: stream_id, hbf: hbf1, flags: set_flag(:headers, :end_stream))
        :ssl.send(state.socket, encode(frame1))
        frame2 = continuation(stream_id: stream_id, hbf: hbf2)
        :ssl.send(state.socket, encode(frame2))
        flags = set_flag(:continuation, :end_headers)
        frame3 = continuation(stream_id: stream_id, hbf: hbf3, flags: flags)
        :ssl.send(state.socket, encode(frame3))
        state
      end)

      {:ok, conn, ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:status, ^ref, "200"}, {:headers, ^ref, _headers}, {:done, ^ref}] = responses
      assert Conn.open?(conn)
    end

    test "server sends a response without a :status header", context do
      context.server
      |> Server.expect(fn state, headers(stream_id: stream_id) ->
        headers = [
          {:store_name, "foo", "bar"},
          {:store_name, "baz", "bong"}
        ]

        {hbf, encode_table} = HPACK.encode(headers, state.encode_table)
        state = put_in(state.encode_table, encode_table)

        flags = set_flags(:headers, [:end_headers, :end_stream])
        frame = headers(stream_id: stream_id, hbf: hbf, flags: flags)
        :ssl.send(state.socket, encode(frame))
      end)
      |> Server.expect(fn state, rst_stream() -> state end)

      {:ok, conn, ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:closed, ^ref, {:protocol_error, :missing_status_header}}] = responses
      assert Conn.open?(conn)
    end

    test "client has to split headers because of max frame size", context do
      context.server
      |> Server.expect(fn state, headers(stream_id: 3, hbf: hbf, flags: flags) ->
        assert flag_set?(flags, :headers, :end_stream)
        refute flag_set?(flags, :headers, :end_headers)
        Map.put(state, :current_hbf, hbf)
      end)
      |> Server.expect(fn state, continuation(stream_id: 3, hbf: hbf, flags: flags) ->
        refute flag_set?(flags, :continuation, :end_headers)
        Map.update!(state, :current_hbf, &(&1 <> hbf))
      end)
      |> Server.expect(fn state, continuation(stream_id: 3, hbf: hbf, flags: flags) ->
        assert flag_set?(flags, :continuation, :end_headers)
        hbf = Map.fetch!(state, :current_hbf) <> hbf
        {:ok, headers, decode_table} = HPACK.decode(hbf, state.decode_table)
        state = put_in(state.decode_table, decode_table)
        assert [{":method", "METH"} | _] = headers

        {hbf, encode_table} = HPACK.encode([{:store_name, ":status", "200"}], state.encode_table)
        state = put_in(state.encode_table, encode_table)

        flags = set_flags(:headers, [:end_stream, :end_headers])
        frame = headers(stream_id: 3, hbf: hbf, flags: flags)

        :ssl.send(state.socket, encode(frame))

        state
      end)

      # This is an empirical number of headers so that the minimum max frame size (~16kb) fits
      # between 2 and 3 times (so that we can test the behaviour above).
      headers = for i <- 1..400, do: {"a#{i}", String.duplicate("a", 100)}
      assert {:ok, conn, ref} = Conn.request(context.conn, "METH", "/", headers)

      assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:status, ^ref, "200"}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert Conn.open?(conn)
    end
  end

  describe "frame encoding errors by the server" do
    test "server sends a frame with the wrong stream id", context do
      context.server
      |> Server.expect(fn state, headers() ->
        payload = encode_raw(_ping = 0x06, 0x00, 3, <<0::64>>)
        :ssl.send(state.socket, payload)
      end)
      |> Server.expect(fn state, goaway(error_code: :protocol_error) -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:error, %Conn{} = conn, :protocol_error, []} = stream_messages_until_error(conn)
      refute Conn.open?(conn)
    end

    test "server sends a frame with a bad size", context do
      context.server
      |> Server.expect(fn state, headers() ->
        # Payload should be 8 bytes long.
        payload = encode_raw(_ping = 0x06, 0x00, 3, <<>>)
        :ssl.send(state.socket, payload)
      end)
      |> Server.expect(fn state, goaway(error_code: :frame_size_error) -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])
      assert {:error, %Conn{} = conn, :frame_size_error, []} = stream_messages_until_error(conn)
      refute Conn.open?(conn)
    end
  end

  describe "flow control" do
    test "server sends a WINDOW_UPDATE with too big of a size on a stream", context do
      max_window_size = 2_147_483_647

      context.server
      |> Server.expect(fn state, headers(stream_id: stream_id) ->
        frame = window_update(stream_id: stream_id, window_size_increment: max_window_size)
        :ssl.send(state.socket, encode(frame))
      end)
      |> Server.expect(fn state, rst_stream() -> state end)

      {:ok, conn, ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:closed, ^ref, :flow_control_error}] = responses
      assert Conn.open?(conn)
    end

    test "server sends a WINDOW_UPDATE with too big of a size on the connection level", context do
      max_window_size = 2_147_483_647

      context.server
      |> Server.expect(fn state, headers() ->
        frame = window_update(stream_id: 0, window_size_increment: max_window_size)
        :ssl.send(state.socket, encode(frame))
      end)
      |> Server.expect(fn state, goaway(error_code: :flow_control_error) -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])
      assert {:error, %Conn{} = conn, :flow_control_error, []} = stream_messages_until_error(conn)
      refute Conn.open?(conn)
    end

    test "server violates client's max frame size", context do
      context.server
      |> Server.expect(fn state, headers(stream_id: stream_id) ->
        frame = data(stream_id: stream_id, data: :binary.copy(<<0>>, 100_000))
        :ssl.send(state.socket, encode(frame))
      end)
      |> Server.expect(fn state, goaway(error_code: :frame_size_error) -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:error, %Conn{} = conn, :frame_size_error, []} = stream_messages_until_error(conn)
      refute Conn.open?(conn)
    end

    test "client splits data automatically based on server's max frame size", context do
      max_frame_size = Conn.get_setting(context.conn, :max_frame_size)

      context.server
      |> Server.expect(fn state, headers(stream_id: 3) -> state end)
      |> Server.expect(fn state, data(stream_id: 3, flags: 0x00, data: data) ->
        assert data == :binary.copy(<<0>>, max_frame_size)
        state
      end)
      |> Server.expect(fn state, data(stream_id: 3, flags: 0x01, data: data) ->
        assert data == <<0>>

        headers = [{:store_name, ":status", "200"}]
        {hbf, encode_table} = HPACK.encode(headers, state.encode_table)
        state = put_in(state.encode_table, encode_table)

        frame =
          headers(stream_id: 3, hbf: hbf, flags: set_flags(:headers, [:end_stream, :end_headers]))

        :ok = :ssl.send(state.socket, encode(frame))

        state
      end)

      body = :binary.copy(<<0>>, max_frame_size + 1)
      assert {:ok, %Conn{} = conn, ref} = Conn.request(context.conn, "GET", "/", [], body)

      assert {:ok, %Conn{} = conn, responses} = stream_messages_until_response(conn)
      assert [{:status, ^ref, "200"}, {:headers, ^ref, []}, {:done, ^ref}] = responses
      assert Conn.open?(conn)
    end
  end

  describe "settings" do
    test "client can send settings to server", context do
      assert {:ok, %Conn{} = conn, []} = stream_next_message(context.conn)

      Server.expect(context.server, fn state, settings(params: [max_concurrent_streams: 123]) ->
        frame = settings(stream_id: 0, flags: set_flag(:settings, :ack), params: [])
        :ssl.send(state.socket, encode(frame))
      end)

      {:ok, conn} = Conn.put_settings(conn, max_concurrent_streams: 123)
      assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
      assert Conn.open?(conn)
    end

    test "client can read server settings", %{conn: conn} do
      assert Conn.get_setting(conn, :max_concurrent_streams) == 100
      assert Conn.get_setting(conn, :enable_push) == true
    end

    test "server can update the initial window size and affect open streams", context do
      context.server
      |> Server.expect(fn state, headers(stream_id: 3) ->
        frame = settings(params: [initial_window_size: 100])
        :ssl.send(state.socket, encode(frame))
      end)
      |> Server.expect(fn state, settings(flags: 0x01, params: []) -> state end)

      {:ok, conn, _ref} = Conn.request(context.conn, "GET", "/", [])

      assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
      assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
      assert conn.initial_window_size == 100

      # This stream is half_closed_local, so there's not point in updating its window size since
      # we won't send anything on it anymore.
      assert conn.streams[3].window_size == 65535
    end
  end

  defp stream_next_message(conn) do
    assert_receive message, 1000
    Conn.stream(conn, message)
  end

  defp stream_messages_until_response(conn) do
    case stream_next_message(conn) do
      {:ok, %Conn{} = conn, []} ->
        stream_messages_until_response(conn)

      other ->
        other
    end
  end

  defp stream_messages_until_error(conn) do
    case stream_next_message(conn) do
      {:ok, %Conn{} = conn, responses} ->
        assert responses == []
        stream_messages_until_error(conn)

      {:error, %Conn{}, _reason, _responses} = error ->
        error
    end
  end
end
