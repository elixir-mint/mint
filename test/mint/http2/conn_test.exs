defmodule Mint.HTTP2Test do
  use ExUnit.Case, async: true

  import Mint.HTTP2.Frame
  import ExUnit.CaptureLog

  alias Mint.HTTP2
  alias Mint.HTTP2.TestServer, as: TS

  setup context do
    default_options = [transport_opts: [verify: :verify_none]]
    options = Keyword.merge(default_options, context[:connect_options] || [])
    {conn, server} = TS.connect(options)
    [conn: conn, server: server]
  end

  describe "stream/2 with unknown messages or error messages" do
    test "unknown message", %{conn: conn} do
      assert HTTP2.stream(conn, :unknown_message) == :unknown
    end

    test "closed-socket messages are treated as errors", %{conn: conn} do
      assert {:error, %HTTP2{} = conn, :closed, []} =
               HTTP2.stream(conn, {:ssl_closed, conn.socket})

      refute HTTP2.open?(conn)
    end

    test "socket error messageyeah i s are treated as errors", %{conn: conn} do
      message = {:ssl_error, conn.socket, :etimeout}
      assert {:error, %HTTP2{} = conn, :etimeout, []} = HTTP2.stream(conn, message)
      refute HTTP2.open?(conn)
    end
  end

  describe "closed streams" do
    test "server closes a stream with RST_STREAM", %{conn: conn, server: server} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
                 rst_stream(stream_id: stream_id, error_code: :protocol_error)
               ])

      assert [{:error, ^ref, {:rst_stream, :protocol_error}}] = responses
      assert HTTP2.open?(conn)
    end

    test "when server sends frames after sending RST_STREAM, it is ignored",
         %{conn: conn, server: server} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
                 rst_stream(stream_id: stream_id, error_code: :cancel),
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert responses == [{:error, ref, {:rst_stream, :cancel}}]

      assert HTTP2.open?(conn)
    end

    test "client closes a stream with cancel_request/2", %{conn: conn, server: server} do
      {conn, ref} = open_request(conn)
      {:ok, conn} = HTTP2.cancel_request(conn, ref)

      assert [
               headers(stream_id: stream_id),
               rst_stream(stream_id: stream_id, error_code: :cancel)
             ] = TS.recv_next_frames(server, 2)

      # If the server replies next, we ignore the replies.
      assert {_server, {:ok, %HTTP2{} = conn, []}} =
               stream_frames(conn, server, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers]},
                 data(stream_id: stream_id, data: "hello", flags: set_flags(:data, [:end_stream]))
               ])

      assert HTTP2.open?(conn)
    end

    test "receiving a RST_STREAM on a closed stream is ignored", %{server: server, conn: conn} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert [rst_stream(stream_id: ^stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:ok, %HTTP2{} = conn, []}} =
               stream_frames(conn, server, [
                 rst_stream(stream_id: stream_id, error_code: :no_error),
                 rst_stream(stream_id: stream_id, error_code: :no_error)
               ])

      assert HTTP2.open?(conn)
    end
  end

  describe "stream state transitions" do
    test "if client receives HEADERS after receiving a END_STREAM flag, it ignores it",
         %{server: server, conn: conn} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]},
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]}
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert HTTP2.open?(conn)
    end

    test "if client receives DATA after receiving a END_STREAM flag, it ignores it",
         %{server: server, conn: conn} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
                 {:headers, stream_id, [{":status", "200"}], [:end_headers, :end_stream]},
                 data(stream_id: stream_id, data: "hello", flags: set_flags(:data, [:end_stream]))
               ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, []}, {:done, ^ref}] = responses

      assert HTTP2.open?(conn)
    end
  end

  describe "closing the connection" do
    test "server closes the connection with GOAWAY", %{server: server, conn: conn} do
      {conn, _ref1} = open_request(conn)
      {conn, ref2} = open_request(conn)
      {conn, ref3} = open_request(conn)

      assert [headers(), headers(), headers()] = TS.recv_next_frames(server, 3)

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
                 goaway(
                   stream_id: 0,
                   last_stream_id: 3,
                   error_code: :protocol_error,
                   debug_data: "debug data"
                 )
               ])

      assert [
               {:error, ^ref2, {:goaway, :protocol_error, "debug data"}},
               {:error, ^ref3, {:goaway, :protocol_error, "debug data"}}
             ] = responses

      TS.close_socket(server)

      assert_receive message
      assert {:error, %HTTP2{} = conn, :closed, []} = HTTP2.stream(conn, message)
      refute HTTP2.open?(conn)
    end

    test "client closes the connection with close/1", %{conn: conn, server: server} do
      assert {:ok, conn} = HTTP2.close(conn)
      # TODO: find a better way that doesn't use :ssl directly or the underlying server socket.
      assert :ssl.recv(server.socket, 0, 0) == {:error, :closed}
      refute HTTP2.open?(conn)
    end
  end

  describe "headers and continuation" do
    test "server splits headers into multiple CONTINUATION frames", %{server: server, conn: conn} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      {server, <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>>} =
        TS.encode_headers(server, [{":status", "200"}, {"foo", "bar"}, {"baz", "bong"}])

      {_server, {:ok, %HTTP2{} = conn, responses}} =
        stream_frames(conn, server, [
          headers(stream_id: stream_id, hbf: hbf1, flags: set_flags(:headers, [])),
          continuation(stream_id: stream_id, hbf: hbf2, flags: set_flags(:continuation, [])),
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

    test "server sends a badly encoded header block fragment", %{conn: conn, server: server} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:error, %HTTP2{} = conn, :compression_error, []}} =
               stream_frames(conn, server, [
                 headers(
                   stream_id: stream_id,
                   hbf: "not a good hbf",
                   flags: set_flags(:headers, [:end_headers])
                 )
               ])

      assert [goaway(error_code: :compression_error)] = TS.recv_next_frames(server, 1)

      refute HTTP2.open?(conn)
    end

    test "server sends a CONTINUATION frame outside of headers streaming",
         %{conn: conn, server: server} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      {_server, {:error, %HTTP2{} = conn, :protocol_error, []}} =
        stream_frames(conn, server, [continuation(stream_id: stream_id, hbf: "hbf")])

      assert [goaway(error_code: :protocol_error)] = TS.recv_next_frames(server, 1)

      refute HTTP2.open?(conn)
    end

    test "server sends a non-CONTINUATION frame while streaming headers",
         %{conn: conn, server: server} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      {_server, {:error, %HTTP2{} = conn, :protocol_error, []}} =
        stream_frames(conn, server, [
          headers(stream_id: stream_id, hbf: "hbf", flags: set_flags(:headers, [])),
          data(stream_id: stream_id, data: "hello")
        ])

      assert [goaway(error_code: :protocol_error)] = TS.recv_next_frames(server, 1)

      refute HTTP2.open?(conn)
    end

    test "server sends HEADERS with END_STREAM but no END_HEADERS and then sends CONTINUATIONs",
         %{conn: conn, server: server} do
      {conn, ref} = open_request(conn)

      {server, <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>>} =
        TS.encode_headers(server, [{":status", "200"}, {"foo", "bar"}, {"baz", "bong"}])

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      {server, {:ok, %HTTP2{} = conn, responses}} =
        stream_frames(conn, server, [
          headers(stream_id: stream_id, hbf: hbf1, flags: set_flags(:headers, [:end_stream])),
          continuation(stream_id: stream_id, hbf: hbf2, flags: set_flags(:continuation, [])),
          continuation(
            stream_id: stream_id,
            hbf: hbf3,
            flags: set_flags(:continuation, [:end_headers])
          )
        ])

      assert [{:status, ^ref, 200}, {:headers, ^ref, _headers}, {:done, ^ref}] = responses

      assert [rst_stream(error_code: :no_error)] = TS.recv_next_frames(server, 1)

      assert HTTP2.open?(conn)
    end

    test "server sends a response without a :status header", %{conn: conn, server: server} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      {_server, {:ok, %HTTP2{} = conn, responses}} =
        stream_frames(conn, server, [
          {:headers, stream_id, [{"foo", "bar"}, {"baz", "bong"}], [:end_headers, :end_stream]}
        ])

      assert [{:error, ^ref, {:protocol_error, :missing_status_header}}] = responses

      assert [rst_stream(error_code: :protocol_error)] = TS.recv_next_frames(server, 1)

      assert HTTP2.open?(conn)
    end

    test "client has to split headers because of max frame size", %{conn: conn, server: server} do
      # This is an empirical number of headers so that the minimum max frame size (~16kb) fits
      # between 2 and 3 times (so that we can test the behaviour above).
      headers = for i <- 1..400, do: {"a#{i}", String.duplicate("a", 100)}
      assert {:ok, conn, ref} = HTTP2.request(conn, "GET", "/", headers)

      assert [
               headers(stream_id: stream_id, hbf: hbf1, flags: flags1),
               continuation(stream_id: stream_id, hbf: hbf2, flags: flags2),
               continuation(stream_id: stream_id, hbf: hbf3, flags: flags3)
             ] = TS.recv_next_frames(server, 3)

      assert flag_set?(flags1, :headers, :end_stream)
      refute flag_set?(flags1, :headers, :end_headers)
      refute flag_set?(flags2, :continuation, :end_headers)
      assert flag_set?(flags3, :continuation, :end_headers)

      {_server, headers} = TS.decode_headers(server, hbf1 <> hbf2 <> hbf3)
      assert [{":method", "GET"}, {":path", "/"}, {":scheme", "https"} | _] = headers

      assert HTTP2.open?(conn)
    end
  end

  describe "server pushes" do
    test "a PUSH_PROMISE frame and a few CONTINUATION frames are received",
         %{conn: conn, server: server} do
      promised_stream_id = 4

      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      # Promised headers.
      headers = [{":method", "GET"}, {"foo", "bar"}, {"baz", "bong"}]

      {server, <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>>} =
        TS.encode_headers(server, headers)

      # Normal headers.
      {server, hbf} = TS.encode_headers(server, [{":status", "200"}, {"push", "promise"}])

      assert {server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
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

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
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
         %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      {server, hbf} = TS.encode_headers(server, [{":method", "GET"}])

      assert {server, {:error, %HTTP2{} = conn, :protocol_error, []}} =
               stream_frames(conn, server, [
                 push_promise(
                   stream_id: stream_id,
                   hbf: hbf,
                   promised_stream_id: 4,
                   flags: set_flags(:push_promise, [:end_headers])
                 )
               ])

      assert [goaway(error_code: :protocol_error)] = TS.recv_next_frames(server, 1)
      refute HTTP2.open?(conn)
    end
  end

  describe "misbehaving server" do
    test "sends a frame with the wrong stream id", %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers()] = TS.recv_next_frames(server, 1)

      data = IO.iodata_to_binary(encode_raw(_ping = 0x06, 0x00, 3, <<0::64>>))

      assert {:error, %HTTP2{} = conn, :protocol_error, []} =
               HTTP2.stream(conn, {:ssl, conn.socket, data})

      assert [goaway(error_code: :protocol_error)] = TS.recv_next_frames(server, 1)

      refute HTTP2.open?(conn)
    end

    test "sends a frame with a bad size", %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers()] = TS.recv_next_frames(server, 1)

      # Payload should be 8 bytes long, but is empty here.
      data = IO.iodata_to_binary(encode_raw(_ping = 0x06, 0x00, 3, <<>>))

      assert {:error, %HTTP2{} = conn, :frame_size_error, []} =
               HTTP2.stream(conn, {:ssl, conn.socket, data})

      assert [goaway(error_code: :frame_size_error)] = TS.recv_next_frames(server, 1)
      refute HTTP2.open?(conn)
    end

    test "sends a frame on a stream with a stream ID bigger than client's biggest",
         %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      bad_stream_id = stream_id + 10

      assert {_server, {:error, %HTTP2{} = conn, :protocol_error, []}} =
               stream_frames(conn, server, [
                 {:headers, bad_stream_id, [{":status", "200"}], [:end_headers]}
               ])

      assert [goaway(error_code: :protocol_error)] = TS.recv_next_frames(server, 1)

      refute HTTP2.open?(conn)
    end
  end

  describe "flow control" do
    test "server sends a WINDOW_UPDATE with too big of a size on a stream",
         %{server: server, conn: conn} do
      {conn, ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:ok, %HTTP2{} = conn, responses}} =
               stream_frames(conn, server, [
                 window_update(
                   stream_id: stream_id,
                   window_size_increment: _max_window_size = 2_147_483_647
                 )
               ])

      assert [{:error, ^ref, :flow_control_error}] = responses

      assert [rst_stream(stream_id: ^stream_id, error_code: :flow_control_error)] =
               TS.recv_next_frames(server, 1)

      assert HTTP2.open?(conn)
    end

    test "server sends a WINDOW_UPDATE with too big of a size on the connection level",
         %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:error, %HTTP2{} = conn, :flow_control_error, []}} =
               stream_frames(conn, server, [
                 window_update(
                   stream_id: 0,
                   window_size_increment: _max_window_size = 2_147_483_647
                 )
               ])

      assert [goaway(error_code: :flow_control_error)] = TS.recv_next_frames(server, 1)

      refute HTTP2.open?(conn)
    end

    test "server violates client's max frame size", %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert {_server, {:error, %HTTP2{} = conn, :frame_size_error, []}} =
               stream_frames(conn, server, [
                 data(stream_id: stream_id, data: :binary.copy(<<0>>, 100_000))
               ])

      assert [goaway(error_code: :frame_size_error)] = TS.recv_next_frames(server, 1)

      refute HTTP2.open?(conn)
    end

    test "client splits data automatically based on server's max frame size",
         %{server: server, conn: conn} do
      max_frame_size = HTTP2.get_setting(conn, :max_frame_size)

      body = :binary.copy(<<0>>, max_frame_size + 1)
      {conn, _ref} = open_request(conn, body)

      assert [
               headers(stream_id: stream_id),
               data(stream_id: stream_id, flags: flags1, data: data1),
               data(stream_id: stream_id, flags: flags2, data: data2)
             ] = TS.recv_next_frames(server, 3)

      assert flags1 == set_flags(:data, [])
      assert data1 == :binary.copy(<<0>>, max_frame_size)

      assert flags2 == set_flags(:data, [:end_stream])
      assert data2 == <<0>>

      assert HTTP2.open?(conn)
    end
  end

  describe "settings" do
    test "put_settings/2 can be used to send settings to server", %{server: server, conn: conn} do
      {:ok, conn} = HTTP2.put_settings(conn, max_concurrent_streams: 123)

      assert [settings() = frame] = TS.recv_next_frames(server, 1)
      assert settings(frame, :params) == [max_concurrent_streams: 123]
      assert settings(frame, :flags) == set_flags(:settings, [])

      assert {_server, {:ok, %HTTP2{} = conn, []}} =
               stream_frames(conn, server, [
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

    test "get_setting/2 can be used to read server settings", %{conn: conn} do
      assert HTTP2.get_setting(conn, :max_concurrent_streams) == 100
      assert HTTP2.get_setting(conn, :enable_push) == true
    end

    test "get_setting/2 fails with unknown settings", %{conn: conn} do
      assert_raise ArgumentError, "unknown HTTP/2 setting: :unknown", fn ->
        HTTP2.get_setting(conn, :unknown)
      end
    end

    test "server can update the initial window size and affect open streams",
         %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      {_server, {:ok, %HTTP2{} = conn, []}} =
        stream_frames(conn, server, [settings(params: [initial_window_size: 100])])

      # TODO: likely not ideal to peek into the connection here.
      assert conn.initial_window_size == 100
      # This stream is half_closed_local, so there's not point in updating its window size since
      # we won't send anything on it anymore.
      assert conn.streams[stream_id].window_size == 65535

      assert [settings() = frame] = TS.recv_next_frames(server, 1)
      assert settings(frame, :flags) == set_flags(:settings, [:ack])
    end
  end

  describe "stream_request_body/3" do
    test "streaming a request", %{server: server, conn: conn} do
      {conn, ref} = open_request(conn, :stream)
      assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, "foo")
      assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, "bar")
      assert {:ok, conn} = HTTP2.stream_request_body(conn, ref, :eof)

      assert [
               headers(stream_id: stream_id) = headers,
               data(stream_id: stream_id, data: "foo") = data1,
               data(stream_id: stream_id, data: "bar") = data2,
               data(stream_id: stream_id, data: "") = data3
             ] = TS.recv_next_frames(server, 4)

      refute flag_set?(headers(headers, :flags), :headers, :end_stream)
      refute flag_set?(data(data1, :flags), :data, :end_stream)
      refute flag_set?(data(data2, :flags), :data, :end_stream)
      assert flag_set?(data(data3, :flags), :data, :end_stream)

      assert HTTP2.open?(conn)
    end
  end

  describe "stream priority" do
    test "PRIORITY frames are ignored", %{server: server, conn: conn} do
      {conn, _ref} = open_request(conn)

      assert [headers(stream_id: stream_id)] = TS.recv_next_frames(server, 1)

      assert capture_log(fn ->
               assert {_server, {:ok, %HTTP2{} = conn, []}} =
                        stream_frames(conn, server, [
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

  defp stream_frames(conn, server, frames) do
    {server, data} = TS.encode_frames(server, frames)
    result = HTTP2.stream(conn, {:ssl, conn.socket, data})
    {server, result}
  end

  defp open_request(conn, body \\ nil) do
    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], body)
    assert is_reference(ref)
    {conn, ref}
  end
end
