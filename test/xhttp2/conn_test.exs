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
    assert Conn.open?(conn) == false
  end

  test "socket error messages are treated as errors", %{conn: conn} do
    message = {:ssl_error, conn.socket, :etimeout}
    assert {:error, %Conn{} = conn, :etimeout, []} = Conn.stream(conn, message)
    assert Conn.open?(conn) == false
  end

  test "server sends RST_STREAM", %{conn: conn, server: server} do
    Server.expect(server, fn state, headers(stream_id: stream_id) ->
      frame = rst_stream(stream_id: stream_id, error_code: :protocol_error)
      :ssl.send(state.socket, encode(frame))
    end)

    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [])

    assert {:ok, %Conn{}, responses} = stream_next_message(conn)
    assert [{:closed, ^ref, {:rst_stream, :protocol_error}}] = responses
  end

  test "when server sends GOAWAY all unprocessed streams are closed", %{
    conn: conn,
    server: server
  } do
    server
    |> Server.expect(fn state, headers() -> state end)
    |> Server.expect(fn state, headers() -> state end)
    |> Server.expect(fn state, headers() ->
      code = :protocol_error
      frame = goaway(stream_id: 0, last_stream_id: 3, error_code: code, debug_data: "debug data")
      :ok = :ssl.send(state.socket, encode(frame))
      :ok = :ssl.close(state.socket)
      %{state | socket: nil}
    end)

    {:ok, conn, _ref1} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [])
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/", [])

    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)

    assert [
             {:closed, ^ref2, {:goaway, :protocol_error, "debug data"}},
             {:closed, ^ref3, {:goaway, :protocol_error, "debug data"}}
           ] = responses

    assert {:error, %Conn{} = conn, :closed, []} = stream_next_message(conn)

    assert Conn.open?(conn) == false
  end

  test "server splits headers into multiple CONTINUATION frames", %{conn: conn, server: server} do
    Server.expect(server, fn state, headers(stream_id: stream_id) ->
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

    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [])

    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)

    assert [{:status, ^ref, "200"}, {:headers, ^ref, _headers}] = responses

    assert Conn.open?(conn)
  end

  test "server sends a badly encoded header block", %{conn: conn, server: server} do
    server
    |> Server.expect(fn state, headers(stream_id: stream_id) ->
      flags = set_flag(:headers, :end_headers)
      frame = headers(stream_id: stream_id, hbf: "not a good hbf", flags: flags)
      :ssl.send(state.socket, encode(frame))
    end)
    |> Server.expect(fn state, goaway() -> state end)

    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [])

    assert {:error, %Conn{} = conn, :compression_error, []} = stream_next_message(conn)

    assert Conn.open?(conn) == false
  end

  test "server sends a CONTINUATION frame outside of headers streaming", %{
    conn: conn,
    server: server
  } do
    server
    |> Server.expect(fn state, headers(stream_id: stream_id) ->
      frame = continuation(stream_id: stream_id, hbf: "hbf")
      :ssl.send(state.socket, encode(frame))
    end)
    |> Server.expect(fn state, goaway() -> state end)

    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [])

    assert {:error, %Conn{} = conn, :protocol_error, []} = stream_next_message(conn)
    assert Conn.open?(conn) == false
  end

  test "server sends a non-CONTINUATION frame while streaming headers", %{
    conn: conn,
    server: server
  } do
    server
    |> Server.expect(fn state, headers(stream_id: stream_id) ->
      # Headers are streaming but we send a non-CONTINUATION frame.
      headers = headers(stream_id: stream_id, hbf: "hbf")
      data = data(stream_id: stream_id, data: "some data")
      :ssl.send(state.socket, [encode(headers), encode(data)])
    end)
    |> Server.expect(fn state, goaway() -> state end)

    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [])

    assert {:error, %Conn{} = conn, :protocol_error, []} = stream_next_message(conn)
    assert Conn.open?(conn) == false
  end

  test "server sends a HEADERS with END_STREAM set but not END_HEADERS", %{
    conn: conn,
    server: server
  } do
    Server.expect(server, fn state, headers(stream_id: stream_id) ->
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

    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [])

    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)
    assert [{:status, ^ref, "200"}, {:headers, ^ref, _headers}, {:done, ^ref}] = responses
    assert Conn.open?(conn) == true
  end

  test "server sends a response without a :status header", %{conn: conn, server: server} do
    server
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

    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [])

    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)
    assert [{:closed, ^ref, {:protocol_error, :missing_status_header}}] = responses
    assert Conn.open?(conn) == true
  end

  test "server sends a frame with the wrong stream id", %{conn: conn, server: server} do
    Server.expect(server, fn state, headers() ->
      payload = encode_raw(_ping = 0x06, 0x00, 3, "opaque data")
      :ssl.send(state.socket, payload)
    end)

    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [])
    assert {:error, %Conn{} = conn, :protocol_error, []} = stream_next_message(conn)
    assert Conn.open?(conn) == false
  end

  test "server sends a WINDOW_UPDATE with too big of a size on a stream", %{
    conn: conn,
    server: server
  } do
    max_window_size = 2_147_483_647

    server
    |> Server.expect(fn state, headers(stream_id: stream_id) ->
      frame = window_update(stream_id: stream_id, window_size_increment: max_window_size)
      :ssl.send(state.socket, encode(frame))
    end)
    |> Server.expect(fn state, rst_stream() -> state end)

    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [])
    assert {:ok, %Conn{} = conn, responses} = stream_next_message(conn)
    assert [{:closed, ^ref, :flow_control_error}] = responses
    assert Conn.open?(conn) == true
  end

  test "server sends a WINDOW_UPDATE with too big of a size on the connection level", %{
    conn: conn,
    server: server
  } do
    max_window_size = 2_147_483_647

    server
    |> Server.expect(fn state, headers() ->
      frame = window_update(stream_id: 0, window_size_increment: max_window_size)
      :ssl.send(state.socket, encode(frame))
    end)
    |> Server.expect(fn state, goaway(error_code: :flow_control_error) -> state end)

    {:ok, conn, _ref} = Conn.request(conn, "GET", "/", [])
    assert {:error, %Conn{} = conn, :flow_control_error, []} = stream_next_message(conn)
    assert Conn.open?(conn) == false
  end

  test "client can send settings to server", %{conn: conn, server: server} do
    Server.expect(server, fn state, settings(params: [max_concurrent_streams: 123]) ->
      frame = settings(stream_id: 0, flags: set_flag(:settings, :ack), params: [])
      :ssl.send(state.socket, encode(frame))
    end)

    {:ok, conn} = Conn.put_settings(conn, max_concurrent_streams: 123)
    assert {:ok, %Conn{} = conn, []} = stream_next_message(conn)
    assert Conn.open?(conn) == true
  end

  test "client can read server settings", %{conn: conn} do
    assert Conn.get_setting(conn, :max_concurrent_streams) == 100
    assert Conn.get_setting(conn, :enable_push) == true
  end

  defp stream_next_message(conn) do
    assert_receive message, 1000
    Conn.stream(conn, message)
  end
end
