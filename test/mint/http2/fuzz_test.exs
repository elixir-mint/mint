defmodule Mint.HTTP2.FuzzTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  import Mint.HTTP2.Frame, except: [inspect: 1]

  alias Mint.{HTTP2, HTTP2.Frame, HTTP2.TestServer}

  @moduletag :capture_log
  @moduletag timeout: :infinity

  @recv_timeout 300
  @runs String.to_integer(System.get_env("FUZZ_RUNS", "10"))

  ## Generators

  defp status_gen do
    member_of([
      "200",
      "200",
      "200",
      "204",
      "304",
      "103",
      "100",
      "101",
      "404",
      "500",
      "abc",
      "099",
      "1000"
    ])
  end

  defp regular_header_gen do
    frequency([
      {5, tuple({member_of(["x-a", "x-b", "x-c"]), string(:alphanumeric, max_length: 5)})},
      {2, tuple({constant("content-length"), member_of(["0", "1", "5", "10", "abc", "-1"])})},
      {2, tuple({constant("cookie"), member_of(["a=1", "b=2"])})},
      {1, constant({"connection", "close"})},
      {1, constant({"te", "trailers"})},
      {1, constant({"transfer-encoding", "chunked"})},
      {1, constant({"X-Upper", "v"})},
      {1, constant({"x-nl", "a\nb"})},
      {1, constant({":path", "/"})},
      {1, constant({"", "empty"})}
    ])
  end

  defp response_headers_gen do
    frequency([
      {6,
       bind(status_gen(), fn s ->
         map(list_of(regular_header_gen(), max_length: 4), &[{":status", s} | &1])
       end)},
      {1, list_of(regular_header_gen(), max_length: 3)},
      {1,
       bind(status_gen(), fn s ->
         map(list_of(regular_header_gen(), max_length: 2), &(&1 ++ [{":status", s}]))
       end)},
      {1, bind(status_gen(), fn s -> constant([{":status", s}, {":status", s}]) end)}
    ])
  end

  defp promised_headers_gen do
    frequency([
      {5,
       constant([
         {":method", "GET"},
         {":scheme", "https"},
         {":authority", "localhost"},
         {":path", "/p"}
       ])},
      {1, constant([{":method", "POST"}, {":scheme", "https"}, {":path", "/p"}])},
      {1, constant([{":method", "GET"}, {":path", "/p"}])},
      {1,
       map(
         list_of(regular_header_gen(), max_length: 3),
         &([{":method", "GET"}, {":scheme", "https"}, {":path", "/p"}] ++ &1)
       )}
    ])
  end

  defp target_gen do
    frequency([
      {6, tuple({constant(:known), integer(0..2)})},
      {3, tuple({constant(:promised), integer(0..2)})},
      {1, constant(:even_idle)},
      {1, constant(:odd_idle)},
      {1, constant(:zero)},
      {1, constant(:closed)}
    ])
  end

  defp action_gen do
    frequency([
      {8,
       tuple(
         {constant(:headers), target_gen(), response_headers_gen(), boolean(), boolean(),
          boolean()}
       )},
      {8,
       tuple(
         {constant(:data), target_gen(), integer(0..300),
          member_of([nil, "", "pad", :binary.copy("p", 100)]), boolean()}
       )},
      {3,
       tuple(
         {constant(:push_promise), target_gen(), promised_headers_gen(),
          member_of([:next, :next, :next, :same, :odd, :zero, :lower]), boolean()}
       )},
      {2,
       tuple(
         {constant(:rst_stream), target_gen(),
          member_of([:no_error, :cancel, :protocol_error, :refused_stream, {:custom_error, 99}])}
       )},
      {2,
       tuple(
         {constant(:settings),
          list_of(
            member_of([
              {:header_table_size, 0},
              {:header_table_size, 8192},
              {:enable_push, false},
              {:max_concurrent_streams, 0},
              {:max_concurrent_streams, 1},
              {:initial_window_size, 0},
              {:initial_window_size, 10},
              {:initial_window_size, 2_147_483_647},
              {:max_frame_size, 16_384},
              {:max_frame_size, 100},
              {:max_header_list_size, 10}
            ]),
            max_length: 3
          )}
       )},
      {1, constant(:settings_ack)},
      {1, tuple({constant(:ping), boolean()})},
      {1,
       tuple(
         {constant(:goaway), member_of([:zero, :known, :high]),
          member_of([:no_error, :internal_error])}
       )},
      {2,
       tuple({constant(:window_update), target_gen(), member_of([1, 100, 65_535, 2_147_483_647])})},
      {1, tuple({constant(:priority), target_gen()})},
      {1, tuple({constant(:unknown), integer(10..255), target_gen(), binary(max_length: 10)})},
      {1, tuple({constant(:raw), binary(min_length: 1, max_length: 12)})},
      {2, tuple({constant(:client), constant(:cancel), integer(0..2)})},
      {2, tuple({constant(:client), constant(:body), integer(0..2), member_of(["x", :eof])})},
      {1, tuple({constant(:client), constant(:ping)})},
      {2, tuple({constant(:client), constant(:request), member_of([nil, :stream, "body"])})},
      {1,
       tuple(
         {constant(:client), constant(:put_settings),
          member_of([
            [initial_window_size: 10],
            [initial_window_size: 65_535],
            [initial_window_size: 100_000],
            [header_table_size: 0],
            [header_table_size: 8192],
            [max_frame_size: 16_384],
            [max_header_list_size: 100],
            [enable_push: false]
          ])}
       )},
      {1,
       tuple(
         {constant(:headers_raw), target_gen(), binary(min_length: 1, max_length: 16), boolean()}
       )}
    ])
  end

  defp scenario_gen do
    gen all request_count <- integer(1..3),
            bodies <- list_of(member_of([nil, :stream, "body"]), length: request_count),
            actions <- list_of(action_gen(), min_length: 1, max_length: 25),
            chunk_sizes <- list_of(integer(1..64), min_length: 1, max_length: 40),
            cancel_first? <- boolean(),
            mode <- member_of([:active, :active, :passive]) do
      %{
        bodies: bodies,
        actions: actions,
        chunk_sizes: chunk_sizes,
        cancel_first?: cancel_first?,
        mode: mode
      }
    end
  end

  ## Property

  property "stream/2 never raises and keeps the connection consistent on random server frames" do
    check all scenario <- scenario_gen(), max_runs: @runs do
      run_scenario(scenario)
    end
  end

  defp run_scenario(%{
         bodies: bodies,
         actions: actions,
         chunk_sizes: chunk_sizes,
         cancel_first?: cancel_first?,
         mode: mode
       }) do
    drain_mailbox()
    {:ok, port, task} = TestServer.listen_and_accept()
    conn = start_connection(port, task, mode)

    {conn, refs, sids} =
      Enum.reduce(bodies, {conn, [], []}, fn body, {conn, refs, sids} ->
        sid = conn.next_stream_id
        {:ok, conn, ref} = HTTP2.request(conn, "GET", "/", [], body)
        {conn, refs ++ [ref], sids ++ [sid]}
      end)

    ^sids = for headers(stream_id: sid) <- recv_all_frames(), do: sid

    {conn, closed_sid} =
      if cancel_first? do
        {:ok, conn} = HTTP2.cancel_request(conn, hd(refs))
        [rst_stream()] = recv_all_frames()
        {conn, hd(sids)}
      else
        {conn, nil}
      end

    tracker = Enum.into(refs, %{}, &{&1, :new})
    tracker = if cancel_first?, do: Map.put(tracker, hd(refs), :done), else: tracker

    state = %{
      sids: sids,
      refs: refs,
      promised: [],
      next_promised: 2,
      closed: closed_sid,
      server: Process.get(:fuzz_server),
      chunks: Stream.cycle(chunk_sizes),
      tracker: tracker,
      actions: actions,
      mode: mode,
      log: []
    }

    run(conn, actions, state)
    _ = HTTP2.close(conn)
    _ = :ssl.close(state.server.socket)
    drain_mailbox()
  end

  defp run(_conn, [], _state), do: :ok

  defp run(conn, [{:client, op} | rest], state) do
    run_client(conn, op, rest, state)
  end

  defp run(conn, [{:client, op, arg} | rest], state) do
    run_client(conn, {op, arg}, rest, state)
  end

  defp run(conn, [{:client, op, arg1, arg2} | rest], state) do
    run_client(conn, {op, arg1, arg2}, rest, state)
  end

  defp run(conn, actions, state) do
    {server_actions, rest} =
      Enum.split_while(actions, fn
        {:client, _} -> false
        {:client, _, _} -> false
        {:client, _, _, _} -> false
        _other -> true
      end)

    {chunks, state} =
      Enum.map_reduce(server_actions, state, fn action, state ->
        {bytes, server, state} = encode_action(action, state.server, state)
        {bytes, %{state | server: server}}
      end)

    state = %{state | log: state.log ++ server_actions}

    case feed(conn, IO.iodata_to_binary(chunks), state) do
      {:open, conn, state} -> run(conn, rest, state)
      :closed -> :ok
    end
  end

  defp run_client(conn, op, rest, state) do
    state = %{state | log: state.log ++ [{:client, op}]}

    {conn, state} =
      try do
        client_op(conn, op, state)
      rescue
        e ->
          flunk(
            "client op #{inspect(op)} raised #{Exception.format(:error, e, __STACKTRACE__)}\n#{describe(state)}"
          )
      end

    check_conn(conn, state)

    if HTTP2.open?(conn, :read) do
      run(conn, rest, state)
    end
  end

  defp describe(state) do
    "actions so far: #{inspect(state.log, limit: :infinity)}\nall actions: #{inspect(state.actions, limit: :infinity)}"
  end

  defp pick_ref(state, i), do: Enum.at(state.refs, rem(i, length(state.refs)))

  defp client_op(conn, {:cancel, i}, state) do
    ref = pick_ref(state, i)

    case HTTP2.cancel_request(conn, ref) do
      {:ok, conn} -> {conn, put_in(state.tracker[ref], :done)}
      {:error, conn, _reason} -> {conn, state}
    end
  end

  defp client_op(conn, {:body, i, chunk}, state) do
    ref = pick_ref(state, i)

    case HTTP2.stream_request_body(conn, ref, chunk) do
      {:ok, conn} -> {conn, state}
      {:error, conn, _reason} -> {conn, state}
    end
  end

  defp client_op(conn, :ping, state) do
    case HTTP2.ping(conn) do
      {:ok, conn, ref} -> {conn, put_in(state.tracker[ref], :ping)}
      {:error, conn, _reason} -> {conn, state}
    end
  end

  defp client_op(conn, {:request, body}, state) do
    sid = conn.next_stream_id

    case HTTP2.request(conn, "GET", "/", [], body) do
      {:ok, conn, ref} ->
        state = %{state | sids: state.sids ++ [sid], refs: state.refs ++ [ref]}
        {conn, put_in(state.tracker[ref], :new)}

      {:error, conn, _reason} ->
        {conn, state}
    end
  end

  defp client_op(conn, {:put_settings, params}, state) do
    case HTTP2.put_settings(conn, params) do
      {:ok, conn} -> {conn, state}
      {:error, conn, _reason} -> {conn, state}
    end
  end

  defp feed(conn, "", state), do: {:open, conn, state}

  defp feed(conn, bytes, state) do
    size = min(Enum.at(state.chunks, 0), byte_size(bytes))
    <<chunk::binary-size(^size), rest::binary>> = bytes
    state = %{state | chunks: Stream.drop(state.chunks, 1)}

    result =
      try do
        deliver(conn, chunk, state)
      rescue
        e ->
          flunk(
            "stream/2 raised #{Exception.format(:error, e, __STACKTRACE__)}\n#{describe(state)}"
          )
      catch
        kind, value ->
          flunk("stream/2 threw #{inspect(kind)} #{inspect(value)}\n#{describe(state)}")
      end

    case result do
      {:ok, conn, responses} ->
        state = check_responses(responses, state)
        check_conn(conn, state)

        if HTTP2.open?(conn, :read) do
          feed(conn, rest, state)
        else
          :closed
        end

      {:error, conn, reason, responses} ->
        state = check_responses(responses, state)
        check_conn(conn, state)

        if HTTP2.open?(conn, :write) do
          flunk("connection still writable after error #{inspect(reason)}\n#{describe(state)}")
        end

        :closed

      other ->
        flunk("unexpected return #{inspect(other)}\n#{describe(state)}")
    end
  end

  defp deliver(conn, chunk, %{mode: :active}) do
    HTTP2.stream(conn, {:ssl, conn.socket, chunk})
  end

  defp deliver(conn, chunk, %{mode: :passive} = state) do
    :ok = :ssl.send(state.server.socket, chunk)
    HTTP2.recv(conn, byte_size(chunk), 1000)
  end

  defp check_responses(responses, state) do
    tracker =
      Enum.reduce(responses, state.tracker, fn response, tracker ->
        ref = elem(response, 1)
        ref_state = Map.get(tracker, ref, :unknown)
        tag = elem(response, 0)

        next =
          case {tag, ref_state} do
            {:pong, :ping} ->
              :done

            {_, :unknown} ->
              flunk(
                "response #{inspect(response)} for unknown ref in #{inspect(responses)}\n#{describe(state)}"
              )

            {_, :done} ->
              flunk(
                "response #{inspect(response)} after done/error in #{inspect(responses)}\n#{describe(state)}"
              )

            {:error, _} ->
              :done

            {:push_promise, _} ->
              ref_state

            {:status, :new} ->
              if elem(response, 2) in 100..199, do: :interim, else: :headers_pending

            {:headers, :interim} ->
              :new

            {:headers, :headers_pending} ->
              :body

            {:headers, :body} ->
              :trailers

            {:data, :body} ->
              :body

            {:done, s} when s in [:body, :trailers] ->
              :done

            _ ->
              flunk(
                "response #{inspect(response)} in state #{inspect(ref_state)} in #{inspect(responses)}\n#{describe(state)}"
              )
          end

        tracker = Map.put(tracker, ref, next)

        case response do
          {:push_promise, _ref, promised_ref, _headers} -> Map.put(tracker, promised_ref, :new)
          _ -> tracker
        end
      end)

    %{state | tracker: tracker}
  end

  defp check_conn(conn, state) do
    streams = Map.values(conn.streams)
    open = [:open, :half_closed_local, :half_closed_remote]

    expected = %{
      open_client: Enum.count(streams, &(rem(&1.id, 2) == 1 and &1.state in open)),
      open_server: Enum.count(streams, &(rem(&1.id, 2) == 0 and &1.state in open)),
      reserved: Enum.count(streams, &(&1.state == :reserved_remote)),
      ref_map: Enum.into(streams, %{}, &{&1.ref, &1.id})
    }

    actual = %{
      open_client: conn.open_client_stream_count,
      open_server: conn.open_server_stream_count,
      reserved: conn.reserved_server_stream_count,
      ref_map: conn.ref_to_stream_id
    }

    if expected != actual do
      flunk(
        "counters out of sync: expected #{inspect(expected)} got #{inspect(actual)}\n#{describe(state)}"
      )
    end

    for {ref, :done} <- state.tracker, Map.has_key?(conn.ref_to_stream_id, ref) do
      flunk("stream for finished ref #{inspect(ref)} still tracked\n#{describe(state)}")
    end

    for {ref, ref_state} <- state.tracker,
        ref_state not in [:done, :ping],
        not Map.has_key?(conn.ref_to_stream_id, ref),
        HTTP2.open?(conn, :read),
        conn.state == :open do
      flunk("unfinished ref #{inspect(ref)} (#{ref_state}) has no stream\n#{describe(state)}")
    end
  end

  ## Server frame encoding

  defp resolve({:known, i}, state), do: Enum.at(state.sids, rem(i, length(state.sids)))
  defp resolve({:promised, i}, %{promised: []} = state), do: resolve({:known, i}, state)
  defp resolve({:promised, i}, state), do: Enum.at(state.promised, rem(i, length(state.promised)))
  defp resolve(:even_idle, state), do: state.next_promised + 2
  defp resolve(:odd_idle, state), do: Enum.max(state.sids) + 2
  defp resolve(:zero, _state), do: 0
  defp resolve(:closed, %{closed: nil} = state), do: resolve({:known, 0}, state)
  defp resolve(:closed, state), do: state.closed

  defp encode_action({:headers, target, headers, end_stream?, split?, padded?}, server, state) do
    sid = resolve(target, state)
    {server, hbf} = TestServer.encode_headers(server, headers)
    padding = if padded?, do: "xx", else: nil

    bytes =
      if split? and byte_size(hbf) > 1 do
        half = div(byte_size(hbf), 2)
        <<a::binary-size(^half), b::binary>> = hbf
        flags = if end_stream?, do: [:end_stream], else: []

        [
          Frame.encode(
            headers(stream_id: sid, hbf: a, padding: padding, flags: set_flags(:headers, flags))
          ),
          Frame.encode(
            continuation(stream_id: sid, hbf: b, flags: set_flags(:continuation, [:end_headers]))
          )
        ]
      else
        flags = if end_stream?, do: [:end_headers, :end_stream], else: [:end_headers]

        Frame.encode(
          headers(stream_id: sid, hbf: hbf, padding: padding, flags: set_flags(:headers, flags))
        )
      end

    {bytes, server, state}
  end

  defp encode_action({:headers_raw, target, hbf, end_stream?}, server, state) do
    sid = resolve(target, state)
    flags = if end_stream?, do: [:end_headers, :end_stream], else: [:end_headers]

    {Frame.encode(headers(stream_id: sid, hbf: hbf, flags: set_flags(:headers, flags))), server,
     state}
  end

  defp encode_action({:data, target, size, padding, end_stream?}, server, state) do
    sid = resolve(target, state)
    flags = if end_stream?, do: set_flags(:data, [:end_stream]), else: 0

    {Frame.encode(
       data(stream_id: sid, data: :binary.copy("d", size), padding: padding, flags: flags)
     ), server, state}
  end

  defp encode_action({:push_promise, target, headers, kind, split?}, server, state) do
    sid = resolve(target, state)

    promised =
      case kind do
        :next -> state.next_promised
        :same -> state.next_promised - 2
        :odd -> state.next_promised + 1
        :zero -> 0
        :lower -> 2
      end

    state =
      if kind == :next,
        do: %{state | next_promised: promised + 2, promised: [promised | state.promised]},
        else: state

    {server, hbf} = TestServer.encode_headers(server, headers)

    bytes =
      if split? and byte_size(hbf) > 1 do
        half = div(byte_size(hbf), 2)
        <<a::binary-size(^half), b::binary>> = hbf

        [
          Frame.encode(
            push_promise(stream_id: sid, promised_stream_id: promised, hbf: a, flags: 0)
          ),
          Frame.encode(
            continuation(stream_id: sid, hbf: b, flags: set_flags(:continuation, [:end_headers]))
          )
        ]
      else
        Frame.encode(
          push_promise(
            stream_id: sid,
            promised_stream_id: promised,
            hbf: hbf,
            flags: set_flags(:push_promise, [:end_headers])
          )
        )
      end

    {bytes, server, state}
  end

  defp encode_action({:rst_stream, target, code}, server, state) do
    {Frame.encode(rst_stream(stream_id: resolve(target, state), error_code: code)), server, state}
  end

  defp encode_action({:settings, params}, server, state) do
    {Frame.encode(settings(params: params)), server, state}
  end

  defp encode_action(:settings_ack, server, state) do
    {Frame.encode(settings(flags: set_flags(:settings, [:ack]), params: [])), server, state}
  end

  defp encode_action({:ping, ack?}, server, state) do
    flags = if ack?, do: set_flags(:ping, [:ack]), else: 0
    {Frame.encode(ping(flags: flags, opaque_data: <<1::64>>)), server, state}
  end

  defp encode_action({:goaway, last, code}, server, state) do
    last_id =
      case last do
        :zero -> 0
        :known -> hd(state.sids)
        :high -> Enum.max(state.sids) + 100
      end

    {Frame.encode(goaway(last_stream_id: last_id, error_code: code, debug_data: "bye")), server,
     state}
  end

  defp encode_action({:window_update, target, increment}, server, state) do
    {Frame.encode(
       window_update(stream_id: resolve(target, state), window_size_increment: increment)
     ), server, state}
  end

  defp encode_action({:priority, target}, server, state) do
    sid = resolve(target, state)

    {Frame.encode(priority(stream_id: sid, exclusive?: false, stream_dependency: sid, weight: 1)),
     server, state}
  end

  defp encode_action({:unknown, type, target, payload}, server, state) do
    {Frame.encode_raw(type, 0, resolve(target, state), payload), server, state}
  end

  defp encode_action({:raw, bytes}, server, state) do
    {bytes, server, state}
  end

  ## Connection setup

  defp start_connection(port, server_socket_task, mode) do
    ack_flags = Frame.set_flags(:settings, [:ack])

    {:ok, conn} =
      HTTP2.connect(:https, "localhost", port, transport_opts: [verify: :verify_none], mode: mode)

    {:ok, server_socket} = Task.await(server_socket_task)
    :ok = TestServer.perform_http2_handshake(server_socket)

    :ok =
      :ssl.send(server_socket, [
        Frame.encode(settings(params: [])),
        Frame.encode(settings(flags: ack_flags, params: []))
      ])

    {:ok, conn, []} =
      if mode == :passive do
        HTTP2.recv(conn, 0, @recv_timeout)
      else
        socket = conn.socket
        assert_receive {:ssl, ^socket, _} = message, @recv_timeout
        HTTP2.stream(conn, message)
      end

    {:ok, data} = :ssl.recv(server_socket, 0, @recv_timeout)
    {:ok, settings(flags: ^ack_flags, params: []), ""} = Frame.decode_next(data)
    :ok = :ssl.setopts(server_socket, active: true)
    Process.put(:fuzz_server, TestServer.new(server_socket))
    conn
  end

  defp recv_all_frames do
    recv_all_data("") |> decode_all([])
  end

  defp recv_all_data(acc) do
    receive do
      {:ssl, _socket, data} -> recv_all_data(acc <> data)
    after
      100 -> acc
    end
  end

  defp decode_all(data, acc) do
    case Frame.decode_next(data) do
      {:ok, frame, rest} -> decode_all(rest, [frame | acc])
      :more -> Enum.reverse(acc)
    end
  end

  defp drain_mailbox do
    receive do
      _ -> drain_mailbox()
    after
      0 -> :ok
    end
  end
end
