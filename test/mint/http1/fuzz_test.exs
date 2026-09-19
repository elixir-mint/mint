defmodule Mint.HTTP1.FuzzTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Mint.HTTP1

  @moduletag :capture_log
  @moduletag timeout: :infinity

  @runs String.to_integer(System.get_env("FUZZ_RUNS", "100"))

  ## Generators

  defp header_gen do
    frequency([
      {40, tuple({member_of(["x-a", "x-b"]), string(:alphanumeric, max_length: 6)})},
      {2, tuple({constant("connection"), member_of(["close", "keep-alive", "Close"])})},
      {2, constant({"X-B", " c "})},
      {2, constant({"x-d", "a\tb"})},
      {1, constant({"x-c", "a\r\n b"})},
      {1, constant({"content-length", "abc"})},
      {1, constant({"transfer-encoding", "gzip"})},
      {1, constant({"connection", ""})},
      {1, constant({"", "x"})},
      {1, constant({"x e", "y"})},
      {1, constant({"x-f", "\x01"})},
      {1, constant({"x-g", "ü"})},
      {1, constant({"Upgrade", "websocket"})}
    ])
  end

  defp body_gen do
    frequency([
      {2, constant(:none)},
      {4, tuple({constant(:cl), binary(max_length: 40)})},
      {4,
       tuple(
         {constant(:chunked), list_of(binary(min_length: 1, max_length: 20), max_length: 4),
          list_of(header_gen(), max_length: 2), member_of(["", "", ";ext", ";a=b", " ", ";\x01"])}
       )},
      {2, tuple({constant(:close), binary(max_length: 40)})}
    ])
  end

  defp framing_headers_gen(body) do
    derived =
      case body do
        :none ->
          [[], [{"content-length", "0"}]]

        {:cl, _} ->
          [[{"content-length", :match}]]

        {:chunked, _, _, _} ->
          [[{"transfer-encoding", "chunked"}]]

        {:close, _} ->
          [[], [{"connection", "close"}]]
      end

    frequency([
      {9, member_of(derived)},
      {1,
       member_of([
         [{"content-length", "5"}],
         [{"content-length", "-1"}],
         [{"content-length", "2, 2"}],
         [{"content-length", "3"}, {"content-length", "3"}],
         [{"transfer-encoding", "chunked"}, {"content-length", "3"}],
         [{"transfer-encoding", "chunked"}]
       ])}
    ])
  end

  defp response_gen do
    gen all preludes <-
              list_of(
                tuple(
                  {member_of(["100", "102", "103", "101"]), list_of(header_gen(), max_length: 2)}
                ),
                max_length: 2
              ),
            version <-
              frequency([{8, constant("1.1")}, {1, constant("1.0")}, {1, constant("1.5")}]),
            status <-
              frequency([
                {10, member_of(["200", "200", "200", "204", "304", "404", "500"])},
                {1, member_of(["600", "99", "101", "1000", "20"])}
              ]),
            body <- body_gen(),
            framing <- framing_headers_gen(body),
            headers <- list_of(header_gen(), max_length: 3) do
      %{
        preludes: preludes,
        version: version,
        status: status,
        headers: framing ++ headers,
        body: body
      }
    end
  end

  defp method_gen do
    frequency([
      {6, constant({"GET", nil})},
      {2, constant({"POST", "x"})},
      {2, constant({"POST", :stream})},
      {1, constant({"HEAD", nil})},
      {1, constant({"CONNECT", nil})}
    ])
  end

  defp client_op_gen do
    frequency([
      {3, tuple({integer(0..40), constant(:body), integer(0..3), member_of(["x", :eof])})},
      {1, tuple({integer(0..40), constant(:request), method_gen()})}
    ])
  end

  defp scenario_gen do
    gen all methods <- list_of(method_gen(), min_length: 1, max_length: 3),
            ops <- list_of(client_op_gen(), max_length: 3),
            responses <- list_of(response_gen(), length: length(methods) + length(ops)),
            mutation <-
              frequency([
                {10, constant(nil)},
                {1, tuple({constant(:insert), integer(0..400), byte()})},
                {1, tuple({constant(:delete), integer(0..400)})}
              ]),
            chunk_sizes <- list_of(integer(1..64), min_length: 1, max_length: 30),
            close? <- boolean(),
            mode <- member_of([:active, :active, :passive]),
            stream_headers? <- boolean(),
            max_header_list_size <- member_of([262_144, 262_144, 300, 100]),
            case_sensitive_headers? <- boolean(),
            status_reason? <- boolean(),
            extra <-
              frequency([
                {8, constant("")},
                {1, constant("\r\n")},
                {1, constant("HTTP/1.1 200 OK\r\n\r\n")},
                {1, constant("junk")}
              ]) do
      all_methods =
        methods ++
          for {_index, :request, method} <- ops, do: method

      responses =
        responses
        |> Enum.take(length(all_methods))
        |> Enum.zip_with(all_methods, fn
          response, {"HEAD", _body} -> %{response | body: :none}
          response, _method -> response
        end)

      %{
        methods: methods,
        ops: ops,
        responses: responses,
        mutation: mutation,
        chunk_sizes: chunk_sizes,
        close?: close?,
        mode: mode,
        stream_headers?: stream_headers?,
        max_header_list_size: max_header_list_size,
        case_sensitive_headers?: case_sensitive_headers?,
        status_reason?: status_reason?,
        extra: extra
      }
    end
  end

  ## Property

  property "stream/2 and recv/3 never raise and keep requests consistent on random responses" do
    check all scenario <- scenario_gen(), max_runs: @runs do
      run_scenario(scenario)
    end
  end

  defp run_scenario(%{methods: methods, responses: responses} = scenario) do
    drain_mailbox()
    {:ok, listen_socket} = :gen_tcp.listen(0, mode: :binary, packet: :raw, active: false)
    {:ok, port} = :inet.port(listen_socket)
    parent = self()

    accept =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        :ok = :gen_tcp.controlling_process(socket, parent)
        {:ok, socket}
      end)

    {:ok, conn} =
      HTTP1.connect(:http, "localhost", port,
        mode: scenario.mode,
        stream_headers: scenario.stream_headers?,
        max_header_list_size: scenario.max_header_list_size,
        case_sensitive_headers: scenario.case_sensitive_headers?,
        optional_responses: if(scenario.status_reason?, do: [:status_reason], else: [])
      )

    {:ok, server_socket} = Task.await(accept)
    :ok = :gen_tcp.close(listen_socket)

    {conn, refs, meta} =
      Enum.reduce(methods, {conn, [], %{}}, fn {method, body}, {conn, refs, meta} ->
        case HTTP1.request(conn, method, "/", [], body) do
          {:ok, conn, ref} -> {conn, refs ++ [ref], Map.put(meta, ref, new_meta(method))}
          {:error, conn, _reason} -> {conn, refs, meta}
        end
      end)

    bytes = responses |> Enum.map(&render_response/1) |> IO.iodata_to_binary()
    bytes = mutate(bytes <> scenario.extra, scenario.mutation)

    state = %{
      scenario: scenario,
      bytes: bytes,
      refs: refs,
      tracker: Enum.into(refs, %{}, &{&1, :new}),
      meta: meta,
      chunks: Stream.cycle(scenario.chunk_sizes),
      index: 0,
      server_socket: server_socket,
      log: []
    }

    case feed(conn, bytes, state) do
      {:open, conn, state} when scenario.close? ->
        result =
          try do
            close_from_server(conn, state)
          rescue
            e ->
              flunk(
                "close raised #{Exception.format(:error, e, __STACKTRACE__)}\n#{describe(state)}"
              )
          end

        handle_result(result, state)

      _ ->
        :ok
    end

    _ = HTTP1.close(conn)
    :gen_tcp.close(server_socket)
    drain_mailbox()
  end

  defp new_meta(method), do: %{method: method, status: nil, content_length: nil, body_size: 0}

  defp describe(state) do
    "scenario: #{inspect(state.scenario, limit: :infinity)}\nbytes: #{inspect(state.bytes, limit: :infinity)}\nlog: #{inspect(state.log, limit: :infinity)}"
  end

  defp close_from_server(conn, %{scenario: %{mode: :active}}) do
    HTTP1.stream(conn, {:tcp_closed, conn.socket})
  end

  defp close_from_server(conn, %{scenario: %{mode: :passive}} = state) do
    :ok = :gen_tcp.close(state.server_socket)
    HTTP1.recv(conn, 0, 1000)
  end

  defp feed(conn, "", state), do: {:open, conn, state}

  defp feed(conn, bytes, state) do
    case run_client_ops(conn, state) do
      {:open, conn, state} ->
        size = min(Enum.at(state.chunks, 0), byte_size(bytes))
        <<chunk::binary-size(^size), rest::binary>> = bytes
        state = %{state | chunks: Stream.drop(state.chunks, 1), index: state.index + 1}
        state = %{state | log: state.log ++ [{:chunk, chunk}]}

        result =
          try do
            deliver(conn, chunk, state)
          rescue
            e ->
              flunk(
                "stream/recv raised #{Exception.format(:error, e, __STACKTRACE__)}\n#{describe(state)}"
              )
          catch
            kind, value ->
              flunk("stream/recv threw #{inspect(kind)} #{inspect(value)}\n#{describe(state)}")
          end

        case handle_result(result, state) do
          {:open, conn, state} -> feed(conn, rest, state)
          other -> other
        end

      other ->
        other
    end
  end

  defp deliver(conn, chunk, %{scenario: %{mode: :active}}) do
    HTTP1.stream(conn, {:tcp, conn.socket, chunk})
  end

  defp deliver(conn, chunk, %{scenario: %{mode: :passive}} = state) do
    :ok = :gen_tcp.send(state.server_socket, chunk)
    HTTP1.recv(conn, byte_size(chunk), 1000)
  end

  defp run_client_ops(conn, state) do
    ops =
      for {index, op, arg1, arg2} <- state.scenario.ops,
          index == state.index,
          do: {op, arg1, arg2}

    Enum.reduce_while(ops, {:open, conn, state}, fn op, {:open, conn, state} ->
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

      if HTTP1.open?(conn, :read) do
        {:cont, {:open, conn, state}}
      else
        {:halt, {:closed, conn, state}}
      end
    end)
  end

  defp client_op(conn, {:body, i, chunk}, state) do
    ref = Enum.at(state.refs, rem(i, length(state.refs)))

    case HTTP1.stream_request_body(conn, ref, chunk) do
      {:ok, conn} -> {conn, state}
      {:error, conn, _reason} -> {conn, state}
    end
  end

  defp client_op(conn, {:request, {method, body}}, state) do
    case HTTP1.request(conn, method, "/", [], body) do
      {:ok, conn, ref} ->
        state = %{state | refs: state.refs ++ [ref], tracker: Map.put(state.tracker, ref, :new)}
        {conn, put_in(state.meta[ref], new_meta(method))}

      {:error, conn, _reason} ->
        {conn, state}
    end
  end

  defp handle_result({:ok, conn, responses}, state) do
    state = check_responses(responses, state)

    if HTTP1.open?(conn) do
      expected_open = Enum.count(state.tracker, fn {_ref, ref_state} -> ref_state != :done end)

      if HTTP1.open_request_count(conn) != expected_open do
        flunk(
          "open_request_count #{HTTP1.open_request_count(conn)} but #{expected_open} unfinished requests, responses #{inspect(responses)}\n#{describe(state)}"
        )
      end

      {:open, conn, state}
    else
      if HTTP1.open_request_count(conn) != 0 do
        flunk(
          "closed connection with #{HTTP1.open_request_count(conn)} open requests, responses #{inspect(responses)}\n#{describe(state)}"
        )
      end

      for {ref, ref_state} <- state.tracker, ref_state != :done do
        flunk(
          "closed connection but ref #{inspect(ref)} is #{inspect(ref_state)}, responses #{inspect(responses)}\n#{describe(state)}"
        )
      end

      {:closed, conn, state}
    end
  end

  defp handle_result({:error, conn, _reason, responses}, state) do
    state = check_responses(responses, state)

    if HTTP1.open?(conn) do
      flunk(
        "connection still open after error, responses #{inspect(responses)}\n#{describe(state)}"
      )
    end

    {:closed, conn, state}
  end

  defp handle_result(other, state) do
    flunk("unexpected return #{inspect(other)}\n#{describe(state)}")
  end

  defp check_responses(responses, state) do
    stream_headers? = state.scenario.stream_headers?

    {tracker, meta} =
      Enum.reduce(responses, {state.tracker, state.meta}, fn response, {tracker, meta} ->
        ref = elem(response, 1)
        ref_state = Map.get(tracker, ref, :unknown)
        tag = elem(response, 0)
        meta = update_meta(meta, response, ref_state, state)

        next =
          case {tag, ref_state} do
            {_, :unknown} ->
              flunk(
                "response #{inspect(response)} for unknown ref, responses #{inspect(responses)}\n#{describe(state)}"
              )

            {_, :done} ->
              flunk(
                "response #{inspect(response)} after done/error, responses #{inspect(responses)}\n#{describe(state)}"
              )

            {:error, _} ->
              :done

            {:status_reason, s} when s in [:interim, :headers_pending] ->
              s

            {:status, s} when s == :new or (s == :interim and stream_headers?) ->
              if elem(response, 2) in 100..199 and elem(response, 2) != 101,
                do: :interim,
                else: :headers_pending

            {:headers, :interim} ->
              if stream_headers?, do: :interim, else: :new

            {:headers, :headers_pending} ->
              if stream_headers?, do: :headers_pending, else: :body

            {:data, :headers_pending} when stream_headers? ->
              :body

            {:done, :headers_pending} when stream_headers? ->
              :done

            {:headers, :body} ->
              :trailers

            {:headers, :trailers} when stream_headers? ->
              :trailers

            {:data, :body} ->
              :body

            {:done, s} when s in [:body, :trailers] ->
              :done

            _ ->
              flunk(
                "response #{inspect(response)} in state #{inspect(ref_state)}, responses #{inspect(responses)}\n#{describe(state)}"
              )
          end

        {Map.put(tracker, ref, next), meta}
      end)

    %{state | tracker: tracker, meta: meta}
  end

  # RFC 9112 6.3: a content-length body has exactly that many bytes, and responses
  # to HEAD, 204 and 304 responses and 2xx responses to CONNECT have no body.
  defp update_meta(meta, {:status, ref, status}, _ref_state, _state) when is_map_key(meta, ref) do
    put_in(meta[ref].status, status)
  end

  defp update_meta(meta, {:headers, ref, headers}, :headers_pending, _state)
       when is_map_key(meta, ref) do
    values = for {name, value} <- headers, String.downcase(name) == "content-length", do: value

    chunked? =
      Enum.any?(headers, fn {name, _} -> String.downcase(name) == "transfer-encoding" end)

    case values do
      [value] when not chunked? ->
        if value =~ ~r/^[0-9]+$/,
          do: put_in(meta[ref].content_length, String.to_integer(value)),
          else: meta

      _ ->
        meta
    end
  end

  defp update_meta(meta, {:data, ref, data}, _ref_state, _state) when is_map_key(meta, ref) do
    update_in(meta[ref].body_size, &(&1 + byte_size(data)))
  end

  defp update_meta(meta, {:done, ref}, _ref_state, state) when is_map_key(meta, ref) do
    %{method: method, status: status, content_length: content_length, body_size: body_size} =
      meta[ref]

    # A 101 response hands the connection to another protocol, whose bytes are
    # delivered as data whatever the request method was.
    bodiless? =
      status != 101 and
        (method == "HEAD" or status in [204, 304] or
           (method == "CONNECT" and status in 200..299))

    cond do
      bodiless? and body_size > 0 ->
        flunk(
          "#{method} #{status} response completed with #{body_size} body bytes\n#{describe(state)}"
        )

      not bodiless? and status != 101 and content_length != nil and body_size != content_length ->
        flunk(
          "response completed with #{body_size} body bytes but content-length #{content_length}\n#{describe(state)}"
        )

      true ->
        meta
    end
  end

  defp update_meta(meta, _response, _ref_state, _state), do: meta

  ## Rendering

  defp render_response(%{
         preludes: preludes,
         version: version,
         status: status,
         headers: headers,
         body: body
       }) do
    prelude_text =
      for {pstatus, pheaders} <- preludes do
        ["HTTP/1.1 ", pstatus, " Info\r\n", render_headers(pheaders, nil), "\r\n"]
      end

    {body_bytes, body_length} =
      case body do
        :none ->
          {"", 0}

        {:cl, bytes} ->
          {bytes, byte_size(bytes)}

        {:close, bytes} ->
          {bytes, byte_size(bytes)}

        {:chunked, chunks, trailers, ext} ->
          rendered =
            for chunk <- chunks do
              [Integer.to_string(byte_size(chunk), 16), ext, "\r\n", chunk, "\r\n"]
            end

          {IO.iodata_to_binary([
             rendered,
             "0",
             ext,
             "\r\n",
             render_headers(trailers, nil),
             "\r\n"
           ]), chunks |> Enum.map(&byte_size/1) |> Enum.sum()}
      end

    [
      prelude_text,
      "HTTP/",
      version,
      " ",
      status,
      " Reason\r\n",
      render_headers(headers, body_length),
      "\r\n",
      body_bytes
    ]
  end

  defp render_headers(headers, body_length) do
    for {name, value} <- headers do
      value =
        case value do
          :match -> Integer.to_string(body_length || 0)
          other -> other
        end

      [name, ": ", value, "\r\n"]
    end
  end

  defp mutate(bytes, nil), do: bytes

  defp mutate(bytes, {:insert, pos, byte}) do
    pos = min(pos, byte_size(bytes))
    <<a::binary-size(^pos), b::binary>> = bytes
    a <> <<byte>> <> b
  end

  defp mutate(bytes, {:delete, _pos}) when byte_size(bytes) == 0, do: bytes

  defp mutate(bytes, {:delete, pos}) do
    pos = min(pos, byte_size(bytes) - 1)
    <<a::binary-size(^pos), _, b::binary>> = bytes
    a <> b
  end

  defp drain_mailbox do
    receive do
      _ -> drain_mailbox()
    after
      0 -> :ok
    end
  end
end
