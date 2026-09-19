defmodule Mint.HTTP1.FuzzTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Mint.{HTTP1, HTTP1.TestServer}

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

  defp scenario_gen do
    gen all methods <-
              list_of(member_of(["GET", "GET", "HEAD", "POST"]), min_length: 1, max_length: 3),
            responses <- list_of(response_gen(), length: length(methods)),
            mutation <-
              frequency([
                {6, nil},
                {1, tuple({constant(:insert), integer(0..400), byte()})},
                {1, tuple({constant(:delete), integer(0..400)})}
              ]),
            chunk_sizes <- list_of(integer(1..64), min_length: 1, max_length: 30),
            close? <- boolean(),
            extra <-
              frequency([
                {4, constant("")},
                {1, constant("\r\n")},
                {1, constant("HTTP/1.1 200 OK\r\n\r\n")},
                {1, constant("junk")}
              ]) do
      responses =
        Enum.zip_with(methods, responses, fn
          "HEAD", response -> %{response | body: :none}
          _method, response -> response
        end)

      %{
        methods: methods,
        responses: responses,
        mutation: mutation,
        chunk_sizes: chunk_sizes,
        close?: close?,
        extra: extra
      }
    end
  end

  ## Property

  property "stream/2 never raises and keeps requests consistent on random server responses" do
    check all scenario <- scenario_gen(), max_runs: @runs do
      run_scenario(scenario)
    end
  end

  defp run_scenario(
         %{methods: methods, responses: responses, chunk_sizes: chunk_sizes} = scenario
       ) do
    drain_mailbox()
    {:ok, port, server_ref} = TestServer.start()
    {:ok, conn} = HTTP1.connect(:http, "localhost", port)
    assert_receive {^server_ref, server_socket}

    {refs, conn} =
      Enum.map_reduce(methods, conn, fn method, conn ->
        body = if method == "POST", do: "x", else: nil
        {:ok, conn, ref} = HTTP1.request(conn, method, "/", [], body)
        {ref, conn}
      end)

    bytes = responses |> Enum.map(&render_response/1) |> IO.iodata_to_binary()
    bytes = mutate(bytes <> scenario.extra, scenario.mutation)

    tracker = Enum.into(refs, %{}, &{&1, :new})
    context = {scenario, bytes}

    outcome = feed(conn, bytes, Stream.cycle(chunk_sizes), tracker, context)

    case outcome do
      {:open, conn, tracker} when scenario.close? ->
        result =
          try do
            HTTP1.stream(conn, {:tcp_closed, conn.socket})
          rescue
            e ->
              flunk(
                "stream/2 raised on close #{Exception.format(:error, e, __STACKTRACE__)}\n#{inspect(context, limit: :infinity)}"
              )
          end

        handle_result(result, tracker, context)

      _ ->
        :ok
    end

    _ = HTTP1.close(conn)
    :gen_tcp.close(server_socket)
    drain_mailbox()
  end

  defp feed(conn, "", _chunks, tracker, _context), do: {:open, conn, tracker}

  defp feed(conn, bytes, chunks, tracker, context) do
    size = min(Enum.at(chunks, 0), byte_size(bytes))
    <<chunk::binary-size(^size), rest::binary>> = bytes

    result =
      try do
        HTTP1.stream(conn, {:tcp, conn.socket, chunk})
      rescue
        e ->
          flunk(
            "stream/2 raised #{Exception.format(:error, e, __STACKTRACE__)}\n#{inspect(context, limit: :infinity)}"
          )
      catch
        kind, value ->
          flunk(
            "stream/2 threw #{inspect(kind)} #{inspect(value)}\n#{inspect(context, limit: :infinity)}"
          )
      end

    case handle_result(result, tracker, context) do
      {:open, conn, tracker} -> feed(conn, rest, Stream.drop(chunks, 1), tracker, context)
      other -> other
    end
  end

  defp handle_result({:ok, conn, responses}, tracker, context) do
    tracker = check_responses(responses, tracker, context)

    if HTTP1.open?(conn) do
      {:open, conn, tracker}
    else
      if HTTP1.open_request_count(conn) != 0 do
        flunk(
          "closed connection with #{HTTP1.open_request_count(conn)} open requests, responses #{inspect(responses)}\n#{inspect(context, limit: :infinity)}"
        )
      end

      for {ref, state} <- tracker, state != :done do
        flunk(
          "closed connection but ref #{inspect(ref)} is #{inspect(state)}, responses #{inspect(responses)}\n#{inspect(context, limit: :infinity)}"
        )
      end

      {:closed, conn, tracker}
    end
  end

  defp handle_result({:error, conn, _reason, responses}, tracker, context) do
    tracker = check_responses(responses, tracker, context)

    if HTTP1.open?(conn) do
      flunk(
        "connection still open after error, responses #{inspect(responses)}\n#{inspect(context, limit: :infinity)}"
      )
    end

    {:closed, conn, tracker}
  end

  defp handle_result(other, _tracker, context) do
    flunk("unexpected return #{inspect(other)}\n#{inspect(context, limit: :infinity)}")
  end

  defp check_responses(responses, tracker, context) do
    Enum.reduce(responses, tracker, fn response, tracker ->
      ref = elem(response, 1)
      state = Map.get(tracker, ref, :unknown)
      tag = elem(response, 0)

      next =
        case {tag, state} do
          {_, :unknown} ->
            flunk(
              "response #{inspect(response)} for unknown ref, responses #{inspect(responses)}\n#{inspect(context, limit: :infinity)}"
            )

          {_, :done} ->
            flunk(
              "response #{inspect(response)} after done/error, responses #{inspect(responses)}\n#{inspect(context, limit: :infinity)}"
            )

          {:error, _} ->
            :done

          {:status, :new} ->
            if elem(response, 2) in 100..199 and elem(response, 2) != 101,
              do: :interim,
              else: :headers_pending

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
              "response #{inspect(response)} in state #{inspect(state)}, responses #{inspect(responses)}\n#{inspect(context, limit: :infinity)}"
            )
        end

      Map.put(tracker, ref, next)
    end)
  end

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
