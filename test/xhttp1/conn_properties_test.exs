defmodule XHTTP1.ConnPropertiesTest do
  use ExUnit.Case, async: true
  use ExUnitProperties
  import XHTTP1.TestHelpers
  alias XHTTP1.Conn
  alias XHTTP1.TestServer

  setup do
    {:ok, port} = TestServer.start()
    assert {:ok, conn} = Conn.connect("localhost", port, transport: XHTTP.Transport.TCP)
    [conn: conn]
  end

  property "body with content-length", %{conn: conn} do
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n0123456789XXX"

    check all byte_chunks <- random_chunks(response) do
      {conn, responses} =
        Enum.reduce(byte_chunks, {conn, []}, fn bytes, {conn, responses} ->
          assert {:ok, conn, new_responses} =
                   Conn.stream(conn, {:tcp, conn.transport_state, bytes})

          {conn, responses ++ new_responses}
        end)

      assert [status, headers | rest] = responses
      assert {:status, ^ref, 200} = status
      assert {:headers, ^ref, [{"content-length", "10"}]} = headers
      assert merge_body(rest, ref) == "0123456789"

      assert conn.buffer == "XXX"
    end
  end

  property "body with chunked transfer-encoding split on every byte", %{conn: conn} do
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" <>
        "2meta\r\n01\r\n2\r\n23\r\n0meta\r\ntrailer: value\r\n\r\nXXX"

    check all byte_chunks <- random_chunks(response) do
      {conn, responses} =
        Enum.reduce(byte_chunks, {conn, []}, fn bytes, {conn, responses} ->
          assert {:ok, conn, new_responses} =
                   Conn.stream(conn, {:tcp, conn.transport_state, bytes})

          {conn, responses ++ new_responses}
        end)

      assert [status, headers | rest] = responses
      assert {:status, ^ref, 200} = status
      assert {:headers, ^ref, [{"transfer-encoding", "chunked"}]} = headers
      assert merge_body_with_trailers(rest, ref) == {"0123", [{"trailer", "value"}]}

      assert conn.buffer == "XXX"
    end
  end

  property "pipeline with multiple responses in single message", %{conn: conn} do
    {:ok, conn, ref1} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref2} = Conn.request(conn, "GET", "/", [], nil)
    {:ok, conn, ref3} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nXXXXX"
    responses = for _ <- 1..3, do: response, into: ""

    check all byte_chunks <- random_chunks(responses) do
      {_conn, responses} =
        Enum.reduce(byte_chunks, {conn, []}, fn bytes, {conn, responses} ->
          assert {:ok, conn, new_responses} =
                   Conn.stream(conn, {:tcp, conn.transport_state, bytes})

          {conn, responses ++ new_responses}
        end)

      assert [{:status, ^ref1, _}, {:headers, ^ref1, _} | responses] = responses
      assert {"XXXXX", responses} = merge_pipelined_body(responses, ref1)
      assert [{:status, ^ref2, _}, {:headers, ^ref2, _} | responses] = responses
      assert {"XXXXX", responses} = merge_pipelined_body(responses, ref2)
      assert [{:status, ^ref3, _}, {:headers, ^ref3, _} | responses] = responses
      assert {"XXXXX", []} = merge_pipelined_body(responses, ref3)
    end
  end

  defp random_chunks(binary) do
    size = byte_size(binary)

    StreamData.bind(StreamData.integer(0..size), fn num_splits ->
      StreamData.integer(1..(size - 1))
      |> Enum.take(num_splits)
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.reduce({[], binary, 0}, fn split, {chunks, rest, prev_split} ->
        length = split - prev_split
        <<chunk::binary-size(length), rest::binary>> = rest
        {[chunk | chunks], rest, split}
      end)
      |> join_last_chunk()
      |> Enum.reverse()
      |> StreamData.constant()
    end)
  end

  defp join_last_chunk({chunks, rest, _last_split}), do: [rest | chunks]
end
