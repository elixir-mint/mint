defmodule XHTTP.ConnTest do
  use ExUnit.Case, async: true
  use ExUnitProperties
  import XHTTP.TestHelpers
  alias XHTTP.Conn
  alias XHTTP.TestHelpers.TCPMock

  property "body with content-length" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)
    response = "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n0123456789XXX"

    check all byte_chunks <- random_chunks(response) do
      {conn, responses} =
        Enum.reduce(byte_chunks, {conn, []}, fn bytes, {conn, responses} ->
          assert {:ok, conn, new_responses} = Conn.stream(conn, {:tcp, conn.socket, bytes})
          {conn, responses ++ new_responses}
        end)

      assert [status, headers | rest] = responses
      assert {:status, ^ref, {{1, 1}, 200, "OK"}} = status
      assert {:headers, ^ref, [{"content-length", "10"}]} = headers
      assert merge_body(rest, ref) == "0123456789"

      assert conn.buffer == "XXX"
    end
  end

  property "body with chunked transfer-encoding split on every byte" do
    {:ok, conn} = Conn.connect("localhost", 80, transport: TCPMock)
    {:ok, conn, ref} = Conn.request(conn, "GET", "/", [], nil)

    response =
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" <>
        "2meta\r\n01\r\n2\r\n23\r\n0meta\r\ntrailer: value\r\n\r\nXXX"

    check all byte_chunks <- random_chunks(response) do
      {conn, responses} =
        Enum.reduce(byte_chunks, {conn, []}, fn bytes, {conn, responses} ->
          assert {:ok, conn, new_responses} = Conn.stream(conn, {:tcp, conn.socket, bytes})
          {conn, responses ++ new_responses}
        end)

      assert [status, headers | rest] = responses
      assert {:status, ^ref, {{1, 1}, 200, "OK"}} = status
      assert {:headers, ^ref, [{"transfer-encoding", "chunked"}]} = headers
      assert merge_body(rest, ref) == {"0123", [{"trailer", "value"}]}

      assert conn.buffer == "XXX"
    end
  end

  defp random_chunks(binary) do
    size = byte_size(binary)

    StreamData.bind(StreamData.integer(0..size), fn num_splits ->
      StreamData.integer(1..size-1)
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
