defmodule XHTTP1.IntegrationTest do
  use ExUnit.Case, async: true
  import XHTTP1.TestHelpers
  alias XHTTP1.{Conn, Transport}

  @moduletag :integration

  test "200 response - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, headers} = headers
    assert get_header(headers, "connection") == ["keep-alive"]
    assert merge_body(responses, request) =~ "httpbin"
  end

  test "ssl, path, long body - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 443, transport: Transport.SSL)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/bytes/50000", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert byte_size(merge_body(responses, request)) == 50000
  end

  test "keep alive - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 443, transport: Transport.SSL)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "SEE ALSO"

    assert {:ok, conn} = Conn.connect("httpbin.org", 443, transport: Transport.SSL)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "SEE ALSO"
  end

  test "POST body - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80)
    assert {:ok, conn, request} = Conn.request(conn, "POST", "/post", [], "BODY")
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ ~s("BODY")
  end

  test "POST body streaming - httpbin.org" do
    headers = [{"content-length", "4"}]
    assert {:ok, conn} = Conn.connect("httpbin.org", 80)
    assert {:ok, conn, request} = Conn.request(conn, "POST", "/post", headers, :stream)
    assert {:ok, conn} = Conn.stream_request_body(conn, "BO")
    assert {:ok, conn} = Conn.stream_request_body(conn, "DY")
    assert {:ok, conn} = Conn.stream_request_body(conn, :eof)
    assert {:ok, conn, responses} = receive_stream(conn)

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ ~s("BODY")
  end

  test "pipelining - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80)
    assert {:ok, conn, request1} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, request2} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, request3} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, request4} = Conn.request(conn, "GET", "/", [], nil)

    assert {:ok, conn, [_status, _headers | responses1]} = receive_stream(conn)
    assert {:ok, conn, [_status, _headers | responses2]} = receive_stream(conn)
    assert {:ok, conn, [_status, _headers | responses3]} = receive_stream(conn)
    assert {:ok, _conn, [_status, _headers | responses4]} = receive_stream(conn)

    assert merge_body(responses1, request1) =~
             "Testing an HTTP Library can become difficult sometimes"

    assert merge_body(responses2, request2) =~
             "Testing an HTTP Library can become difficult sometimes"

    assert merge_body(responses3, request3) =~
             "Testing an HTTP Library can become difficult sometimes"

    assert merge_body(responses4, request4) =~
             "Testing an HTTP Library can become difficult sometimes"
  end

  # TODO: Figure out what is happening here. Server is responding without
  # content-length or transfer-encoding headers, this means we should read body
  # until connection is closed by server. We timeout in this test but curl
  # returns immediately, so somehow curl knows much earlier that the body is
  # zero length.
  # $ curl -vv httpbin.org/stream-bytes/0
  @tag :skip
  test "chunked no chunks - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/stream-bytes/0", [], nil)

    assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

    assert byte_size(merge_body(responses, request)) == 1024
  end

  test "chunked single chunk - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80)

    assert {:ok, conn, request} =
             Conn.request(conn, "GET", "/stream-bytes/1024?chunk_size=1024", [], nil)

    assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

    assert byte_size(merge_body(responses, request)) == 1024
  end

  test "chunked multiple chunks - httpbin.org" do
    assert {:ok, conn} = Conn.connect("httpbin.org", 80)

    assert {:ok, conn, request} =
             Conn.request(conn, "GET", "/stream-bytes/1024?chunk_size=100", [], nil)

    assert {:ok, _conn, [_status, _headers | responses]} = receive_stream(conn)

    assert byte_size(merge_body(responses, request)) == 1024
  end

  defp receive_stream(conn) do
    receive_stream(conn, [])
  end

  defp receive_stream(conn, responses) do
    receive do
      {:rest, conn, rest_responses} ->
        maybe_done(conn, rest_responses, responses)

      {tag, _socket, _data} = message when tag in [:tcp, :ssl] ->
        assert {:ok, conn, new_responses} = Conn.stream(conn, message)
        maybe_done(conn, new_responses, responses)

      {tag, _socket} = message when tag in [:tcp_close, :ssl_close] ->
        assert {:error, _conn, :closed} = Conn.stream(conn, message)

      {tag, _reason} = message when tag in [:tcp_error, :ssl_error] ->
        assert {:error, _conn, _reason} = Conn.stream(conn, message)
    after
      10000 ->
        flunk("receive_stream timeout")
    end
  end

  defp maybe_done(conn, responses, acc) do
    {new, rest} = Enum.split_while(responses, &(not match?({:done, _}, &1)))

    case {new, rest} do
      {new, []} ->
        receive_stream(conn, acc ++ new)

      {new, [done | rest]} ->
        if rest != [], do: send(self(), {:rest, conn, rest})
        {:ok, conn, acc ++ new ++ [done]}
    end
  end

  defp get_header(headers, name) do
    for {n, v} <- headers, n == name, do: v
  end
end
