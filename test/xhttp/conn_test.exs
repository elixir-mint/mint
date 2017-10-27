defmodule XHTTP.ConnTest do
  use ExUnit.Case, async: true
  alias XHTTP.Conn

  @tag :integration
  test "302 response - google.com" do
    assert {:ok, conn} = Conn.connect("google.com", 80)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 302, "Found"}} = status
    assert {:headers, ^request, headers} = headers
    assert hd(get_header(headers, "location")) =~ "www.google."
    assert merge_body(responses, request) =~ "<TITLE>302 Moved</TITLE>"
  end

  @tag :integration
  test "200 response - example.com" do
    assert {:ok, conn} = Conn.connect("example.com", 80)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "<title>Example Domain</title>"
  end

  @tag :integration
  test "ssl, path, long body - tools.ietf.org" do
    assert {:ok, conn} = Conn.connect("tools.ietf.org", 443, transport: :ssl)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/html/rfc2616", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "Full Copyright Statement"
  end

  @tag :integration
  test "keep alive - tools.ietf.org" do
    assert {:ok, conn} = Conn.connect("tools.ietf.org", 443, transport: :ssl)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/html/rfc7230", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "Security Considerations"

    assert {:ok, conn} = Conn.connect("tools.ietf.org", 443, transport: :ssl)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/html/rfc7231", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers | responses] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert merge_body(responses, request) =~ "Semantics and Content"
  end

  defp merge_body([{:body, request, body} | responses], request) do
    body <> merge_body(responses, request)
  end

  defp merge_body([{:done, request}], request) do
    ""
  end

  defp receive_stream(conn, responses) do
    receive do
      {tag, _socket, _data} = message when tag in [:tcp, :ssl] ->
        assert {:ok, conn, new_responses} = Conn.stream(conn, message)

        if match?({:done, _}, Enum.at(new_responses, -1)) do
          {:ok, conn, responses ++ new_responses}
        else
          receive_stream(conn, responses ++ new_responses)
        end

      {tag, _socket} = message when tag in [:tcp_close, :ssl_close] ->
        assert {:error, _conn, :closed} = Conn.stream(conn, message)

      {tag, _reason} = message when tag in [:tcp_error, :ssl_error] ->
        assert {:error, _conn, _reason} = Conn.stream(conn, message)
    after
      5000 ->
        flunk("receive_stream timeout")
    end
  end

  defp get_header(headers, name) do
    for {n, v} <- headers, n == name, do: v
  end
end
