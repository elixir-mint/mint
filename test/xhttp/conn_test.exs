defmodule XHTTP.ConnTest do
  use ExUnit.Case, async: true
  alias XHTTP.Conn

  @tag :integration
  test "google.com" do
    assert {:ok, conn} = Conn.connect("google.com", 80)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers, body, {:done, ^request}] = responses
    assert {:status, ^request, {{1, 1}, 302, "Found"}} = status
    assert {:headers, ^request, headers} = headers
    assert {:body, ^request, body} = body
    assert hd(get_header(headers, "location")) =~ "www.google."
    assert body =~ "<TITLE>302 Moved</TITLE>"
  end

  @tag :integration
  test "hex.pm" do
    assert {:ok, conn} = Conn.connect("hex.pm", 80)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers, body, {:done, ^request}] = responses
    assert {:status, ^request, {{1, 1}, 301, "Moved Permanently"}} = status
    assert {:headers, ^request, headers} = headers
    assert {:body, ^request, ""} = body
    assert get_header(headers, "location") == ["https://hex.pm/"]
  end

  @tag :integration
  test "example.com" do
    assert {:ok, conn} = Conn.connect("example.com", 80)
    assert {:ok, conn, request} = Conn.request(conn, "GET", "/", [], nil)
    assert {:ok, conn, responses} = receive_stream(conn, [])

    assert conn.buffer == ""
    assert [status, headers, body, {:done, ^request}] = responses
    assert {:status, ^request, {{1, 1}, 200, "OK"}} = status
    assert {:headers, ^request, _} = headers
    assert {:body, ^request, body} = body
    assert body =~ "<title>Example Domain</title>"
  end

  defp receive_stream(conn, responses) do
    receive do
      {:tcp, _socket, _data} = message ->
        assert {:ok, conn, new_responses} = Conn.stream(conn, message)

        if match?({:done, _}, Enum.at(new_responses, -1)) do
          {:ok, conn, responses ++ new_responses}
        else
          receive_stream(conn, responses ++ new_responses)
        end

      {:tcp_closed, _socket} = message ->
        assert {:error, _conn, :closed} = Conn.stream(conn, message)

      {:tcp_error, _reason} = message ->
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
