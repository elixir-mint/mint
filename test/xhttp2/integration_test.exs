defmodule XHTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  alias XHTTP2.Conn

  @moduletag :integration

  setup context do
    case context.connect do
      {host, port} ->
        assert {:ok, %Conn{} = conn} = Conn.connect(host, port)
        [conn: conn]

      _other ->
        []
    end
  end

  describe "http2.golang.org" do
    @moduletag connect: {"http2.golang.org", 443}

    test "GET /reqinfo", %{conn: conn} do
      headers = headers_for_request("GET", "https://http2.golang.org/reqinfo")
      assert {:ok, %Conn{} = conn, req_id} = Conn.request(conn, headers)

      assert {:ok, %Conn{} = conn, responses} = receive_stream(conn)

      assert [
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data =~ "Method: GET"

      assert conn.buffer == ""
      assert Conn.open?(conn)
    end

    test "PUT /ECHO", %{conn: conn} do
      headers = headers_for_request("PUT", "https://http2.golang.org/ECHO")
      assert {:ok, %Conn{} = conn, req_id} = Conn.request(conn, headers, "hello world")

      assert {:ok, %Conn{} = conn, responses} = receive_stream(conn)

      assert [
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:data, ^req_id, ""},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data == "HELLO WORLD"

      assert conn.buffer == ""
      assert Conn.open?(conn)
    end

    test "ping", %{conn: conn} do
      assert {:ok, %Conn{} = conn} = Conn.ping(conn)
      assert {:ok, %Conn{} = conn, [:pong]} = receive_stream(conn)
      assert conn.buffer == ""
      assert Conn.open?(conn)
    end
  end

  defp headers_for_request(method, url) do
    uri = URI.parse(url)

    [
      {":method", method},
      {":path", uri.path},
      {":scheme", uri.scheme},
      {":authority", uri.authority}
    ]
  end

  defp receive_stream(conn) do
    receive_stream(conn, [])
  end

  defp receive_stream(conn, responses) do
    receive do
      {:rest, conn, rest_responses} ->
        maybe_done(conn, rest_responses, responses)

      {tag, _socket, _data} = message when tag in [:tcp, :ssl] ->
        assert {:ok, %Conn{} = conn, new_responses} = Conn.stream(conn, message)
        maybe_done(conn, new_responses, responses)

      {tag, _socket} = message when tag in [:tcp_close, :ssl_close] ->
        assert {:error, %Conn{}, :closed} = Conn.stream(conn, message)

      {tag, _reason} = message when tag in [:tcp_error, :ssl_error] ->
        assert {:error, %Conn{}, _reason} = Conn.stream(conn, message)
    after
      10000 ->
        flunk("receive_stream timeout")
    end
  end

  defp maybe_done(conn, [{:done, _} = done | rest], acc) do
    if rest != [] do
      send(self(), {:rest, conn, rest})
    end

    {:ok, conn, acc ++ [done]}
  end

  defp maybe_done(conn, [:pong | rest], acc) do
    if rest != [] do
      send(self(), {:rest, conn, rest})
    end

    {:ok, conn, acc ++ [:pong]}
  end

  defp maybe_done(conn, [resp | rest], acc) do
    maybe_done(conn, rest, acc ++ [resp])
  end

  defp maybe_done(conn, [], acc) do
    receive_stream(conn, acc)
  end
end
