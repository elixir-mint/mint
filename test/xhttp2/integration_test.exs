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
      assert {:ok, %Conn{} = conn, req_id} = Conn.request(conn, "GET", "/reqinfo", [])

      assert {:ok, %Conn{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, "200"},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data =~ "Method: GET"

      assert conn.buffer == ""
      assert Conn.open?(conn)
    end

    test "GET /clockstream", %{conn: conn} do
      assert {:ok, %Conn{} = conn, req_id} = Conn.request(conn, "GET", "/clockstream", [])

      assert_receive message, 5000
      assert {:ok, %Conn{} = conn, responses} = Conn.stream(conn, message)
      assert [{:status, ^req_id, "200"}, {:headers, ^req_id, _headers}] = responses

      assert_receive message, 5000
      assert {:ok, %Conn{} = conn, responses} = Conn.stream(conn, message)
      assert [{:data, ^req_id, data}] = responses
      assert data =~ "# ~1KB of junk to force browsers to start rendering immediately"

      assert_receive message, 5000
      assert {:ok, %Conn{} = conn, responses} = Conn.stream(conn, message)
      assert [{:data, ^req_id, data}] = responses
      assert data =~ ~r/\A\d{4}-\d{2}-\d{2}/

      assert Conn.open?(conn)
    end

    test "PUT /ECHO", %{conn: conn} do
      assert {:ok, %Conn{} = conn, req_id} = Conn.request(conn, "PUT", "/ECHO", [], "hello world")

      assert {:ok, %Conn{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, "200"},
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

    test "GET /file/gopher.png", %{conn: conn} do
      assert {:ok, %Conn{} = conn, ref} = Conn.request(conn, "GET", "/file/gopher.png", [])
      assert {:ok, %Conn{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^ref, "200"},
               {:headers, ^ref, headers},
               {:data, ^ref, data1},
               {:data, ^ref, data2},
               {:data, ^ref, data3},
               {:done, ^ref}
             ] = responses

      assert is_list(headers)
      assert is_binary(data1)
      assert is_binary(data2)
      assert is_binary(data3)

      assert conn.buffer == ""
      assert Conn.open?(conn)
    end

    test "ping", %{conn: conn} do
      assert {:ok, %Conn{} = conn, ref} = Conn.ping(conn)
      assert {:ok, %Conn{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert Conn.open?(conn)
    end
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

  defp maybe_done(conn, [{:pong, _} = pong_resp | rest], acc) do
    if rest != [] do
      send(self(), {:rest, conn, rest})
    end

    {:ok, conn, acc ++ [pong_resp]}
  end

  defp maybe_done(conn, [resp | rest], acc) do
    maybe_done(conn, rest, acc ++ [resp])
  end

  defp maybe_done(conn, [], acc) do
    receive_stream(conn, acc)
  end
end
