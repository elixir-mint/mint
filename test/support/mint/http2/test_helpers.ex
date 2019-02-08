defmodule Mint.HTTP2.TestHelpers do
  import ExUnit.Assertions

  def receive_stream(conn) do
    receive_stream(conn, [])
  end

  def receive_stream(conn, responses) do
    assert_receive message, 10_000

    case message do
      {:rest, conn, rest_responses} ->
        maybe_done(conn, rest_responses, responses)

      {tag, _socket, _data} = message when tag in [:tcp, :ssl] ->
        assert {:ok, %Mint.HTTP2{} = conn, new_responses} = Mint.HTTP2.stream(conn, message)
        maybe_done(conn, new_responses, responses)

      {tag, _socket} = message when tag in [:tcp_closed, :ssl_closed] ->
        assert {:error, %Mint.HTTP2{}, :closed} = Mint.HTTP2.stream(conn, message)

      {tag, _reason} = message when tag in [:tcp_error, :ssl_error] ->
        assert {:error, %Mint.HTTP2{}, _reason} = Mint.HTTP2.stream(conn, message)

      other ->
        flunk("Received unexpected message: #{inspect(other)}")
    end
  end

  def maybe_done(conn, [{:done, _} = done | rest], acc) do
    if rest != [] do
      send(self(), {:rest, conn, rest})
    end

    {:ok, conn, acc ++ [done]}
  end

  def maybe_done(conn, [{:pong, _} = pong_resp | rest], acc) do
    if rest != [] do
      send(self(), {:rest, conn, rest})
    end

    {:ok, conn, acc ++ [pong_resp]}
  end

  def maybe_done(conn, [resp | rest], acc) do
    maybe_done(conn, rest, acc ++ [resp])
  end

  def maybe_done(conn, [], acc) do
    receive_stream(conn, acc)
  end
end
