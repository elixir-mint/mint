defmodule Mint.HTTP2.TestHelpers do
  import ExUnit.Assertions

  @spec receive_stream(Mint.HTTP2.t()) :: {:ok, Mint.HTTP2.t(), [Mint.Types.response()]}
  def receive_stream(%Mint.HTTP2{} = conn) do
    receive_stream(conn, [])
  end

  defp receive_stream(conn, responses) do
    assert_receive message, 10_000

    {tag, closed_tag, error_tag} =
      case conn.transport do
        Mint.Core.Transport.TCP -> {:tcp, :tcp_closed, :tcp_error}
        Mint.Core.Transport.SSL -> {:ssl, :ssl_closed, :ssl_error}
      end

    case message do
      {:rest, conn, rest_responses} ->
        maybe_done(conn, rest_responses, responses)

      {^tag, _socket, _data} = message ->
        assert {:ok, %Mint.HTTP2{} = conn, new_responses} = Mint.HTTP2.stream(conn, message)
        maybe_done(conn, new_responses, responses)

      {^closed_tag, _socket} = message ->
        assert {:error, %Mint.HTTP2{}, :closed} = Mint.HTTP2.stream(conn, message)

      {^error_tag, _reason} = message ->
        assert {:error, %Mint.HTTP2{}, _reason} = Mint.HTTP2.stream(conn, message)

      other ->
        flunk("Received unexpected message: #{inspect(other)}")
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
