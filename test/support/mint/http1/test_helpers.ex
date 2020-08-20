defmodule Mint.HTTP1.TestHelpers do
  import ExUnit.Assertions

  def merge_body(responses, request) do
    merge_body(responses, request, "")
  end

  defp merge_body([{:data, request, new_body} | responses], request, body) do
    merge_body(responses, request, body <> new_body)
  end

  defp merge_body([{:done, request}], request, body) do
    body
  end

  def merge_body_with_trailers(responses, request) do
    merge_body_with_trailers(responses, request, "")
  end

  defp merge_body_with_trailers([{:data, request, new_body} | responses], request, body) do
    merge_body_with_trailers(responses, request, body <> new_body)
  end

  defp merge_body_with_trailers([{:headers, request, trailing}, {:done, request}], request, body) do
    {body, trailing}
  end

  def merge_pipelined_body(responses, request) do
    merge_pipelined_body(responses, request, "")
  end

  defp merge_pipelined_body([{:data, request, new_body} | responses], request, body) do
    merge_pipelined_body(responses, request, body <> new_body)
  end

  defp merge_pipelined_body([{:done, request} | rest], request, body) do
    {body, rest}
  end

  def receive_stream(conn) do
    receive do
      {:rest, previous} ->
        maybe_done(conn, previous)
    after
      0 ->
        receive_stream(conn, [])
    end
  end

  def receive_stream(conn, acc) do
    socket = Mint.HTTP.get_socket(conn)

    receive do
      {tag, ^socket, _data} = message when tag in [:tcp, :ssl] ->
        assert {:ok, conn, responses} = conn.__struct__.stream(conn, message)
        maybe_done(conn, acc ++ responses)

      {tag, ^socket} = message when tag in [:tcp_closed, :ssl_closed] ->
        assert {:ok, conn, responses} = conn.__struct__.stream(conn, message)
        maybe_done(conn, acc ++ responses)

      {tag, ^socket, _reason} = message when tag in [:tcp_error, :ssl_error] ->
        assert {:error, _conn, _reason, _responses} = conn.__struct__.stream(conn, message)
    after
      10000 ->
        flunk("receive_stream timeout")
    end
  end

  def maybe_done(conn, responses) do
    {all, rest} = Enum.split_while(responses, &(not match?({:done, _}, &1)))

    case {all, rest} do
      {all, []} ->
        receive_stream(conn, all)

      {all, [done | rest]} ->
        if rest != [], do: send(self(), {:rest, rest})
        {:ok, conn, all ++ [done]}
    end
  end

  def get_header(headers, name) do
    for {n, v} <- headers, n == name, do: v
  end

  def local_addr() do
    {:ok, addrs} = :inet.getif()
    local_addr = List.first(addrs) |> elem(0) |> :inet.ntoa()
    "#{local_addr}"
  end

  def unused_ip() do
    {:ok, host} = :inet.gethostname()
    {:ok, hent} = :inet.gethostbyname(host)
    {:hostent, _, _, _, _, [{a, b, c, _d} | _]} = hent
    unused_ip(a, b, c, 16)
  end

  defp unused_ip(255, b, c, d), do: unused_ip(1, b + 1, c, d)
  defp unused_ip(a, 255, c, d), do: unused_ip(a, 1, c + 1, d)
  defp unused_ip(a, b, 255, d), do: unused_ip(a, b, 1, d + 1)

  defp unused_ip(a, b, c, d) do
    case :inet.gethostbyaddr({a, b, c, d}) do
      {:ok, _} -> unused_ip(a + 1, b, c, d)
      {:error, _} -> "#{:inet.ntoa({a, b, c, d})}"
    end
  end
end
