defmodule XHTTP1.TestHelpers do
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
    receive_stream(conn, [])
  end

  def receive_stream(conn, responses) do
    receive do
      {:rest, conn, rest_responses} ->
        maybe_done(conn, rest_responses, responses)

      {tag, _socket, _data} = message when tag in [:tcp, :ssl] ->
        assert {:ok, conn, new_responses} = conn.__struct__.stream(conn, message)
        maybe_done(conn, new_responses, responses)

      {tag, _socket} = message when tag in [:tcp_closed, :ssl_closed] ->
        assert {:ok, conn, new_responses} = conn.__struct__.stream(conn, message)
        maybe_done(conn, new_responses, responses)

      {tag, _reason} = message when tag in [:tcp_error, :ssl_error] ->
        assert {:error, _conn, _reason} = conn.__struct__.stream(conn, message)
    after
      10000 ->
        flunk("receive_stream timeout")
    end
  end

  def maybe_done(conn, responses, acc) do
    {new, rest} = Enum.split_while(responses, &(not match?({:done, _}, &1)))

    case {new, rest} do
      {new, []} ->
        receive_stream(conn, acc ++ new)

      {new, [done | rest]} ->
        if rest != [], do: send(self(), {:rest, conn, rest})
        {:ok, conn, acc ++ new ++ [done]}
    end
  end

  def get_header(headers, name) do
    for {n, v} <- headers, n == name, do: v
  end
end
