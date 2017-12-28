ExUnit.start()
Application.ensure_all_started(:ssl)

defmodule XHTTP1.TestHelpers do
  def merge_body(responses, request) do
    merge_body(responses, request, "")
  end

  defp merge_body([{:body, request, new_body} | responses], request, body) do
    merge_body(responses, request, body <> new_body)
  end

  defp merge_body([{:done, request}], request, body) do
    body
  end

  def merge_body_with_trailers(responses, request) do
    merge_body_with_trailers(responses, request, "")
  end

  defp merge_body_with_trailers([{:body, request, new_body} | responses], request, body) do
    merge_body_with_trailers(responses, request, body <> new_body)
  end

  defp merge_body_with_trailers([{:headers, request, trailing}, {:done, request}], request, body) do
    {body, trailing}
  end

  def merge_pipelined_body(responses, request) do
    merge_pipelined_body(responses, request, "")
  end

  defp merge_pipelined_body([{:body, request, new_body} | responses], request, body) do
    merge_pipelined_body(responses, request, body <> new_body)
  end

  defp merge_pipelined_body([{:done, request} | rest], request, body) do
    {body, rest}
  end
end

defmodule XHTTP1.TestHelpers.Server do
  def start() do
    {:ok, listen_socket} = :gen_tcp.listen(0, mode: :binary, packet: :raw)
    spawn_link(fn -> loop(listen_socket) end)
    :inet.port(listen_socket)
  end

  defp loop(listen_socket) do
    {:ok, _socket} = :gen_tcp.accept(listen_socket)
    loop(listen_socket)
  end
end
