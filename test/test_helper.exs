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

defmodule XHTTP1.TestHelpers.TCPMock do
  def connect(hostname, port, opts \\ []) do
    Kernel.send(self(), {:tcp_mock, :connect, [hostname, port, opts]})
    {:ok, make_ref()}
  end

  def close(socket) do
    Kernel.send(self(), {:tcp_mock, :close, [socket]})
    :ok
  end

  def getopts(socket, list) do
    Kernel.send(self(), {:tcp_mock, :getopts, [socket, list]})
    {:ok, Enum.map(list, &{&1, 0})}
  end

  def setopts(socket, opts) do
    Kernel.send(self(), {:tcp_mock, :setopts, [socket, opts]})
    :ok
  end

  def send(socket, data, opts \\ []) do
    Kernel.send(self(), {:tcp_mock, :send, [socket, data, opts]})
    :ok
  end
end
