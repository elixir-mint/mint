ExUnit.start()
Application.ensure_all_started(:ssl)
Logger.configure(level: :info)

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

defmodule XHTTP2.TestHelpers.SSLMock do
  use GenServer

  alias XHTTP2.Frame

  import XHTTP2.Frame, except: [encode: 1]

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @state %{
    state: nil
  }

  def connect(hostname, port, opts) do
    Kernel.send(self(), {:ssl_mock, :connect, [hostname, port, opts]})
    {:ok, _pid} = GenServer.start_link(__MODULE__, nil)
  end

  def negotiated_protocol(pid) do
    Kernel.send(self(), {:ssl_mock, :send, [pid]})
    {:ok, "h2"}
  end

  def close(pid) do
    Kernel.send(self(), {:ssl_mock, :close, [pid]})
    :ok = Agent.stop(pid)
  end

  def getopts(pid, list) do
    Kernel.send(self(), {:ssl_mock, :getopts, [pid, list]})
    {:ok, Enum.map(list, &{&1, 0})}
  end

  def setopts(pid, opts) do
    Kernel.send(self(), {:ssl_mock, :setopts, [pid, opts]})
    :ok
  end

  def send(pid, data, opts \\ []) do
    Kernel.send(self(), {:ssl_mock, :send, [pid, data, opts]})
    GenServer.call(pid, {:send, IO.iodata_to_binary(data)})
  end

  def recv(pid, _) do
    Kernel.send(self(), {:ssl_mock, :recv, [pid]})
    GenServer.call(pid, :recv)
  end

  ## Callbacks

  @impl true
  def init(nil) do
    {:ok, put_in(@state.state, :connected)}
  end

  @impl true
  def handle_call({:send, @connection_preface <> rest}, _from, %{state: :connected} = state) do
    {:ok, settings(stream_id: 0, flags: 0x00), ""} = Frame.decode_next(rest)
    {:reply, :ok, %{state | state: :got_client_settings}}
  end

  def handle_call({:send, data}, _from, %{state: :sent_server_settings} = state) do
    {:ok, settings(stream_id: 0, flags: 0x01), ""} = Frame.decode_next(data)
    {:reply, :ok, %{state | state: :got_client_settings_ack}}
  end

  def handle_call({:send, _}, _from, state) do
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:recv, _from, %{state: :got_client_settings} = state) do
    settings = settings(stream_id: 0, flags: 0x00, params: [])
    {:reply, {:ok, encode(settings)}, %{state | state: :sent_server_settings}}
  end

  def handle_call(:recv, _from, %{state: :got_client_settings_ack} = state) do
    settings = settings(stream_id: 0, flags: 0x01, params: [])
    {:reply, {:ok, encode(settings)}, %{state | state: :ready}}
  end

  defp encode(frame) do
    frame |> Frame.encode() |> IO.iodata_to_binary()
  end
end
