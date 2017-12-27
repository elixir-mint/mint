defmodule XHTTP2.SSLMock do
  @behaviour :gen_statem

  alias XHTTP2.{Frame, HPACK}

  import XHTTP2.Frame, except: [encode: 1]

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @state %{
    state: nil,
    decode_table: HPACK.new(4096),
    encode_table: HPACK.new(4096),
    controlling_process: nil
  }

  def connect(_hostname, _port, _opts) do
    {:ok, _pid} = :gen_statem.start_link(__MODULE__, [controlling_process: self()], [])
  end

  def negotiated_protocol(_pid) do
    {:ok, "h2"}
  end

  def close(pid) do
    :ok = GenServer.stop(pid)
  end

  def getopts(_pid, list) do
    {:ok, Enum.map(list, &{&1, 0})}
  end

  def setopts(_pid, _opts) do
    :ok
  end

  def send(pid, data, _opts \\ []) do
    GenServer.call(pid, {:send, IO.iodata_to_binary(data)})
  end

  def recv(pid, _) do
    GenServer.call(pid, :recv)
  end

  ## Callbacks

  @impl :gen_statem
  def terminate(_reason, _state, _data), do: :void

  @impl :gen_statem
  def code_change(_vsn, state, data, _extra), do: {:ok, state, data}

  @impl :gen_statem
  def callback_mode(), do: :state_functions

  @impl :gen_statem
  def init(options) do
    data = Map.put(@state, :controlling_process, Keyword.fetch!(options, :controlling_process))
    {:ok, :connected, data}
  end

  def connected({:call, from}, {:send, @connection_preface <> rest}, data) do
    {:ok, settings(stream_id: 0, flags: 0x00), ""} = Frame.decode_next(rest)
    {:next_state, :got_client_settings, data, {:reply, from, :ok}}
  end

  def got_client_settings({:call, from}, :recv, data) do
    settings = settings(stream_id: 0, flags: 0x00, params: [])
    {:next_state, :sent_server_settings, data, {:reply, from, {:ok, encode(settings)}}}
  end

  def sent_server_settings({:call, from}, {:send, packet}, data) do
    {:ok, settings(stream_id: 0, flags: 0x01), ""} = Frame.decode_next(packet)
    {:next_state, :got_client_settings_ack, data, {:reply, from, :ok}}
  end

  def got_client_settings_ack({:call, from}, :recv, data) do
    settings = settings(stream_id: 0, flags: 0x01, params: [])
    {:next_state, :idle, data, {:reply, from, {:ok, encode(settings)}}}
  end

  def idle({:call, from}, {:send, packet}, data) do
    {:ok, frame, ""} = Frame.decode_next(packet)

    case frame do
      headers(hbf: hbf, stream_id: stream_id) ->
        {:ok, headers, decode_table} = HPACK.decode(hbf, data.decode_table)
        data = put_in(data.decode_table, decode_table)
        handle_request(data, stream_id, get_req_header(headers, ":path"), headers)
    end

    {:keep_state_and_data, {:reply, from, :ok}}
  end

  defp handle_request(_data, _stream_id, "/", _) do
    :ok
  end

  defp handle_request(data, stream_id, "/server-sends-rst-stream", _) do
    frame = rst_stream(stream_id: stream_id, error_code: :protocol_error)
    Kernel.send(data.controlling_process, {:ssl_mock, self(), encode(frame)})
  end

  defp handle_request(data, _stream_id, "/server-sends-goaway", _) do
    frame =
      goaway(
        stream_id: 0,
        last_stream_id: 3,
        error_code: :protocol_error,
        debug_data: "debug data"
      )

    Kernel.send(data.controlling_process, {:ssl_mock, self(), encode(frame)})
  end

  defp handle_request(data, stream_id, "/split-headers-into-continuation", _) do
    headers = [
      {:store_name, ":status", "200"},
      {:store_name, "foo", "bar"},
      {:store_name, "baz", "bong"}
    ]

    {hbf, _encode_table} = HPACK.encode(headers, data.encode_table)

    <<hbf1::1-bytes, hbf2::1-bytes, hbf3::binary>> = IO.iodata_to_binary(hbf)

    # TODO: update encode table

    frame1 = headers(stream_id: stream_id, hbf: hbf1)
    Kernel.send(data.controlling_process, {:ssl_mock, self(), encode(frame1)})

    frame2 = continuation(stream_id: stream_id, hbf: hbf2)
    Kernel.send(data.controlling_process, {:ssl_mock, self(), encode(frame2)})

    frame3 = continuation(stream_id: stream_id, hbf: hbf3, flags: 0x04)
    Kernel.send(data.controlling_process, {:ssl_mock, self(), encode(frame3)})
  end

  defp encode(frame) do
    frame |> Frame.encode() |> IO.iodata_to_binary()
  end

  defp get_req_header(headers, header) do
    {^header, value} = List.keyfind(headers, header, 0)
    value
  end
end
