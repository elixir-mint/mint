defmodule Mint.HTTP2.TestServer do
  use GenServer

  import Mint.HTTP2.Frame
  import ExUnit.Assertions

  alias Mint.HTTP2.{Frame, HPACK}

  require Logger

  defstruct [
    :listen_socket,
    :socket,
    :port,
    buffer: "",
    encode_table: Mint.HTTP2.HPACK.new(4096),
    decode_table: Mint.HTTP2.HPACK.new(4096),
    frame_handlers: :queue.new(),
    verifying_from: nil
  ]

  @handshake_recv_timeout 100

  @certificate Path.absname("certificate.pem", __DIR__)
  @key Path.absname("key.pem", __DIR__)
  @ssl_opts [
    mode: :binary,
    packet: :raw,
    active: false,
    reuseaddr: true,
    next_protocols_advertised: ["h2"],
    alpn_preferred_protocols: ["h2"],
    certfile: @certificate,
    keyfile: @key
  ]

  ## API

  def start_link() do
    GenServer.start_link(__MODULE__, nil)
  end

  def port(server) do
    GenServer.call(server, :get_port)
  end

  def expect(server, fun) when is_function(fun, 2) do
    :ok = GenServer.call(server, {:expect, fun})
    server
  end

  def allow_anything(server) do
    :ok = GenServer.call(server, :allow_anything)
    server
  end

  def start_accepting(server) do
    GenServer.cast(server, :start_accepting)
  end

  def decode_headers(%__MODULE__{} = state, hbf) do
    {:ok, headers, decode_table} = HPACK.decode(hbf, state.decode_table)
    state = put_in(state.decode_table, decode_table)
    {state, headers}
  end

  def encode_headers(%__MODULE__{} = state, headers) do
    {hbf, state} =
      get_and_update_in(state.encode_table, fn encode_table ->
        headers
        |> Enum.map(fn {name, value} -> {:store_name, name, value} end)
        |> HPACK.encode(encode_table)
      end)

    {state, hbf}
  end

  def send(%__MODULE__{} = state, iodata) do
    :ok = :ssl.send(state.socket, iodata)
    state
  end

  def send_frames(%__MODULE__{} = state, frames) do
    __MODULE__.send(state, Enum.map(frames, &Frame.encode/1))
  end

  def send_frame(%__MODULE__{} = state, frame), do: send_frames(state, [frame])

  def send_headers(%__MODULE__{} = state, stream_id, headers, flags) do
    {state, hbf} = __MODULE__.encode_headers(state, headers)
    flags = set_flags(:headers, flags)
    frame = headers(stream_id: stream_id, hbf: hbf, flags: flags)
    send_frame(state, frame)
  end

  def verify(server) do
    GenServer.call(server, :verify)
  end

  ## Callbacks

  @impl true
  def init(nil) do
    {:ok, listen_socket} = :ssl.listen(0, @ssl_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    state = %__MODULE__{listen_socket: listen_socket, port: port}
    {:ok, state}
  end

  @impl true
  def handle_call(call, from, state)

  def handle_call(:get_port, _from, %{port: port} = state) do
    {:reply, port, state}
  end

  def handle_call({:expect, fun}, _from, state) do
    if state.verifying_from do
      flunk("Cannot add a frame expectation when verify/1 has been called")
    else
      state = update_in(state.frame_handlers, &:queue.in(fun, &1))
      {:reply, :ok, state}
    end
  end

  def handle_call(:verify, from, state) do
    case :queue.peek(state.frame_handlers) do
      :empty -> {:reply, :ok, state}
      _other -> {:noreply, put_in(state.verifying_from, from)}
    end
  end

  def handle_call(:allow_anything, _from, state) do
    state = update_in(state.frame_handlers, &:queue.in(:allow_anything, &1))
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast(:start_accepting, state) do
    {:ok, socket} = :ssl.transport_accept(state.listen_socket)
    :ok = :ssl.ssl_accept(socket)
    :ok = handshake(socket)
    :ok = :ssl.setopts(socket, active: true)
    {:noreply, %{state | socket: socket}}
  end

  @impl true
  def handle_info(msg, state)

  def handle_info({:ssl, socket, packet}, %{socket: socket} = state) do
    state = handle_data(state, state.buffer <> packet)
    {:noreply, state}
  end

  def handle_info({:ssl_closed, socket}, %{socket: socket} = state) do
    {:noreply, state}
  end

  def handle_info({:ssl_error, socket, _reason}, %{socket: socket} = state) do
    {:noreply, state}
  end

  defp handle_data(state, data) do
    verifying? = not is_nil(state.verifying_from)
    frame_handlers_left? = :queue.peek(state.frame_handlers) != :empty

    case decode_next(data) do
      {:ok, frame, rest} ->
        state = handle_frame(state, frame)
        handle_data(state, rest)

      :more when verifying? and data != "" and not frame_handlers_left? ->
        flunk("There's data left but no frame was expected. Data: #{inspect(data)}")

      :more when verifying? and data == "" and not frame_handlers_left? ->
        GenServer.reply(state.verifying_from, :ok)
        put_in(state.buffer, "")

      :more ->
        put_in(state.buffer, data)

      {:error, reason} ->
        flunk("Frame decoding error: #{inspect(reason)}")
    end
  end

  defp handle_frame(state, frame) do
    case get_and_update_in(state.frame_handlers, &:queue.out/1) do
      {{:value, :allow_anything}, state} ->
        _ = Logger.debug("Ignoring frame #{inspect(frame)}")
        update_in(state.frame_handlers, &:queue.in_r(:allow_anything, &1))

      {{:value, handler}, state} ->
        call_handler(state, frame, handler)

      {:empty, _state} ->
        flunk("Received frame but no frame was expected. Frame: #{inspect(frame)}")
    end
  end

  defp call_handler(state, frame, handler) do
    assert %__MODULE__{} = state = handler.(state, frame)
    state
  rescue
    FunctionClauseError ->
      flunk("Next handler failed because it didn't match frame: #{inspect(frame)}")
  end

  connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  defp handshake(socket) do
    no_flags = 0x00
    ack_flags = set_flag(:settings, :ack)

    assert {:ok, unquote(connection_preface) <> rest} =
             :ssl.recv(socket, 0, @handshake_recv_timeout)

    assert {:ok, settings(flags: no_flags, params: _), ""} = Frame.decode_next(rest)

    assert :ok = :ssl.send(socket, encode(settings(params: [])))

    assert {:ok, packet} = :ssl.recv(socket, 0, @handshake_recv_timeout)

    assert {:ok, settings(stream_id: 0, flags: ^ack_flags, params: []), ""} =
             Frame.decode_next(packet)

    assert :ok = :ssl.send(socket, encode(settings(flags: ack_flags, params: [])))
  end
end
