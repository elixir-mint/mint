defmodule XHTTP2.Server do
  use GenServer

  import XHTTP2.Frame

  defstruct [
    :listen_socket,
    :socket,
    :port,
    :handshake_fun,
    buffer: "",
    encode_table: XHTTP2.HPACK.new(4096),
    decode_table: XHTTP2.HPACK.new(4096),
    frame_handlers: :queue.new()
  ]

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

  def start(handshake_fun \\ &handshake/1) when is_function(handshake_fun, 1) do
    GenServer.start(__MODULE__, handshake_fun)
  end

  def port(server) do
    GenServer.call(server, :get_port)
  end

  def expect(server, fun) when is_function(fun, 2) do
    :ok = GenServer.call(server, {:expect, fun})
    server
  end

  def start_accepting(server) do
    GenServer.cast(server, :start_accepting)
  end

  def stop(server) do
    GenServer.stop(server)
  end

  ## Callbacks

  @impl true
  def init(handshake_fun) do
    {:ok, listen_socket} = :ssl.listen(0, @ssl_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    state = %__MODULE__{listen_socket: listen_socket, port: port, handshake_fun: handshake_fun}
    {:ok, state}
  end

  @impl true
  def handle_call(call, from, state)

  def handle_call(:get_port, _from, %{port: port} = state) do
    {:reply, port, state}
  end

  def handle_call({:expect, fun}, _from, state) do
    state = update_in(state.frame_handlers, &:queue.in(fun, &1))
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast(:start_accepting, state) do
    {:ok, socket} = :ssl.transport_accept(state.listen_socket)
    :ok = :ssl.ssl_accept(socket)
    :ok = state.handshake_fun.(socket)
    :ok = :ssl.setopts(socket, active: true)
    {:noreply, %{state | socket: socket}}
  end

  @impl true
  def handle_info(msg, state)

  def handle_info({:ssl, socket, packet}, %{socket: socket} = state) do
    state = handle_data(state, packet)
    {:noreply, state}
  end

  def handle_info({:ssl_closed, socket}, %{socket: socket} = state) do
    {:noreply, state}
  end

  def handle_info({:ssl_error, socket, _reason}, %{socket: socket} = state) do
    {:noreply, state}
  end

  defp handle_data(state, packet) do
    case decode_next(state.buffer <> packet) do
      {:ok, frame, rest} ->
        case get_and_update_in(state.frame_handlers, &:queue.out/1) do
          {{:value, handler}, state} ->
            state =
              case handler.(state, frame) do
                :ok -> state
                %{} = new_state -> new_state
              end

            handle_data(state, rest)

          {:empty, _state} ->
            raise "could not handle frame because of missing handler: #{inspect(frame)}"
        end

      :more ->
        put_in(state.buffer, packet)

      {:error, reason} ->
        raise "frame decoding error: #{inspect(reason)}"
    end
  end

  connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  defp handshake(socket) do
    {:ok, unquote(connection_preface) <> rest} = :ssl.recv(socket, 0, 100)
    {:ok, settings(stream_id: 0, flags: 0x00), ""} = decode_next(rest)

    settings = settings(stream_id: 0, flags: 0x00, params: [])
    :ok = :ssl.send(socket, encode(settings))

    {:ok, packet} = :ssl.recv(socket, 0, 100)
    {:ok, settings(stream_id: 0, flags: 0x01), ""} = decode_next(packet)

    settings = settings(stream_id: 0, flags: 0x01, params: [])
    :ok = :ssl.send(socket, encode(settings))
  end
end
