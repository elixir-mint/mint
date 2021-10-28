defmodule Mint.HTTP2.TestServer do
  use GenServer

  import ExUnit.Assertions

  import Mint.Core.Util, only: [maybe_concat: 2]

  alias Mint.HTTP2.Frame

  @enforce_keys [:test_runner, :frames]
  defstruct [
    :test_runner,
    :connect_options,
    :server_settings,
    :port,
    :listen_socket,
    :server_socket,
    :frames
  ]

  @ssl_opts [
    mode: :binary,
    packet: :raw,
    active: false,
    reuseaddr: true,
    next_protocols_advertised: ["h2"],
    alpn_preferred_protocols: ["h2"],
    certfile: Path.absname("../certificate.pem", __DIR__),
    keyfile: Path.absname("../key.pem", __DIR__)
  ]

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  def start_link(args) when is_list(args) do
    GenServer.start_link(__MODULE__, args)
  end

  def recv_next_frames(server_pid, frame_count) when frame_count > 0 do
    GenServer.call(server_pid, {:recv_next_frames, frame_count})
  end

  def send_data(server_pid, data) do
    GenServer.call(server_pid, {:send_data, data})
  end

  @spec get_socket(%__MODULE__{}) :: :ssl.sslsocket()
  def get_socket(server_pid) do
    GenServer.call(server_pid, :get_socket)
  end

  # LRB TODO specs for GenServer callbacks?
  @impl true
  @spec init(keyword()) :: {:ok, %__MODULE__{}, {:continue, {:do_init, keyword()}}}
  def init(args) do
    test_runner = Keyword.fetch!(args, :test_runner)

    {:ok, %__MODULE__{test_runner: test_runner, frames: :queue.new()},
     {:continue, {:do_init, args}}}
  end

  @impl true
  def handle_call({:recv_next_frames, frame_count}, _from, %__MODULE__{frames: frames} = state)
      when frame_count > 0 do
    {dequeued, frames} = dequeue(frames, frame_count, [])
    {:reply, dequeued, %__MODULE__{state | frames: frames}}
  end

  @impl true
  def handle_call({:send_data, data}, _from, %__MODULE__{server_socket: server_socket} = state) do
    result = :ssl.send(server_socket, data)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_socket, _from, %__MODULE__{server_socket: server_socket} = state) do
    {:reply, {:ok, server_socket}, state}
  end

  @impl true
  def handle_continue(
        {:do_init, args},
        %__MODULE__{frames: frames, test_runner: test_runner} = state
      ) do
    connect_options = Keyword.fetch!(args, :connect_options)
    server_settings = Keyword.fetch!(args, :server_settings)
    send_settings_delay = Keyword.fetch!(args, :send_settings_delay)
    {:ok, {{:port, port} = port_msg, {:listen_socket, listen_socket}}} = start_socket()

    :ok = send_msg(test_runner, port_msg)

    {:ok, server_socket, frames} = accept_and_handshakes(listen_socket, frames)

    :ok = maybe_send_frames_event(test_runner, frames)

    _ref = Process.send_after(self(), :send_settings, send_settings_delay)

    {:noreply,
     %__MODULE__{
       state
       | connect_options: connect_options,
         server_settings: server_settings,
         port: port,
         listen_socket: listen_socket,
         server_socket: server_socket,
         frames: frames
     }}
  end

  @impl true
  def handle_info(
        :send_settings,
        %__MODULE__{
          server_socket: server_socket,
          server_settings: server_settings
        } = state
      ) do
    :ok = send_settings(server_socket, server_settings)
    {:noreply, state}
  end

  @impl true
  def handle_info(
        {:ssl, server_socket, data_in},
        %__MODULE__{
          server_socket: server_socket,
          test_runner: test_runner,
          frames: {:more, frames, data}
        } = state
      ) do
    frames = decode_frames(maybe_concat(data, data_in), frames)
    {:ok, frames} = maybe_send_settings_ack(server_socket, frames)
    :ok = maybe_send_frames_event(test_runner, frames)
    {:noreply, %__MODULE__{state | frames: frames}}
  end

  @impl true
  def handle_info(
        {:ssl, server_socket, data},
        %__MODULE__{server_socket: server_socket, test_runner: test_runner, frames: frames} =
          state
      ) do
    frames = decode_frames(data, frames)
    {:ok, frames} = maybe_send_settings_ack(server_socket, frames)
    :ok = maybe_send_frames_event(test_runner, frames)
    {:noreply, %__MODULE__{state | frames: frames}}
  end

  @impl true
  def handle_info({:ssl_closed, _}, state) do
    # NOTE: we can't stop because there may be more frames to recv by test runner
    # {:stop, :normal, state}
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    IO.puts(:stderr, "[WARNING] unknown handle_info msg #{inspect(msg)} state: #{inspect(state)}")
    {:noreply, state}
  end

  defp start_socket do
    {:ok, listen_socket} = :ssl.listen(0, @ssl_opts)
    {:ok, {_address, port}} = :ssl.sockname(listen_socket)
    {:ok, {{:port, port}, {:listen_socket, listen_socket}}}
  end

  defp accept_and_handshakes(listen_socket, frames) do
    # Let's accept a new connection.
    {:ok, server_socket} = :ssl.transport_accept(listen_socket)

    if function_exported?(:ssl, :handshake, 1) do
      {:ok, _} = apply(:ssl, :handshake, [server_socket])
    else
      :ok = apply(:ssl, :ssl_accept, [server_socket])
    end

    {:ok, frames} = perform_http2_handshake(server_socket, frames)

    :ok = :ssl.setopts(server_socket, active: true)

    {:ok, server_socket, frames}
  end

  defp perform_http2_handshake(server_socket, frames) do
    import Mint.HTTP2.Frame, only: [settings: 1]

    no_flags = Frame.set_flags(:settings, [])

    # First we get the connection preface.
    {:ok, unquote(@connection_preface)} =
      :ssl.recv(server_socket, byte_size(@connection_preface), 100)

    # Then we get a SETTINGS frame.
    frames = recv_and_decode(server_socket, "", frames)
    {{:value, settings_frame}, frames} = :queue.out(frames)
    assert settings(flags: ^no_flags, params: _params) = settings_frame

    # NOTE: we may get frames already from a test, which is why we save and return them here
    {:ok, frames}
  end

  defp send_settings(server_socket, server_settings) do
    import Mint.HTTP2.Frame, only: [settings: 1]
    settings_frame = Frame.encode(settings(params: server_settings))

    case :ssl.send(server_socket, settings_frame) do
      {:error, :closed} ->
        :ok

      val ->
        val
    end
  end

  defp maybe_send_settings_ack(_server_socket, {:more, _frames, _data} = frames) do
    {:ok, frames}
  end

  defp maybe_send_settings_ack(server_socket, frames) do
    import Mint.HTTP2.Frame, only: [settings: 1]

    ack_flags = Frame.set_flags(:settings, [:ack])

    f = fn
      settings(flags: ^ack_flags, params: []) ->
        reply_settings_frame = Frame.encode(settings(flags: ack_flags, params: []))
        :ok = :ssl.send(server_socket, reply_settings_frame)
        false

      _frame ->
        true
    end

    {:ok, :queue.filter(f, frames)}
  end

  defp decode_frames("", frames) do
    frames
  end

  defp decode_frames(data, frames0) do
    case Frame.decode_next(data) do
      {:ok, frame, rest} ->
        frames1 = :queue.in(frame, frames0)
        decode_frames(rest, frames1)

      :more ->
        {:more, frames0, data}

      other ->
        # LRB TODO throw? exit?
        {:error, "Error decoding frame: #{inspect(other)}"}
    end
  end

  defp recv_and_decode(server_socket, data, frames) do
    {:ok, data_in} = :ssl.recv(server_socket, 0, 100)

    case decode_frames(data_in, frames) do
      :more ->
        recv_and_decode(server_socket, maybe_concat(data, data_in), frames)

      decoded_frames ->
        decoded_frames
    end
  end

  defp dequeue(q, 0, acc) do
    {Enum.reverse(acc), q}
  end

  defp dequeue(q0, n, acc) do
    case :queue.out(q0) do
      {{:value, item}, q1} ->
        dequeue(q1, n - 1, [item | acc])

      {:empty, q1} ->
        # LRB TODO error
        dequeue(q1, 0, acc)
    end
  end

  defp maybe_send_frames_event(_test_runner, {:more, _frames, _data}) do
    :ok
  end

  defp maybe_send_frames_event(test_runner, frames) do
    case :queue.len(frames) do
      0 ->
        :ok

      len when len > 0 ->
        msg = {:frames_available, len}
        send_msg(test_runner, msg)
        :ok
    end
  end

  defp send_msg({pid, ref}, msg0) when is_pid(pid) and is_reference(ref) do
    msg1 = {ref, msg0}
    send(pid, msg1)
    :ok
  end
end
