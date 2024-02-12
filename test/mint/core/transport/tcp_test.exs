defmodule Mint.Core.Transport.TCPTest do
  use ExUnit.Case, async: true

  alias Mint.Core.Transport.TCP

  describe "connect/3" do
    test "can connect to IPv6 addresses" do
      tcp_opts = [
        :inet6,
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true
      ]

      {:ok, listen_socket} = :gen_tcp.listen(0, tcp_opts)
      {:ok, {_address, port}} = :inet.sockname(listen_socket)

      task =
        Task.async(fn ->
          {:ok, _socket} = :gen_tcp.accept(listen_socket)
        end)

      assert {:ok, _socket} =
               TCP.connect({127, 0, 0, 1}, port,
                 active: false,
                 inet6: true,
                 timeout: 1000
               )

      assert {:ok, _server_socket} = Task.await(task)
    end

    test "can fall back to IPv4 if IPv6 fails" do
      tcp_opts = [
        :inet6,
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true
      ]

      {:ok, listen_socket} = :gen_tcp.listen(0, tcp_opts)
      {:ok, {_address, port}} = :inet.sockname(listen_socket)

      task =
        Task.async(fn ->
          {:ok, _socket} = :gen_tcp.accept(listen_socket)
        end)

      assert {:ok, _socket} =
               TCP.connect("localhost", port,
                 active: false,
                 inet6: true,
                 timeout: 1000
               )

      assert {:ok, _server_socket} = Task.await(task)
    end

    test "does not fall back to IPv4 if IPv4 is disabled" do
      tcp_opts = [
        :inet,
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true
      ]

      {:ok, listen_socket} = :gen_tcp.listen(0, tcp_opts)
      {:ok, {_address, port}} = :inet.sockname(listen_socket)

      Task.async(fn ->
        {:ok, _socket} = :gen_tcp.accept(listen_socket)
      end)

      assert {:error, %Mint.TransportError{reason: :econnrefused}} =
               TCP.connect("localhost", port,
                 active: false,
                 inet6: true,
                 inet4: false,
                 timeout: 1000
               )
    end
  end

  describe "controlling_process/2" do
    @describetag :capture_log

    setup do
      parent = self()
      ref = make_ref()

      ssl_opts = [
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true
      ]

      spawn_link(fn ->
        {:ok, listen_socket} = :gen_tcp.listen(0, ssl_opts)
        {:ok, {_address, port}} = :inet.sockname(listen_socket)
        send(parent, {ref, port})

        {:ok, socket} = :gen_tcp.accept(listen_socket)

        send(parent, {ref, socket})

        # Keep the server alive forever.
        :ok = Process.sleep(:infinity)
      end)

      assert_receive {^ref, port} when is_integer(port), 500

      {:ok, socket} = TCP.connect("localhost", port, [])
      assert_receive {^ref, server_socket}, 200

      {:ok, server_port: port, socket: socket, server_socket: server_socket}
    end

    test "changing the controlling process of a active: :once socket",
         %{socket: socket, server_socket: server_socket} do
      parent = self()
      ref = make_ref()

      # Send two SSL messages (that get translated to Erlang messages right
      # away because of "nodelay: true"), but wait after each one so that
      # it actually arrives and we can set the socket back to active: :once.
      :ok = TCP.setopts(socket, active: :once)
      :ok = :gen_tcp.send(server_socket, "some data 1")
      Process.sleep(100)

      :ok = TCP.setopts(socket, active: :once)
      :ok = :gen_tcp.send(server_socket, "some data 2")

      wait_until_passes(500, fn ->
        {:messages, messages} = Process.info(self(), :messages)
        assert {:tcp, socket, "some data 1"} in messages
        assert {:tcp, socket, "some data 2"} in messages
      end)

      other_process = spawn_link(fn -> process_mirror(parent, ref) end)

      assert :ok = TCP.controlling_process(socket, other_process)

      assert_receive {^ref, {:tcp, ^socket, "some data 1"}}
      assert_receive {^ref, {:tcp, ^socket, "some data 2"}}

      refute_received _message
    end

    test "changing the controlling process of a passive socket",
         %{socket: socket, server_socket: server_socket} do
      parent = self()
      ref = make_ref()

      :ok = :gen_tcp.send(server_socket, "some data")

      other_process =
        spawn_link(fn ->
          assert_receive message, 500
          send(parent, {ref, message})
        end)

      assert :ok = TCP.controlling_process(socket, other_process)
      assert {:ok, [active: false]} = TCP.getopts(socket, [:active])
      :ok = TCP.setopts(socket, active: :once)

      assert_receive {^ref, {:tcp, ^socket, "some data"}}, 500

      refute_received _message
    end

    test "changing the controlling process of a closed socket",
         %{socket: socket} do
      other_process = spawn_link(fn -> :ok = Process.sleep(:infinity) end)

      :ok = TCP.close(socket)

      assert {:error, _error} = TCP.controlling_process(socket, other_process)
    end
  end

  defp process_mirror(parent, ref) do
    receive do
      message ->
        send(parent, {ref, message})
        process_mirror(parent, ref)
    end
  end

  defp wait_until_passes(time_left, fun) when time_left <= 0 do
    fun.()
  end

  defp wait_until_passes(time_left, fun) do
    fun.()
  rescue
    _exception ->
      Process.sleep(10)
      wait_until_passes(time_left - 10, fun)
  end
end
