defmodule XHTTP.Transport.HTTP1 do
  alias XHTTP1.Conn

  @behaviour XHTTP.Transport

  @impl true
  def connect(_host, _port, _opts) do
    raise "use XHTTP1.Conn.connect/4 instead"
  end

  @impl true
  def upgrade(conn, new_transport, hostname, port, opts) do
    {transport, state} = Conn.get_transport(conn)

    with {:ok, conn} <- Conn.upgrade(transport, state, new_transport, hostname, port, opts) do
      {:ok, {__MODULE__, conn}}
    end
  end

  @impl true
  def negotiated_protocol(conn) do
    {transport, state} = Conn.get_transport(conn)
    transport.negotiated_protocol(state)
  end

  @impl true
  def send(conn, payload) do
    {transport, state} = Conn.get_transport(conn)

    with {:ok, state} <- transport.send(state, payload) do
      {:ok, Conn.put_transport(conn, {transport, state})}
    end
  end

  @impl true
  def close(conn) do
    {transport, state} = Conn.get_transport(conn)

    with {:ok, state} <- transport.close(state) do
      {:ok, Conn.put_transport(conn, {transport, state})}
    end
  end

  @impl true
  def recv(conn, bytes) do
    {transport, state} = Conn.get_transport(conn)

    with {:ok, data, state} <- transport.recv(state, bytes) do
      {:ok, data, Conn.put_transport(conn, {transport, state})}
    end
  end

  @impl true
  def setopts(conn, opts) do
    {transport, state} = Conn.get_transport(conn)
    transport.setopts(state, opts)
  end

  @impl true
  def getopts(conn, opts) do
    {transport, state} = Conn.get_transport(conn)
    transport.getopts(state, opts)
  end

  @impl true
  def socket(conn) do
    {transport, state} = Conn.get_transport(conn)
    transport.socket(state)
  end

  @impl true
  def actual_transport(conn) do
    {transport, state} = Conn.get_transport(conn)
    transport.actual_transport(state)
  end
end
