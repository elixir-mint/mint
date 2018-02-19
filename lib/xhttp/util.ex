defmodule XHTTP.Util do
  def inet_opts(transport, socket) do
    inet = transport_to_inet(transport)

    with {:ok, opts} <- inet.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = calculate_buffer(opts),
         :ok <- inet.setopts(socket, buffer: buffer) do
      :ok
    else
      error ->
        transport.close(socket)
        error
    end
  end

  def transport_to_inet(:gen_tcp), do: :inet
  def transport_to_inet(:ssl), do: :ssl

  def get_transport(opts, default) do
    transport = Keyword.get(opts, :transport, default)

    if transport not in [:gen_tcp, :ssl] do
      raise ArgumentError,
            "the :transport option must be either :gen_tcp or :ssl, got: #{inspect(transport)}"
    end

    transport
  end

  defp calculate_buffer(opts) do
    Keyword.fetch!(opts, :buffer)
    |> max(Keyword.fetch!(opts, :sndbuf))
    |> max(Keyword.fetch!(opts, :recbuf))
  end
end
