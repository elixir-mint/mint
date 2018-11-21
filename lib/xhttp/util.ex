defmodule XHTTP.Util do
  def inet_opts(transport, socket) do
    with {:ok, opts} <- transport.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = calculate_buffer(opts),
         :ok <- transport.setopts(socket, buffer: buffer) do
      :ok
    end
  end

  def get_transport(opts, default) do
    transport = Keyword.get(opts, :transport, default)

    if transport not in [XHTTP.Transport.TCP, XHTTP.Transport.SSL] do
      raise ArgumentError,
            "the :transport option must be either TCP or SSL, got: #{inspect(transport)}"
    end

    transport
  end

  defp calculate_buffer(opts) do
    Keyword.fetch!(opts, :buffer)
    |> max(Keyword.fetch!(opts, :sndbuf))
    |> max(Keyword.fetch!(opts, :recbuf))
  end
end
