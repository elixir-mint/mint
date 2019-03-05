defmodule Mint.Core.Util do
  @moduledoc false

  def inet_opts(transport, socket) do
    with {:ok, opts} <- transport.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = calculate_buffer(opts),
         :ok <- transport.setopts(socket, buffer: buffer) do
      :ok
    end
  end

  def scheme_to_transport(:http), do: Mint.Core.Transport.TCP
  def scheme_to_transport(:https), do: Mint.Core.Transport.SSL
  def scheme_to_transport(module) when is_atom(module), do: module

  defp calculate_buffer(opts) do
    Keyword.fetch!(opts, :buffer)
    |> max(Keyword.fetch!(opts, :sndbuf))
    |> max(Keyword.fetch!(opts, :recbuf))
  end

  # Adds a header to the list of headers unless it's nil or it's already there.
  def put_new_header(headers, name, value)

  def put_new_header(headers, _name, nil) do
    headers
  end

  def put_new_header(headers, name, value) do
    if List.keymember?(headers, name, 0) do
      headers
    else
      [{name, value} | headers]
    end
  end
end
