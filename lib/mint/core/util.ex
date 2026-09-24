defmodule Mint.Core.Util do
  @moduledoc false

  alias Mint.Types

  @spec hostname(keyword(), Types.address()) :: String.t()
  def hostname(opts, address) when is_list(opts) do
    case Keyword.fetch(opts, :hostname) do
      {:ok, hostname} ->
        hostname

      :error when is_binary(address) ->
        address

      :error ->
        raise ArgumentError, "the :hostname option is required when address is not a binary"
    end
  end

  # RFC 9112 3.2.2 and RFC 3986 3.2.2: an IPv6 literal in the Host header or the
  # :authority pseudo-header must be enclosed in square brackets. The RFC 3986
  # IP-literal has no zone ID ("fe80::1%eth0"), so it's left out.
  @spec uri_host(String.t()) :: String.t()
  def uri_host(hostname) do
    [address | _zone_id] = String.split(hostname, "%", parts: 2)

    case :inet.parse_ipv6strict_address(String.to_charlist(address)) do
      {:ok, _address} -> "[" <> address <> "]"
      {:error, :einval} -> hostname
    end
  end

  @spec inet_opts(:gen_tcp | :ssl, :gen_tcp.socket() | :ssl.sslsocket()) :: :ok | {:error, term()}
  def inet_opts(transport, socket) do
    with {:ok, opts} <- transport.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = calculate_buffer(opts),
         :ok <- transport.setopts(socket, buffer: buffer) do
      :ok
    end
  end

  @spec scheme_to_transport(atom()) :: module()
  def scheme_to_transport(:http), do: Mint.Core.Transport.TCP
  def scheme_to_transport(:https), do: Mint.Core.Transport.SSL
  def scheme_to_transport(module) when is_atom(module), do: module

  defp calculate_buffer(opts) do
    Keyword.fetch!(opts, :buffer)
    |> max(Keyword.fetch!(opts, :sndbuf))
    |> max(Keyword.fetch!(opts, :recbuf))
  end

  # Adds a header to the list of headers unless it's nil or it's already there.
  @spec put_new_header(Types.headers(), String.t(), String.t() | nil) :: Types.headers()
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

  @spec put_new_header_lazy(Types.headers(), String.t(), (-> String.t())) :: Types.headers()
  def put_new_header_lazy(headers, name, fun) do
    if List.keymember?(headers, name, 0) do
      headers
    else
      [{name, fun.()} | headers]
    end
  end

  # If the buffer is empty, reusing the incoming data saves
  # a potentially large allocation of memory.
  # This should be fixed in a subsequent OTP release.
  @spec maybe_concat(binary(), binary()) :: binary()
  def maybe_concat(<<>>, data), do: data
  def maybe_concat(buffer, data) when is_binary(buffer), do: buffer <> data
end
