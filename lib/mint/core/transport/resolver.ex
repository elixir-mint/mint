defmodule Mint.Core.Transport.Resolver do
  def resolve(hostname, ipv6, opts) do
    case Keyword.get(opts, :dns_resolver, :default) do
      :default ->
        {:ok, String.to_charlist(hostname)}

      fun ->
        convert_binary_to_charlist(fun.(hostname, ipv6))
    end
  end

  defp convert_binary_to_charlist({:ok, result}) when is_binary(result) do
    {:ok, String.to_charlist(result)}
  end

  defp convert_binary_to_charlist(v) do
    v
  end
end
