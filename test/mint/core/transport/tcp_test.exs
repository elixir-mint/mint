defmodule Mint.Core.Transport.TCPTest do
  use ExUnit.Case, async: true

  alias Mint.Core.Transport.TCP

  test "resolver blocks connections" do
    block_localhost = fn hostname, _ip6 ->
      if hostname == "localhost" do
        {:error, :blocked}
      else
        {:ok, hostname}
      end
    end

    assert {:error, %Mint.TransportError{reason: :blocked}} ==
             TCP.connect("localhost", 443, dns_resolver: block_localhost)
  end
end
