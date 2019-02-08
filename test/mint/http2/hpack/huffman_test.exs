defmodule HPACK.HuffmanTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Mint.HTTP2.HPACK.Huffman

  property "encoding and then decoding is circular" do
    check all binary <- binary() do
      encoded = Huffman.encode(binary)
      assert is_binary(encoded)
      assert Huffman.decode(encoded) == binary
    end
  end

  property "encoding and decoding match joedevivo/hpack's :huffman" do
    check all binary <- string(:ascii) do
      encoded = Huffman.encode(binary)
      assert encoded == :huffman.encode(binary)
      assert Huffman.decode(encoded) == :huffman.decode(encoded)
    end
  end
end
