defmodule HPACK.HuffmanTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias HPACK.Huffman

  property "encoding and then decoding is circular" do
    check all binary <- binary() do
      encoded = Huffman.encode(binary)
      assert is_binary(encoded)
      assert Huffman.decode(encoded) == binary
    end
  end
end
