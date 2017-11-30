defmodule HPACK.HuffmanTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias HPACK.Huffman

  property "encoding and then decoding is circular" do
    check all binary <- binary() do
      assert binary |> Huffman.encode() |> Huffman.decode() == binary
    end
  end
end
