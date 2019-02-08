defmodule HPACK.TypesTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Mint.HTTP2.HPACK.Types

  describe "examples from the spec" do
    test "for encode_integer/2" do
      assert encode_integer(10, _prefix = 5) == <<0b01010::5>>
      assert encode_integer(1337, 5) == <<0b11111_10011010_00001010::21>>
      assert encode_integer(42, 8) == <<0b00101010::8>>
    end

    test "for decode_integer/2" do
      assert decode_integer(<<0b01010::5, "foo">>, _prefix = 5) == {:ok, 10, "foo"}
      assert decode_integer(<<0b11111_10011010_00001010::21, "foo">>, 5) == {:ok, 1337, "foo"}
      assert decode_integer(<<0b00101010::8, "foo">>, 8) == {:ok, 42, "foo"}
    end
  end

  test "decode_integer/2 with bad data" do
    assert decode_integer("bad integer", 5) == :error
  end

  property "encoding and then decoding integers is circular" do
    check all value <- map(integer(), &abs/1),
              prefix <- integer(1..8),
              cruft <- binary() do
      encoded = encode_integer(value, prefix)
      assert decode_integer(<<encoded::bitstring, cruft::binary>>, prefix) == {:ok, value, cruft}
    end
  end

  property "encoding and then decoding strings is circular" do
    check all string <- binary(),
              cruft <- binary(),
              huffman? <- boolean() do
      encoded = encode_binary(string, huffman?)
      assert decode_binary(IO.iodata_to_binary([encoded, cruft])) == {:ok, string, cruft}
    end
  end
end
