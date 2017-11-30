defmodule HPACK.TypesTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import HPACK.Types

  test "encode_integer/2 with examples from the spec" do
    assert encode_integer(10, _prefix = 5) == <<0b01010::5>>
    assert encode_integer(1337, 5) == <<0b11111_10011010_00001010::21>>
    assert encode_integer(42, 8) == <<0b00101010::8>>
  end

  test "decode_integer/2 with examples from the spec" do
    assert decode_integer(<<0b01010::5, "foo">>, _prefix = 5) == {10, "foo"}
    assert decode_integer(<<0b11111_10011010_00001010::21, "foo">>, 5) == {1337, "foo"}
    assert decode_integer(<<0b00101010::8, "foo">>, 8) == {42, "foo"}
  end

  property "encoding and then decoding integers is circular" do
    check all value <- map(integer(), &abs/1),
              prefix <- integer(1..8),
              cruft <- binary() do
      encoded = encode_integer(value, prefix)
      assert decode_integer(<<encoded::bitstring, cruft::binary>>, prefix) == {value, cruft}
    end
  end

  property "encoding and then decoding strings is circular" do
    check all string <- binary(),
              cruft <- binary(),
              huffman? <- boolean() do
      encoded = encode_binary(string, huffman?)
      assert decode_binary(<<encoded::binary, cruft::binary>>) == {string, cruft}
    end
  end
end
