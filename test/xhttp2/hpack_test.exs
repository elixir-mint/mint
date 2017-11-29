defmodule XHTTP2.HPACKTest do
  use ExUnit.Case, async: true

  alias XHTTP2.HPACK

  test "new/1" do
    assert %HPACK.Table{} = HPACK.new(100)
  end

  test "decode/2 with an example from the spec" do
    table = HPACK.new(1000)

    dump =
      <<0x40, 0x0A, 0x63, 0x75>> <>
        <<0x73, 0x74, 0x6F, 0x6D>> <>
        <<0x2D, 0x6B, 0x65, 0x79>> <>
        <<0x0D, 0x63, 0x75, 0x73>> <>
        <<0x74, 0x6F, 0x6D, 0x2D>> <> <<0x68, 0x65, 0x61, 0x64>> <> <<0x65, 0x72>>

    assert {headers, %HPACK.Table{}} = HPACK.decode(dump, table)
    assert headers == [{"custom-key", "custom-header"}]
  end
end
