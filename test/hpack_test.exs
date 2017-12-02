defmodule XHTTP2.HPACKTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  test "new/1" do
    assert %HPACK.Table{} = HPACK.new(100)
  end

  # https://http2.github.io/http2-spec/compression.html#rfc.section.C.2.1
  test "decode/2 with an example from the spec" do
    table = HPACK.new(1000)

    dump =
      <<0x40, 0x0A, 0x63, 0x75>> <>
        <<0x73, 0x74, 0x6F, 0x6D>> <>
        <<0x2D, 0x6B, 0x65, 0x79>> <>
        <<0x0D, 0x63, 0x75, 0x73>> <>
        <<0x74, 0x6F, 0x6D, 0x2D>> <> <<0x68, 0x65, 0x61, 0x64>> <> <<0x65, 0x72>>

    assert {:ok, headers, %HPACK.Table{}} = HPACK.decode(dump, table)
    assert headers == [{"custom-key", "custom-header"}]
  end

  test "manually doing operations on the table that property-based testing would be " <>
         "so much better at doing :( we need stateful testing folks" do
    enc_table = HPACK.new(1000)
    dec_table = HPACK.new(1000)

    {encoded, enc_table} = HPACK.encode([{:store, "a", "A"}], enc_table)
    assert {:ok, [{"a", "A"}], dec_table} = HPACK.decode(encoded, dec_table)
    assert dec_table.entries == [{"a", "A"}]

    {encoded, enc_table} = HPACK.encode([{:store_name, "a", "other"}], enc_table)
    assert {:ok, [{"a", "other"}], dec_table} = HPACK.decode(encoded, dec_table)
    assert dec_table.entries == [{"a", "A"}]

    {encoded, enc_table} = HPACK.encode([{:store_name, "b", "B"}], enc_table)
    assert {:ok, [{"b", "B"}], dec_table} = HPACK.decode(encoded, dec_table)
    assert dec_table.entries == [{"b", "B"}, {"a", "A"}]

    {encoded, _enc_table} = HPACK.encode([{:no_store, "c", "C"}], enc_table)
    assert {:ok, [{"c", "C"}], dec_table} = HPACK.decode(encoded, dec_table)
    assert dec_table.entries == [{"b", "B"}, {"a", "A"}]
  end

  property "encoding then decoding headers is circular" do
    table = HPACK.new(500)

    check all headers_to_encode <- list_of(header()),
              headers = for({_action, name, value} <- headers_to_encode, do: {name, value}) do
      assert {encoded, table} = HPACK.encode(headers_to_encode, table)
      assert {:ok, decoded, _table} = HPACK.decode(encoded, table)
      assert decoded == headers
    end
  end

  @static_table HPACK.Table.static_table()

  defp header() do
    action = member_of([:store, :store_name, :no_store, :never_store])

    header_from_static_table =
      bind(member_of(@static_table), fn
        {name, nil} -> {action, constant(name), binary()}
        {name, value} -> {action, constant(name), constant(value)}
      end)

    random_header = {action, binary(min_length: 1), binary()}

    frequency([
      {1, header_from_static_table},
      {2, random_header}
    ])
  end
end
