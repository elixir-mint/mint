defmodule HPACK.TableTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Mint.HTTP2.HPACK.Table

  test "new/1" do
    assert %Table{} = Table.new(100)
  end

  test "adding headers and fetching them by value" do
    table = Table.new(10_000)

    # These are in the static table.
    assert {:full, _} = Table.lookup_by_header(table, ":status", "200")
    assert {:name, _} = Table.lookup_by_header(table, ":authority", nil)
    assert {:name, _} = Table.lookup_by_header(table, ":authority", "https://example.com")

    assert Table.lookup_by_header(table, "my-nonexistent-header", nil) == :not_found
    assert Table.lookup_by_header(table, "my-nonexistent-header", "my-value") == :not_found

    table = Table.add(table, ":my-header", "my-value")

    assert {:full, _} = Table.lookup_by_header(table, ":my-header", "my-value")
    assert {:name, _} = Table.lookup_by_header(table, ":my-header", "other-value")
    assert {:name, _} = Table.lookup_by_header(table, ":my-header", nil)
  end

  test "resizing" do
    dynamic_table_start = length(Table.__static_table__()) + 1

    # This fits two headers that have name and value of 4 bytes (4 + 4 + 32, twice).
    table = Table.new(80)

    table = Table.add(table, "aaaa", "AAAA")
    table = Table.add(table, "bbbb", "BBBB")
    assert Table.lookup_by_index(table, dynamic_table_start + 1) == {:ok, {"aaaa", "AAAA"}}
    assert Table.lookup_by_index(table, dynamic_table_start) == {:ok, {"bbbb", "BBBB"}}

    # We need to remove one now.
    table = Table.add(table, "cccc", "CCCC")
    assert Table.lookup_by_index(table, dynamic_table_start) == {:ok, {"cccc", "CCCC"}}
    assert Table.lookup_by_index(table, dynamic_table_start + 1) == {:ok, {"bbbb", "BBBB"}}
    assert Table.lookup_by_index(table, dynamic_table_start + 2) == :error

    # If we resize so that no headers fit, all headers are removed.
    table = Table.resize(table, 30)
    assert Table.lookup_by_index(table, dynamic_table_start) == :error
  end

  describe "looking headers up by index" do
    test "with an index out of bounds" do
      assert Table.lookup_by_index(Table.new(100), 1000) == :error
    end

    test "with an index in the static table" do
      assert Table.lookup_by_index(Table.new(100), 1) == {:ok, {":authority", nil}}
    end

    test "with an index in the dynamic table" do
      table = Table.new(100)
      table = Table.add(table, "my-header", "my-value")

      assert Table.lookup_by_index(table, length(Table.__static_table__()) + 1) ==
               {:ok, {"my-header", "my-value"}}
    end
  end

  property "adding a header and then looking it up always returns the index of that header" do
    check all {name, value} <- {string(0..127, min_length: 1), binary()} do
      assert %Table{} = table = Table.new(10_000)
      assert %Table{} = table = Table.add(table, name, value)
      assert {:full, 62} = Table.lookup_by_header(table, name, value)
    end
  end
end
