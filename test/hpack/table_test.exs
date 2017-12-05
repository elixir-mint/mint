defmodule HPACK.TableTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias HPACK.Table

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

      assert Table.lookup_by_index(table, length(Table.static_table()) + 1) ==
               {:ok, {"my-header", "my-value"}}
    end
  end

  property "adding a header and then looking it up always returns the index of that header" do
    check all {name, value} <- {binary(min_length: 1), binary()} do
      assert %Table{} = table = Table.new(10_000)
      assert %Table{} = table = Table.add(table, name, value)
      assert {:full, 62} = Table.lookup_by_header(table, name, value)
    end
  end
end
