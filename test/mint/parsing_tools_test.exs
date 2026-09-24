defmodule Mint.ParsingToolsTest do
  use ExUnit.Case, async: true

  import Mint.ParsingTools

  test "only_digits?/1" do
    assert only_digits?("0")
    assert only_digits?("1234567890")

    refute only_digits?("")
    refute only_digits?("+1")
    refute only_digits?("-1")
    refute only_digits?("1a")
    refute only_digits?(" 1")
    refute only_digits?("1 ")
  end
end
