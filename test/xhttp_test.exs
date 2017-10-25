defmodule XHTTPTest do
  use ExUnit.Case
  doctest XHTTP

  test "greets the world" do
    assert XHTTP.hello() == :world
  end
end
