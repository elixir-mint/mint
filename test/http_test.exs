defmodule Mint.HTTPTest do
  use ExUnit.Case, async: true
  doctest Mint.HTTP, except: [recv_response: 3]
end
