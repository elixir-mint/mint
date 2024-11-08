defmodule Mint.HTTPTest do
  use ExUnit.Case, async: true
  doctest Mint.HTTP, except: [request_and_response: 6]
end
