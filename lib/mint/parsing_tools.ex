defmodule Mint.ParsingTools do
  @moduledoc false

  @spec only_digits?(binary()) :: boolean()
  def only_digits?(<<char>>) when char in ?0..?9, do: true
  def only_digits?(<<char, rest::binary>>) when char in ?0..?9, do: only_digits?(rest)
  def only_digits?(_other), do: false
end
