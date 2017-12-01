defmodule HPACK.Types do
  @moduledoc false

  use Bitwise

  alias HPACK.Huffman

  # This is used as a macro and not an inlined function because we want to be able to use it in
  # guards.
  defmacrop power_of_two(n) do
    quote do: 1 <<< unquote(n)
  end

  @spec encode_integer(non_neg_integer(), 1..8) :: bitstring()
  def encode_integer(integer, prefix)

  def encode_integer(integer, prefix) when integer < power_of_two(prefix) - 1 do
    <<integer::size(prefix)>>
  end

  def encode_integer(integer, prefix) do
    initial = power_of_two(prefix) - 1
    remaining = integer - initial
    <<initial::size(prefix), encode_remaining_integer(remaining)::binary>>
  end

  defp encode_remaining_integer(remaining) when remaining >= 128 do
    first = rem(remaining, 128) + 128
    <<first::8, encode_remaining_integer(div(remaining, 128))::binary>>
  end

  defp encode_remaining_integer(remaining) do
    <<remaining::8>>
  end

  @spec encode_binary(binary(), boolean()) :: iodata()
  def encode_binary(binary, huffman?) do
    binary = if huffman?, do: Huffman.encode(binary), else: binary
    huffman_bit = if huffman?, do: 1, else: 0
    binary_size = encode_integer(byte_size(binary), 7)
    [<<huffman_bit::1, binary_size::bitstring>>, binary]
  end

  @spec decode_integer(bitstring, 1..8) :: {non_neg_integer(), binary()}
  def decode_integer(bitstring, prefix) do
    <<value::size(prefix), rest::binary>> = bitstring

    if value < power_of_two(prefix) - 1 do
      {value, rest}
    else
      decode_remaining_integer(rest, value, 0)
    end
  end

  defp decode_remaining_integer(<<0::1, value::7, rest::binary>>, int, m) do
    {int + (value <<< m), rest}
  end

  defp decode_remaining_integer(<<1::1, value::7, rest::binary>>, int, m) do
    decode_remaining_integer(rest, int + (value <<< m), m + 7)
  end

  @spec decode_binary(binary) :: {binary(), binary()}
  def decode_binary(binary) do
    <<huffman_bit::1, rest::bitstring>> = binary
    {length, rest} = decode_integer(rest, 7)
    <<contents::binary-size(length), rest::binary>> = rest

    contents =
      case huffman_bit do
        0 -> contents
        1 -> Huffman.decode(contents)
      end

    {contents, rest}
  end
end
