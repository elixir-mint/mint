defmodule HPACK.Huffman do
  @moduledoc false

  use Bitwise

  # This file is downloaded from the spec directly.
  # http://httpwg.org/specs/rfc7541.html#huffman.code
  table_file = Path.absname("huffman_table", __DIR__)
  @external_resource table_file

  @eos 256

  defmacrop take_significant_bits(value, bit_count, bits_to_take) do
    quote do
      unquote(value) >>> (unquote(bit_count) - unquote(bits_to_take))
    end
  end

  def encode(binary) do
    encode(binary, _acc = <<>>)
  end

  for line <- File.stream!(table_file) do
    [byte_value, bits, _hex, bit_count] =
      line
      |> case do
           <<?', _, ?', ?\s, rest::binary>> -> rest
           "EOS " <> rest -> rest
           _other -> line
         end
      |> String.replace(["|", "(", ")", "[", "]"], "")
      |> String.split()

    byte_value = String.to_integer(byte_value)
    bits = String.to_integer(bits, 2)
    bit_count = String.to_integer(bit_count)

    if byte_value == @eos do
      def encode(<<>>, acc) do
        overflowing_bits = rem(bit_size(acc), 8)

        if overflowing_bits == 0 do
          acc
        else
          bits_to_add = 8 - overflowing_bits

          value_of_bits_to_add =
            take_significant_bits(unquote(bits), unquote(bit_count), bits_to_add)

          res = <<acc::bitstring, value_of_bits_to_add::size(bits_to_add)>>

          if not is_binary(res) do
            raise inspect(res)
          end

          res
        end
      end

      def decode(<<>>) do
        <<>>
      end

      # Use binary syntax for single match context optimization.
      def decode(<<padding::bitstring>>) when bit_size(padding) in 1..7 do
        padding_size = bit_size(padding)
        <<padding::size(padding_size)>> = padding

        if take_significant_bits(unquote(bits), unquote(bit_count), padding_size) == padding do
          <<>>
        else
          raise "decoding error"
        end
      end
    else
      def encode(<<unquote(byte_value), rest::binary>>, acc) do
        encode(rest, <<acc::bitstring, unquote(bits)::size(unquote(bit_count))>>)
      end

      def decode(<<unquote(bits)::size(unquote(bit_count)), rest::bitstring>>) do
        <<unquote(byte_value), decode(rest)::binary>>
      end
    end
  end
end
