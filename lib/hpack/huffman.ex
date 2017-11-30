defmodule HPACK.Huffman do
  @moduledoc false

  # This file is downloaded from the spec directly.
  # http://httpwg.org/specs/rfc7541.html#huffman.code
  table_file = Path.absname("huffman_table", __DIR__)
  @external_resource table_file

  @eos 256

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
      def encode(<<>>), do: <<unquote(bits)::size(unquote(bit_count))>>
      def decode(<<unquote(bits)::size(unquote(bit_count))>>), do: <<>>
    else
      def encode(<<unquote(byte_value), rest::binary>>) do
        <<unquote(bits)::size(unquote(bit_count)), encode(rest)::bitstring>>
      end

      def decode(<<unquote(bits)::size(unquote(bit_count)), rest::bitstring>>) do
        <<unquote(byte_value), decode(rest)::binary>>
      end
    end
  end
end
