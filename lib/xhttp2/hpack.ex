defmodule XHTTP2.HPACK do
  alias XHTTP2.HPACK.{Table, Types}

  @spec new(non_neg_integer()) :: Table.t()
  def new(max_table_size) when is_integer(max_table_size) and max_table_size >= 0 do
    Table.new(max_table_size)
  end

  @spec decode(binary(), Table.t()) :: {[{binary(), binary()}], Table.t()}
  def decode(block, %Table{} = table) when is_binary(block) do
    decode_headers(block, table, _acc = [])
  end

  defp decode_headers(<<>>, table, acc) do
    {Enum.reverse(acc), table}
  end

  # Indexed header field
  defp decode_headers(<<0b1::1, rest::bitstring>>, table, acc) do
    {index, rest} = Types.decode_integer(rest, 7)
    {:ok, {_name, _value} = header} = Table.fetch(table, index)
    decode_headers(rest, table, [header | acc])
  end

  # Literal header field with incremental indexing
  defp decode_headers(<<0b01::2, rest::bitstring>>, table, acc) do
    {header, rest} =
      case rest do
        # The header name is a string.
        <<0::6, rest::binary>> ->
          {name, rest} = Types.decode_binary(rest)
          {value, rest} = Types.decode_binary(rest)
          {{name, value}, rest}

        # The header name is an index to be looked up in the table.
        _other ->
          {index, rest} = Types.decode_integer(rest, 6)
          {value, rest} = Types.decode_binary(rest)
          {:ok, {name, _value}} = Table.fetch(table, index)
          {{name, value}, rest}
      end

    decode_headers(rest, Table.add(table, header), [header | acc])
  end

  # Literal header field without indexing
  defp decode_headers(<<0b0000::4, rest::bitstring>>, table, acc) do
    {header, rest} =
      case rest do
        <<0::4, rest::binary>> ->
          {name, rest} = Types.decode_binary(rest)
          {value, rest} = Types.decode_binary(rest)
          {{name, value}, rest}

        _other ->
          {index, rest} = Types.decode_integer(rest, 4)
          {value, rest} = Types.decode_binary(rest)
          {:ok, {name, _value}} = Table.fetch(table, index)
          {{name, value}, rest}
      end

    decode_headers(rest, table, [header | acc])
  end

  # Literal header field never indexed
  defp decode_headers(<<0b0001::4, rest::bitstring>>, table, acc) do
    {header, rest} =
      case rest do
        <<0::4, rest::binary>> ->
          {name, rest} = Types.decode_binary(rest)
          {value, rest} = Types.decode_binary(rest)
          {{name, value}, rest}

        _other ->
          {index, rest} = Types.decode_integer(rest, 4)
          {value, rest} = Types.decode_binary(rest)
          {:ok, {name, _value}} = Table.fetch(table, index)
          {{name, value}, rest}
      end

    # TODO: don't let others put this in the table.
    decode_headers(rest, table, [header | acc])
  end

  # Dynamic table size update
  defp decode_headers(<<0b001::3, rest::bitstring>>, table, acc) do
    {new_size, rest} = Types.decode_integer(rest, 5)
    decode_headers(rest, Table.shrink(table, new_size), acc)
  end

  @spec encode([{binary(), binary()}], Table.t()) :: {binary(), Table.t()}
  def encode(headers, %Table{} = table) when is_list(headers) do
    encode_headers(headers, table, _acc = <<>>)
  end

  defp encode_headers([], table, acc) do
    {acc, table}
  end

  defp encode_headers([{name, value} | rest], table, acc)
       when is_binary(name) and is_binary(value) do
    {encoded, table} = encode_header(name, value, table)
    encode_headers(rest, table, <<acc::binary, encoded::binary>>)
  end

  for {index, {name, value}} <- Table.static_table() do
    defp encode_header(unquote(name), unquote(value), table) do
      {<<0b1::1, Types.encode_integer(unquote(index), 7)::bitstring>>, table}
    end

    defp encode_header(unquote(name), value, table) do
      encoded = <<
        0b0000::4,
        Types.encode_integer(unquote(index), 4)::bitstring,
        Types.encode_binary(value, false)::binary
      >>

      {encoded, table}
    end
  end

  defp encode_header(name, value, table) do
    encoded = <<
      0b0000::4,
      0::4,
      Types.encode_binary(name, false)::binary,
      Types.encode_binary(value, false)::binary
    >>

    {encoded, table}
  end
end
