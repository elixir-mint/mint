defmodule HPACK do
  @moduledoc """
  Support for the HPACK header compression algorithm.

  This module provides support for the HPACK header compression algorithm used mainly in HTTP/2.
  The HPACK algorithm requires an encoding context on the encoder side and a decoding context on
  the decoder side. These contexts are semantically different but structurally the same and they
  can both be created through `new/1`.
  """

  alias HPACK.{Table, Types}

  @doc """
  Create a new context.

  `max_table_size` is the maximum table size (in bytes) for the newly created context.
  """
  @spec new(non_neg_integer()) :: Table.t()
  def new(max_table_size) when is_integer(max_table_size) and max_table_size >= 0 do
    Table.new(max_table_size)
  end

  ## Decoding

  @doc """
  Decodes a header block fragment (HBF) through a given context.

  If decoding is successful, this function returns a `{:ok, headers, updated_context}` tuple where
  `headers` is a list of decoded headers, and `updated_context` is the updated context. If there's
  an error in decoding, this function returns `{:error, reason}`.

  ## Examples

      context = HPACK.new(1000)
      hbf = get_hbf_from_somewhere()
      HPACK.decode(hbf, context)
      #=> {:ok, [{":method", "GET"}], updated_context}

  """
  @spec decode(binary(), Table.t()) :: {:ok, [{binary(), binary()}], Table.t()} | {:error, term()}
  def decode(block, %Table{} = table) when is_binary(block) do
    decode_headers(block, table, _acc = [])
  catch
    :throw, error -> {:error, error}
  end

  defp decode_headers(<<>>, table, acc) do
    {:ok, Enum.reverse(acc), table}
  end

  # Indexed header field
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.1
  defp decode_headers(<<0b1::1, rest::bitstring>>, table, acc) do
    {index, rest} = Types.decode_integer(rest, 7)
    decode_headers(rest, table, [lookup_by_index!(table, index) | acc])
  end

  # Literal header field with incremental indexing
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.2.1
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
          {name, _value} = lookup_by_index!(table, index)
          {{name, value}, rest}
      end

    decode_headers(rest, Table.add(table, header), [header | acc])
  end

  # Literal header field without indexing
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.2.2
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
          {name, _value} = lookup_by_index!(table, index)
          {{name, value}, rest}
      end

    decode_headers(rest, table, [header | acc])
  end

  # Literal header field never indexed
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.2.3
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
          {name, _value} = lookup_by_index!(table, index)
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

  defp lookup_by_index!(table, index) do
    case Table.lookup_by_index(table, index) do
      {:ok, header} -> header
      :error -> throw({:index_not_found, index})
    end
  end

  ## Encoding

  @doc """
  Encodes a list of headers through the given context.

  Returns a two-element tuple where the first element is a binary representing the encoded headers
  and the second element is an updated context.

  ## Examples

      headers = [{":authority", "https://example.com"}]
      context = HPACK.new(1000)
      HPACK.encode(headers, context)
      #=> {<<...>>, updated_context}

  """
  @spec encode([{binary(), binary()}], Table.t()) :: {binary(), Table.t()}
  def encode(headers, %Table{} = table) when is_list(headers) do
    encode_headers(headers, table, _acc = [])
  end

  defp encode_headers([], table, acc) do
    {IO.iodata_to_binary(acc), table}
  end

  defp encode_headers([{name, value} | rest], table, acc)
       when is_binary(name) and is_binary(value) do
    encode_headers(rest, table, [acc, encode_header(name, value, table)])
  end

  defp encode_header(name, value, table) do
    case Table.lookup_by_header(table, {name, value}) do
      {:full, index} -> encode_indexed_header(index)
      {:name, index} -> encode_literal_header_without_indexing(index, value)
      :not_found -> encode_literal_header_without_indexing(name, value)
    end
  end

  defp encode_indexed_header(index) do
    <<1::1, Types.encode_integer(index, 7)::bitstring>>
  end

  defp encode_literal_header_without_indexing(index, value) when is_integer(index) do
    [<<0::4, Types.encode_integer(index, 4)::bitstring>>, Types.encode_binary(value, false)]
  end

  defp encode_literal_header_without_indexing(name, value) when is_binary(name) do
    [
      <<0::4, 0::4>>,
      Types.encode_binary(name, false),
      Types.encode_binary(value, false)
    ]
  end
end
