defmodule Mint.HTTP2.HPACK do
  @moduledoc false

  # Support for the HPACK header compression algorithm.
  #
  # This module provides support for the HPACK header compression algorithm used mainly in HTTP/2.
  # The HPACK algorithm requires an encoding context on the encoder side and a decoding context on
  # the decoder side. These contexts are semantically different but structurally the same and they
  # can both be created through `new/1`.

  alias Mint.HTTP2.HPACK.{Table, Types}

  @type header_name() :: binary()
  @type header_value() :: binary()

  @valid_header_actions [:store, :store_name, :no_store, :never_store]

  @doc """
  Create a new context.

  `max_table_size` is the maximum table size (in bytes) for the newly created context.
  """
  @spec new(non_neg_integer()) :: Table.t()
  def new(max_table_size) when is_integer(max_table_size) and max_table_size >= 0 do
    Table.new(max_table_size)
  end

  @doc """
  Resizes the given table to the given size.
  """
  @spec resize(Table.t(), non_neg_integer()) :: Table.t()
  defdelegate resize(table, new_size), to: Table

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
    :throw, {:mint, error} -> {:error, error}
  end

  defp decode_headers(<<>>, table, acc) do
    {:ok, Enum.reverse(acc), table}
  end

  # Indexed header field
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.1
  defp decode_headers(<<0b1::1, rest::bitstring>>, table, acc) do
    {index, rest} = decode_integer(rest, 7)
    decode_headers(rest, table, [lookup_by_index!(table, index) | acc])
  end

  # Literal header field with incremental indexing
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.2.1
  defp decode_headers(<<0b01::2, rest::bitstring>>, table, acc) do
    {name, value, rest} =
      case rest do
        # The header name is a string.
        <<0::6, rest::binary>> ->
          {name, rest} = decode_binary(rest)
          {value, rest} = decode_binary(rest)
          {name, value, rest}

        # The header name is an index to be looked up in the table.
        _other ->
          {index, rest} = decode_integer(rest, 6)
          {value, rest} = decode_binary(rest)
          {name, _value} = lookup_by_index!(table, index)
          {name, value, rest}
      end

    decode_headers(rest, Table.add(table, name, value), [{name, value} | acc])
  end

  # Literal header field without indexing
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.2.2
  defp decode_headers(<<0b0000::4, rest::bitstring>>, table, acc) do
    {name, value, rest} =
      case rest do
        <<0::4, rest::binary>> ->
          {name, rest} = decode_binary(rest)
          {value, rest} = decode_binary(rest)
          {name, value, rest}

        _other ->
          {index, rest} = decode_integer(rest, 4)
          {value, rest} = decode_binary(rest)
          {name, _value} = lookup_by_index!(table, index)
          {name, value, rest}
      end

    decode_headers(rest, table, [{name, value} | acc])
  end

  # Literal header field never indexed
  # http://httpwg.org/specs/rfc7541.html#rfc.section.6.2.3
  defp decode_headers(<<0b0001::4, rest::bitstring>>, table, acc) do
    {name, value, rest} =
      case rest do
        <<0::4, rest::binary>> ->
          {name, rest} = decode_binary(rest)
          {value, rest} = decode_binary(rest)
          {name, value, rest}

        _other ->
          {index, rest} = decode_integer(rest, 4)
          {value, rest} = decode_binary(rest)
          {name, _value} = lookup_by_index!(table, index)
          {name, value, rest}
      end

    # TODO: enforce the "never indexed" part somehow.
    decode_headers(rest, table, [{name, value} | acc])
  end

  # Dynamic table size update
  defp decode_headers(<<0b001::3, rest::bitstring>>, table, acc) do
    {new_size, rest} = decode_integer(rest, 5)
    decode_headers(rest, Table.resize(table, new_size), acc)
  end

  defp decode_headers(_other, _table, _acc) do
    throw({:mint, :protocol_error})
  end

  defp lookup_by_index!(table, index) do
    case Table.lookup_by_index(table, index) do
      {:ok, header} -> header
      :error -> throw({:mint, {:index_not_found, index}})
    end
  end

  defp decode_integer(bitstring, prefix) do
    case Types.decode_integer(bitstring, prefix) do
      {:ok, int, rest} -> {int, rest}
      :error -> throw({:mint, :bad_integer_encoding})
    end
  end

  defp decode_binary(binary) do
    case Types.decode_binary(binary) do
      {:ok, binary, rest} -> {binary, rest}
      :error -> throw({:mint, :bad_binary_encoding})
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
  @spec encode([header], Table.t()) :: {iodata(), Table.t()}
        when header: {action, header_name(), header_value()},
             action: :store | :store_name | :no_store | :never_store
  def encode(headers, %Table{} = table) when is_list(headers) do
    encode_headers(headers, table, _acc = [])
  end

  defp encode_headers([], table, acc) do
    {acc, table}
  end

  defp encode_headers([{action, name, value} | rest], table, acc)
       when action in @valid_header_actions and is_binary(name) and is_binary(value) do
    {encoded, table} =
      case Table.lookup_by_header(table, name, value) do
        {:full, index} ->
          {encode_indexed_header(index), table}

        {:name, index} when action == :store ->
          {encode_literal_header_with_indexing(index, value), Table.add(table, name, value)}

        {:name, index} when action in [:store_name, :no_store] ->
          {encode_literal_header_without_indexing(index, value), table}

        {:name, index} when action == :never_store ->
          {encode_literal_header_never_indexed(index, value), table}

        :not_found when action in [:store, :store_name] ->
          {encode_literal_header_with_indexing(name, value), Table.add(table, name, value)}

        :not_found when action == :no_store ->
          {encode_literal_header_without_indexing(name, value), table}

        :not_found when action == :never_store ->
          {encode_literal_header_never_indexed(name, value), table}
      end

    encode_headers(rest, table, [acc, encoded])
  end

  defp encode_indexed_header(index) do
    <<1::1, Types.encode_integer(index, 7)::bitstring>>
  end

  defp encode_literal_header_with_indexing(index, value) when is_integer(index) do
    [<<1::2, Types.encode_integer(index, 6)::bitstring>>, Types.encode_binary(value, false)]
  end

  defp encode_literal_header_with_indexing(name, value) when is_binary(name) do
    [<<1::2, 0::6>>, Types.encode_binary(name, false), Types.encode_binary(value, false)]
  end

  defp encode_literal_header_without_indexing(index, value) when is_integer(index) do
    [<<0::4, Types.encode_integer(index, 4)::bitstring>>, Types.encode_binary(value, false)]
  end

  defp encode_literal_header_without_indexing(name, value) when is_binary(name) do
    [<<0::4, 0::4>>, Types.encode_binary(name, false), Types.encode_binary(value, false)]
  end

  defp encode_literal_header_never_indexed(index, value) when is_integer(index) do
    [<<1::4, Types.encode_integer(index, 4)::bitstring>>, Types.encode_binary(value, false)]
  end

  defp encode_literal_header_never_indexed(name, value) when is_binary(name) do
    [<<1::4, 0::4>>, Types.encode_binary(name, false), Types.encode_binary(value, false)]
  end
end
