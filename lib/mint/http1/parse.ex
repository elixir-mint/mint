defmodule Mint.HTTP1.Parse do
  @moduledoc false

  # Bound the parse work and keep the chunk size within an unsigned 64-bit value.
  @max_chunk_size_digits 16

  defmacro is_digit(char), do: quote(do: unquote(char) in ?0..?9)
  defmacro is_alpha(char), do: quote(do: unquote(char) in ?a..?z or unquote(char) in ?A..?Z)
  defmacro is_whitespace(char), do: quote(do: unquote(char) in ~c"\s\t")
  defmacro is_comma(char), do: quote(do: unquote(char) == ?,)
  defmacro is_vchar(char), do: quote(do: unquote(char) in 33..126)

  defmacro is_hex_digit(char) do
    quote do
      is_digit(unquote(char)) or unquote(char) in ?a..?f or unquote(char) in ?A..?F
    end
  end

  defmacro is_tchar(char) do
    quote do
      is_digit(unquote(char)) or is_alpha(unquote(char)) or unquote(char) in ~c"!#$%&'*+-.^_`|~"
    end
  end

  def chunk_size(<<char, rest::binary>>) when is_hex_digit(char) do
    parse_hex_prefix(rest, hex_digit_value(char), 1)
  end

  def chunk_size(_other), do: :error

  defp parse_hex_prefix(<<char, _rest::binary>>, _acc, @max_chunk_size_digits)
       when is_hex_digit(char),
       do: :error

  defp parse_hex_prefix(<<char, rest::binary>>, acc, digit_count) when is_hex_digit(char) do
    parse_hex_prefix(rest, acc * 16 + hex_digit_value(char), digit_count + 1)
  end

  defp parse_hex_prefix(<<>>, _acc, _digit_count), do: :more
  defp parse_hex_prefix(rest, acc, _digit_count), do: {:ok, acc, rest}

  defp hex_digit_value(char) when is_digit(char), do: char - ?0
  defp hex_digit_value(char) when char in ?a..?f, do: char - ?a + 10
  defp hex_digit_value(char) when char in ?A..?F, do: char - ?A + 10

  def chunk_extensions(data), do: chunk_extensions(data, :start)

  defp chunk_extensions(<<>>, _state), do: :more

  defp chunk_extensions("\r", state) when state in [:start, :name, :token], do: :more

  defp chunk_extensions(<<"\r\n", rest::binary>>, state)
       when state in [:start, :name, :token],
       do: {:ok, rest}

  defp chunk_extensions(<<?;, rest::binary>>, state)
       when state in [:start, :separator, :name, :name_bws, :token],
       do: chunk_extensions(rest, :name_start)

  defp chunk_extensions(<<char, rest::binary>>, state)
       when is_whitespace(char) and state in [:start, :separator, :token],
       do: chunk_extensions(rest, :separator)

  defp chunk_extensions(<<char, rest::binary>>, state)
       when is_whitespace(char) and state in [:name, :name_bws],
       do: chunk_extensions(rest, :name_bws)

  defp chunk_extensions(<<char, rest::binary>>, state)
       when is_whitespace(char) and state in [:name_start, :value_start],
       do: chunk_extensions(rest, state)

  defp chunk_extensions(<<?=, rest::binary>>, state) when state in [:name, :name_bws],
    do: chunk_extensions(rest, :value_start)

  defp chunk_extensions(<<char, rest::binary>>, state)
       when is_tchar(char) and state in [:name_start, :name],
       do: chunk_extensions(rest, :name)

  defp chunk_extensions(<<char, rest::binary>>, state)
       when is_tchar(char) and state in [:value_start, :token],
       do: chunk_extensions(rest, :token)

  defp chunk_extensions(<<?", rest::binary>>, :value_start),
    do: chunk_extensions(rest, :quoted)

  defp chunk_extensions(<<?", rest::binary>>, :quoted),
    do: chunk_extensions(rest, :start)

  defp chunk_extensions(<<?\\, rest::binary>>, :quoted),
    do: chunk_extensions(rest, :quoted_pair)

  defp chunk_extensions(<<char, rest::binary>>, :quoted)
       when char in [9, 32, 33] or char in 35..91 or char in 93..126 or char in 128..255,
       do: chunk_extensions(rest, :quoted)

  defp chunk_extensions(<<char, rest::binary>>, :quoted_pair)
       when char == 9 or char in 32..126 or char in 128..255,
       do: chunk_extensions(rest, :quoted)

  defp chunk_extensions(_data, _state), do: :error

  def content_length_header(string) do
    trimmed = String.trim_trailing(string)

    if only_digits?(trimmed) do
      {:ok, String.to_integer(trimmed)}
    else
      {:error, {:invalid_content_length_header, string}}
    end
  end

  defp only_digits?(<<char>>) when is_digit(char), do: true
  defp only_digits?(<<char, rest::binary>>) when is_digit(char), do: only_digits?(rest)
  defp only_digits?(_other), do: false

  def connection_header(string) do
    split_into_downcase_tokens(string)
  end

  def transfer_encoding_header(string) do
    split_into_downcase_tokens(string)
  end

  defp split_into_downcase_tokens(string) do
    case token_list_downcase(string) do
      {:ok, []} -> {:error, :empty_token_list}
      {:ok, list} -> {:ok, list}
      :error -> {:error, {:invalid_token_list, string}}
    end
  end

  # Made public for testing.
  def token_list_downcase(string), do: token_list_downcase(string, [])

  defp token_list_downcase(<<>>, acc), do: {:ok, :lists.reverse(acc)}

  # Skip all whitespace and commas.
  defp token_list_downcase(<<char, rest::binary>>, acc)
       when is_whitespace(char) or is_comma(char),
       do: token_list_downcase(rest, acc)

  defp token_list_downcase(rest, acc), do: token_downcase(rest, _token_acc = <<>>, acc)

  defp token_downcase(<<char, rest::binary>>, token_acc, acc) when is_tchar(char),
    do: token_downcase(rest, <<token_acc::binary, downcase_ascii_char(char)>>, acc)

  defp token_downcase(rest, token_acc, acc), do: token_list_sep_downcase(rest, [token_acc | acc])

  defp token_list_sep_downcase(<<>>, acc), do: {:ok, :lists.reverse(acc)}

  defp token_list_sep_downcase(<<char, rest::binary>>, acc) when is_whitespace(char),
    do: token_list_sep_downcase(rest, acc)

  defp token_list_sep_downcase(<<char, rest::binary>>, acc) when is_comma(char),
    do: token_list_downcase(rest, acc)

  defp token_list_sep_downcase(_rest, _acc), do: :error

  defp downcase_ascii_char(char) when char in ?A..?Z, do: char + 32
  defp downcase_ascii_char(char) when char in 0..127, do: char
end
