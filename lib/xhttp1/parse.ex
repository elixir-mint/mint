defmodule XHTTP1.Parse do
  @moduledoc false

  defmacro is_digit(char), do: quote(do: unquote(char) in ?0..?9)
  defmacro is_alpha(char), do: quote(do: unquote(char) in ?a..?z or unquote(char) in ?A..?Z)
  defmacro is_whitespace(char), do: quote(do: unquote(char) in '\s\t')
  defmacro is_comma(char), do: quote(do: unquote(char) == ?,)
  defmacro is_vchar(char), do: quote(do: unquote(char) in 33..126)

  defmacro is_tchar(char) do
    quote do
      unquote(char) in '!#$%&\'*+-.^_`|~' or is_digit(unquote(char)) or is_alpha(unquote(char))
    end
  end

  defp lower_char(?A), do: ?a
  defp lower_char(?B), do: ?b
  defp lower_char(?C), do: ?c
  defp lower_char(?D), do: ?d
  defp lower_char(?E), do: ?e
  defp lower_char(?F), do: ?f
  defp lower_char(?G), do: ?g
  defp lower_char(?H), do: ?h
  defp lower_char(?I), do: ?i
  defp lower_char(?J), do: ?j
  defp lower_char(?K), do: ?k
  defp lower_char(?L), do: ?l
  defp lower_char(?M), do: ?m
  defp lower_char(?N), do: ?n
  defp lower_char(?O), do: ?o
  defp lower_char(?P), do: ?p
  defp lower_char(?Q), do: ?q
  defp lower_char(?R), do: ?r
  defp lower_char(?S), do: ?s
  defp lower_char(?T), do: ?t
  defp lower_char(?U), do: ?u
  defp lower_char(?V), do: ?v
  defp lower_char(?W), do: ?w
  defp lower_char(?X), do: ?x
  defp lower_char(?Y), do: ?y
  defp lower_char(?Z), do: ?z
  defp lower_char(char), do: char

  def lower(string), do: for(<<char <- string>>, do: <<lower_char(char)>>, into: "")

  def ignore_until_crlf(<<>>), do: :more
  def ignore_until_crlf(<<"\r\n", rest::binary>>), do: {:ok, rest}
  def ignore_until_crlf(<<_char, rest::binary>>), do: ignore_until_crlf(rest)

  def content_length_header(string) do
    case Integer.parse(string) do
      {length, ""} when length >= 0 ->
        length

      _other ->
        throw({:xhttp, :invalid_content_length_header})
    end
  end

  def connection_header(string) do
    string
    |> token_list_downcase()
    |> not_empty!()
  end

  def transfer_encoding_header(string) do
    string
    |> token_list_downcase()
    |> not_empty!()
  end

  def token_list_downcase(string), do: token_list_downcase(string, [])

  defp token_list_downcase(<<>>, acc), do: :lists.reverse(acc)

  defp token_list_downcase(<<char, rest::binary>>, acc)
       when is_whitespace(char) or is_comma(char),
       do: token_list_downcase(rest, acc)

  defp token_list_downcase(rest, acc), do: token_downcase(rest, <<>>, acc)

  defp token_downcase(<<char, rest::binary>>, token, acc) when is_tchar(char),
    do: token_downcase(rest, <<token::binary, lower_char(char)>>, acc)

  # defp token_downcase(_rest, <<>>, _acc), do: throw({:xhttp, :invalid_token})

  defp token_downcase(rest, token, acc), do: token_list_sep_downcase(rest, [token | acc])

  defp token_list_sep_downcase(<<>>, acc), do: :lists.reverse(acc)

  defp token_list_sep_downcase(<<char, rest::binary>>, acc) when is_whitespace(char),
    do: token_list_sep_downcase(rest, acc)

  defp token_list_sep_downcase(<<?,, rest::binary>>, acc), do: token_list_downcase(rest, acc)

  defp token_list_sep_downcase(_rest, _acc), do: throw({:xhttp, :invalid_token_list})

  def token_list(string), do: token_list(string, [])

  defp token_list(<<>>, acc), do: :lists.reverse(acc)

  defp token_list(<<char, rest::binary>>, acc) when is_whitespace(char) or is_comma(char),
    do: token_list(rest, acc)

  defp token_list(rest, acc), do: token(rest, <<>>, acc)

  defp token(<<char, rest::binary>>, token, acc) when is_tchar(char),
    do: token(rest, <<token::binary, char>>, acc)

  # defp token(_rest, <<>>, _acc), do: throw({:xhttp, :invalid_token})

  defp token(rest, token, acc), do: token_list_sep(rest, [token | acc])

  defp token_list_sep(<<>>, acc), do: :lists.reverse(acc)

  defp token_list_sep(<<char, rest::binary>>, acc) when is_whitespace(char),
    do: token_list_sep(rest, acc)

  defp token_list_sep(<<?,, rest::binary>>, acc), do: token_list(rest, acc)

  defp token_list_sep(_rest, _acc), do: throw({:xhttp, :invalid_token_list})

  defp not_empty!([]), do: throw({:xhttp, :empty_token_list})

  defp not_empty!(list), do: list
end
