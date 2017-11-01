defmodule XHTTP.Parse do
  # TODO: Inline and optimize, reduce String module usage

  defmacrop digit?(char), do: quote(do: unquote(char) in ?0..?9)
  defmacrop alpha?(char), do: quote(do: unquote(char) in ?a..?z or unquote(char) in ?A..?Z)
  defmacrop whitespace?(char), do: quote(do: unquote(char) in '\s\t')
  defmacrop comma?(char), do: quote(do: unquote(char) == ?,)

  defmacrop tchar?(char) do
    quote do
      unquote(char) in '!#$%&\'*+-.^_`|~' or digit?(unquote(char)) or alpha?(unquote(char))
    end
  end

  def content_length_header(string) do
    case Integer.parse(string) do
      {length, ""} when length >= 0 ->
        length

      _other ->
        throw({:xhttp, :invalid_response})
    end
  end

  def connection_header(string) do
    string
    |> token_list_downcase()
    |> not_empty!()
  end

  def token_list_downcase(string), do: string |> token_list() |> Enum.map(&String.downcase/1)

  def token_list(string), do: token_list(string, [])

  defp token_list(<<>>, acc), do: Enum.reverse(acc)

  defp token_list(<<char, rest::binary>>, acc) when whitespace?(char) or comma?(char),
    do: token_list(rest, acc)

  defp token_list(rest, acc), do: token(rest, <<>>, acc)

  defp token(<<char, rest::binary>>, token, acc) when tchar?(char),
    do: token(rest, <<token::binary, char>>, acc)

  defp token(_rest, <<>>, _acc), do: throw({:xhttp, :invalid_response})

  defp token(rest, token, acc), do: token_list_sep(rest, [token | acc])

  defp token_list_sep(<<>>, acc), do: Enum.reverse(acc)

  defp token_list_sep(<<char, rest::binary>>, acc) when whitespace?(char),
    do: token_list_sep(rest, acc)

  defp token_list_sep(<<?,, rest::binary>>, acc), do: token_list(rest, acc)

  defp token_list_sep(_rest, _acc), do: throw({:xhttp, :invalid_response})

  defp not_empty!([]), do: throw({:xhttp, :invalid_response})

  defp not_empty!(list), do: list
end
