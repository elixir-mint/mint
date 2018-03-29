defmodule XHTTP.Headers do
  @moduledoc ~S"""
  Functions for working with HTTP request and response headers, as described
  in the [HTTP 1.1 specification](https://www.w3.org/Protocols/rfc2616/rfc2616.html).

  Headers are represented in Elixir as a list of `{"header_name", "value"}`
  tuples.  Multiple entries for the same header name are allowed.

  Capitalization of header names is preserved during insertion
  (`put_header/3`), however header names are handled case-insensitively
  during lookup (`get_header/2`, `get_header_values/2`) and deletion
  (`delete_header/2`).
  """

  @type headers :: [{String.t(), String.t()}]

  @doc ~S"""
  Returns the value for the given HTTP request or response header,
  or `nil` if not found.

  Header names are matched case-insensitively.

  If more than one matching header is found, the values are joined with
  `","` as specified in [RFC 2616](https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2).
  """
  @spec get_header(headers, String.t()) :: String.t() | nil
  def get_header(headers, name) do
    case get_header_values(headers, name) do
      [] -> nil
      values -> values |> Enum.join(",")
    end
  end

  @doc ~S"""
  Returns all values for the given HTTP request or response header.
  Returns an empty list if none found.

  Header names are matched case-insensitively.
  """
  @spec get_header_values(headers, String.t()) :: [String.t()]
  def get_header_values(headers, name) do
    get_header_values(headers, String.downcase(name), [])
  end

  defp get_header_values([], _name, values), do: values

  defp get_header_values([{key, value} | rest], name, values) do
    new_values =
      if String.downcase(key) == name do
        values ++ [value]
      else
        values
      end

    get_header_values(rest, name, new_values)
  end

  @doc ~S"""
  Puts the given header `value` under `name`, removing any values previously
  stored under `name`.  The new header is placed at the end of the list.

  Header names are matched case-insensitively, but case of `name` is preserved
  when adding the header.
  """
  @spec put_header(headers, String.t(), String.t()) :: headers
  def put_header(headers, name, value) do
    delete_header(headers, name) ++ [{name, value}]
  end

  @doc ~S"""
  Removes all instances of the given header.

  Header names are matched case-insensitively.
  """
  @spec delete_header(headers, String.t()) :: headers
  def delete_header(headers, name) do
    name = String.downcase(name)
    Enum.filter(headers, fn {key, _value} -> String.downcase(key) != name end)
  end

  @doc ~S"""
  Returns an ordered list of the header names from the given headers.
  Header names are returned in lowercase.
  """
  @spec header_names(headers) :: [String.t()]
  def header_names(headers) do
    header_names(headers, [])
  end

  defp header_names([], names), do: Enum.reverse(names)

  defp header_names([{name, _value} | rest], names) do
    name = String.downcase(name)

    if name in names do
      header_names(rest, names)
    else
      header_names(rest, [name | names])
    end
  end

  @doc ~S"""
  Returns a copy of the given headers, where all header names are lowercased
  and multiple values for the same header have been joined with `","`.
  """
  @spec normalize_headers(headers) :: headers
  def normalize_headers(headers) do
    headers_map =
      Enum.reduce(headers, %{}, fn {name, value}, acc ->
        name = String.downcase(name)
        values = Map.get(acc, name, [])
        Map.put(acc, name, values ++ [value])
      end)

    headers
    |> header_names
    |> Enum.map(fn name ->
      {name, Map.get(headers_map, name) |> Enum.join(",")}
    end)
  end
end
