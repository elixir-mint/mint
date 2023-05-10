defmodule Mint.HTTP1.Headers do
  alias Mint.Core.Util

  # format of headers is [{header_name, canonical_header_name, value}]

  def from_raw_headers(headers) do
    for {name, value} <- headers, do: {name, Util.downcase_ascii(name), value}
  end

  def to_raw_headers(headers, downcase_headers) do
    if downcase_headers do
      for {_name, canonical_name, value} <- headers do
        {canonical_name, value}
      end
    else
      for {name, _canonical_name, value} <- headers, do: {name, value}
    end
  end

  # name is required to be downcase ascii
  def find_header(headers, name) do
    case List.keyfind(headers, name, 1) do
      nil -> nil
      {name, _canonical_name, value} -> {name, value}
    end
  end

  # name is required to be downcase ascii
  # downcase_ascii(new_name) == name
  def replace_header(headers, new_name, canonical_name, value) do
    List.keyreplace(headers, canonical_name, 1, {new_name, canonical_name, value})
  end

  # name is required to be downcase ascii
  def has_header?(headers, name) do
    List.keymember?(headers, name, 1)
  end

  # canonical_name is required to be downcase ascii
  def put_new_header(headers, name, canonical_name, value)

  def put_new_header(headers, _name, _canonical_name, nil) do
    headers
  end

  def put_new_header(headers, name, canonical_name, value) do
    if List.keymember?(headers, canonical_name, 1) do
      headers
    else
      [{name, canonical_name, value} | headers]
    end
  end

  def put_new_header_lazy(headers, name, canonical_name, fun) do
    if List.keymember?(headers, canonical_name, 1) do
      headers
    else
      [{name, canonical_name, fun.()} | headers]
    end
  end
end
