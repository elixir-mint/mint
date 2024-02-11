defmodule Mint.Core.Headers do
  @type canonical_header() ::
          {original_name :: String.t(), canonical_name :: String.t(), value :: String.t()}
  @type raw_header() :: {original_name :: String.t(), value :: String.t()}

  @unallowed_trailer_headers MapSet.new([
                               "content-encoding",
                               "content-length",
                               "content-range",
                               "content-type",
                               "trailer",
                               "transfer-encoding",

                               # Control headers (https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7231.html#rfc.section.5.1)
                               "cache-control",
                               "expect",
                               "host",
                               "max-forwards",
                               "pragma",
                               "range",
                               "te",

                               # Conditionals (https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7231.html#rfc.section.5.2)
                               "if-match",
                               "if-none-match",
                               "if-modified-since",
                               "if-unmodified-since",
                               "if-range",

                               # Authentication/authorization (https://tools.ietf.org/html/rfc7235#section-5.3)
                               "authorization",
                               "proxy-authenticate",
                               "proxy-authorization",
                               "www-authenticate",

                               # Cookie management (https://tools.ietf.org/html/rfc6265)
                               "cookie",
                               "set-cookie",

                               # Control data (https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7231.html#rfc.section.7.1)
                               "age",
                               "cache-control",
                               "expires",
                               "date",
                               "location",
                               "retry-after",
                               "vary",
                               "warning"
                             ])

  @spec from_raw_headers([raw_header()]) :: [canonical_header()]
  def from_raw_headers(headers) do
    Enum.map(headers, fn {name, value} -> {name, String.downcase(name, :ascii), value} end)
  end

  @spec to_raw_headers([canonical_header()], boolean()) :: [raw_header()]
  def to_raw_headers(headers, _case_sensitive_headers = true) do
    Enum.map(headers, fn {name, _canonical_name, value} -> {name, value} end)
  end

  def to_raw_headers(headers, _case_sensitive_headers = false) do
    Enum.map(headers, fn {_name, canonical_name, value} ->
      {canonical_name, value}
    end)
  end

  @spec find_header([canonical_header()], String.t()) :: {String.t(), String.t()} | nil
  def find_header(headers, name) do
    case List.keyfind(headers, name, 1) do
      nil -> nil
      {name, _canonical_name, value} -> {name, value}
    end
  end

  @spec replace_header([canonical_header()], String.t(), String.t(), String.t()) ::
          [canonical_header()]
  def replace_header(headers, new_name, canonical_name, value) do
    List.keyreplace(headers, canonical_name, 1, {new_name, canonical_name, value})
  end

  @spec has_header?([canonical_header()], String.t()) :: boolean()
  def has_header?(headers, name) do
    List.keymember?(headers, name, 1)
  end

  @spec put_new_header([canonical_header()], String.t(), String.t(), String.t() | nil) ::
          [canonical_header()]
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

  @spec put_new_header([canonical_header()], String.t(), String.t(), (-> String.t())) ::
          [canonical_header()]
  def put_new_header_lazy(headers, name, canonical_name, fun) do
    if List.keymember?(headers, canonical_name, 1) do
      headers
    else
      [{name, canonical_name, fun.()} | headers]
    end
  end

  @spec find_unallowed_trailer([canonical_header()]) :: String.t() | nil
  def find_unallowed_trailer(headers) do
    Enum.find_value(headers, fn
      {raw_name, canonical_name, _value} ->
        if canonical_name in @unallowed_trailer_headers do
          raw_name
        end
    end)
  end

  @spec remove_unallowed_trailer([raw_header()]) :: [raw_header()]
  def remove_unallowed_trailer(headers) do
    Enum.reject(headers, fn {name, _value} -> name in @unallowed_trailer_headers end)
  end

  @spec lower_raw(String.t()) :: String.t()
  def lower_raw(name) do
    String.downcase(name, :ascii)
  end

  @spec lower_raws([raw_header()]) :: [raw_header()]
  def lower_raws(headers) do
    Enum.map(headers, fn {name, value} -> {lower_raw(name), value} end)
  end
end
