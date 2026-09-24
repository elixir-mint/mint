defmodule Mint.HTTP1.Response do
  @moduledoc false

  import Mint.HTTP1.Parse

  alias Mint.Core.Headers

  # RFC 9112 4: status-line = HTTP-version SP status-code SP [ reason-phrase ]
  # RFC 9112 2.3: HTTP-version = "HTTP/" DIGIT "." DIGIT, and only HTTP/1.x
  # responses are accepted. RFC 9112 4: status-code = 3DIGIT.
  # The reason phrase is validated while looking for the end of the line, and
  # RFC 9112 2.2 allows a bare LF as the line terminator.
  def decode_status_line(<<"HTTP/1.", minor, ?\s, a, b, c, rest::binary>>)
      when minor in ?0..?9 and a in ?1..?9 and b in ?0..?9 and c in ?0..?9 do
    version = {1, minor - ?0}
    status = (a - ?0) * 100 + (b - ?0) * 10 + (c - ?0)

    case rest do
      <<?\s, reason::binary>> -> decode_reason_phrase(reason, reason, 0, version, status)
      _other -> decode_empty_reason_phrase(rest, version, status)
    end
  end

  def decode_status_line(binary) do
    if byte_size(binary) < byte_size("HTTP/1.1 200") and not String.contains?(binary, "\n") do
      :more
    else
      :error
    end
  end

  # RFC 9112 4: reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )
  defp decode_reason_phrase(<<"\r\n", rest::binary>>, reason, size, version, status),
    do: {:ok, {version, status, binary_part(reason, 0, size)}, rest}

  defp decode_reason_phrase(<<"\n", rest::binary>>, reason, size, version, status),
    do: {:ok, {version, status, binary_part(reason, 0, size)}, rest}

  defp decode_reason_phrase(<<char, rest::binary>>, reason, size, version, status)
       when char == ?\t or char in 32..126 or char in 128..255,
       do: decode_reason_phrase(rest, reason, size + 1, version, status)

  defp decode_reason_phrase(data, _reason, _size, _version, _status) when data in ["", "\r"],
    do: :more

  defp decode_reason_phrase(_data, _reason, _size, _version, _status), do: :error

  defp decode_empty_reason_phrase(<<"\r\n", rest::binary>>, version, status),
    do: {:ok, {version, status, ""}, rest}

  defp decode_empty_reason_phrase(<<"\n", rest::binary>>, version, status),
    do: {:ok, {version, status, ""}, rest}

  defp decode_empty_reason_phrase(data, _version, _status) when data in ["", "\r"], do: :more
  defp decode_empty_reason_phrase(_data, _version, _status), do: :error

  def decode_header(binary) do
    case :erlang.decode_packet(:httph_bin, binary, []) do
      {:ok, {:http_header, _unused, name, _reserved, value}, rest} ->
        {:ok, {header_name(name), value}, rest}

      {:ok, :http_eoh, rest} ->
        {:ok, :eof, rest}

      {:ok, _other, _rest} ->
        :error

      {:more, _length} ->
        :more

      {:error, _reason} ->
        :error
    end
  end

  def obs_fold?(value), do: :binary.match(value, "\n") != :nomatch

  # RFC 9110 5.1: field-name = token, token = 1*tchar
  def valid_header_name?(<<>>), do: false
  def valid_header_name?(name), do: tchars?(name)

  defp tchars?(<<char, rest::binary>>) when is_tchar(char), do: tchars?(rest)
  defp tchars?(<<>>), do: true
  defp tchars?(_other), do: false

  # RFC 9110 5.5: field-value = *field-content, field-vchar = VCHAR / obs-text,
  # with HTAB and SP allowed between field-vchars. A recipient of CR, LF or NUL
  # must reject the message or replace them, and other control characters are
  # not allowed at all.
  def valid_header_value?(<<char, rest::binary>>)
      when char == ?\t or char in 32..126 or char in 128..255,
      do: valid_header_value?(rest)

  def valid_header_value?(<<>>), do: true
  def valid_header_value?(_other), do: false

  # RFC 9112 5.2: a user agent must replace each received obs-fold with one or
  # more SP octets before interpreting the field value. obs-fold = OWS CRLF RWS,
  # so the whitespace on both sides of the line break is replaced too.
  def replace_obs_fold(value) do
    if obs_fold?(value), do: replace_obs_fold(value, <<>>), else: value
  end

  defp replace_obs_fold(<<"\r\n", rest::binary>>, acc),
    do: replace_obs_fold(skip_whitespace(rest), <<trim_trailing_whitespace(acc)::binary, ?\s>>)

  defp replace_obs_fold(<<"\n", rest::binary>>, acc),
    do: replace_obs_fold(skip_whitespace(rest), <<trim_trailing_whitespace(acc)::binary, ?\s>>)

  defp replace_obs_fold(<<char, rest::binary>>, acc),
    do: replace_obs_fold(rest, <<acc::binary, char>>)

  defp replace_obs_fold(<<>>, acc), do: acc

  defp skip_whitespace(<<char, rest::binary>>) when char in ~c"\s\t", do: skip_whitespace(rest)
  defp skip_whitespace(rest), do: rest

  defp header_name(atom) when is_atom(atom), do: atom |> Atom.to_string() |> header_name()
  defp header_name(binary) when is_binary(binary), do: Headers.lower_raw(binary)
end
