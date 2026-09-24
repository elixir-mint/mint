defmodule Mint.HTTP1.Response do
  @moduledoc false

  import Mint.HTTP1.Parse

  alias Mint.Core.Headers

  # RFC 9112 4: status-line = HTTP-version SP status-code SP [ reason-phrase ]
  # RFC 9112 2.2 allows a bare LF as the line terminator.
  def decode_status_line(binary) do
    case :binary.split(binary, "\n") do
      [line, rest] ->
        line = strip_trailing_cr(line)

        with {:ok, version, status, reason} <- parse_status_line(line),
             true <- valid_reason_phrase?(reason) do
          {:ok, {version, status, reason}, rest}
        else
          _other -> :error
        end

      [_incomplete] ->
        :more
    end
  end

  defp strip_trailing_cr(line) do
    size = byte_size(line) - 1

    case line do
      <<line::binary-size(^size), ?\r>> -> line
      line -> line
    end
  end

  # RFC 9112 2.3: HTTP-version = "HTTP/" DIGIT "." DIGIT, and only HTTP/1.x
  # responses are accepted. RFC 9112 4: status-code = 3DIGIT.
  defp parse_status_line(<<"HTTP/1.", minor, ?\s, a, b, c, rest::binary>>)
       when minor in ?0..?9 and a in ?1..?9 and b in ?0..?9 and c in ?0..?9 do
    reason =
      case rest do
        <<>> -> {:ok, ""}
        <<?\s, reason::binary>> -> {:ok, reason}
        _other -> :error
      end

    with {:ok, reason} <- reason do
      {:ok, {1, minor - ?0}, (a - ?0) * 100 + (b - ?0) * 10 + (c - ?0), reason}
    end
  end

  defp parse_status_line(_line), do: :error

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

  # RFC 9112 4: reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )
  defp valid_reason_phrase?(<<char, rest::binary>>)
       when char == ?\t or char in 32..126 or char in 128..255,
       do: valid_reason_phrase?(rest)

  defp valid_reason_phrase?(<<>>), do: true
  defp valid_reason_phrase?(_other), do: false

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
