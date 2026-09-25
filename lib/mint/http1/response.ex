defmodule Mint.HTTP1.Response do
  @moduledoc false

  import Bitwise, only: [|||: 2]
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

  # Header lines are scanned a word of bytes at a time (SWAR, SIMD within a
  # register): 7 bytes are read as one integer, which stays a small integer on
  # 64-bit systems, and bit tricks tell whether any byte in it is one the scan
  # has to stop at. Only words that contain such a byte are looked at byte by byte.
  @word 7
  @bits @word * 8
  @ones Enum.reduce(1..@word, 0, fn _, acc -> Bitwise.bor(Bitwise.bsl(acc, 8), 0x01) end)
  @highs @ones * 0x80
  @lows @ones * 0x7F
  @colons @ones * ?:
  @dels @ones * 0x7F
  @spaces @ones * 0x20

  # Sets the high bit of every byte of `word` that equals the byte in `pattern`
  # (low bytes can also get false positives above a real match, so matches are
  # confirmed byte by byte).
  defmacrop has_byte(word, pattern) do
    quote do
      x = Bitwise.bxor(unquote(word), unquote(pattern))
      Bitwise.band(Bitwise.band(x - @ones, Bitwise.bnot(x)), @highs)
    end
  end

  # Sets the high bit of bytes of `word` that are below the byte in `pattern`.
  defmacrop has_less(word, pattern) do
    quote do
      x = unquote(word)
      Bitwise.band(Bitwise.band(x - unquote(pattern), Bitwise.bnot(x)), @highs)
    end
  end

  # Sets the high bit of ASCII bytes of the word between lo and hi. `x7` is the
  # word with the high bit of every byte cleared and `nx` has the high bit set
  # for every byte below 0x80.
  defmacrop has_between(x7, nx, lo, hi) do
    quote do
      Bitwise.band(
        Bitwise.band(
          unquote(@ones * (127 + hi + 1)) - unquote(x7),
          unquote(x7) + unquote(@ones * (127 - (lo - 1)))
        ),
        unquote(nx)
      )
    end
  end

  # Decodes one header or trailer line. The name is lowercased and the value has
  # its surrounding whitespace removed and its obsolete line folds replaced with
  # a space. A line that ends exactly at the end of the data returns :more unless
  # emit_at_end? is true, since a folded continuation line could follow it.
  def decode_header(binary, emit_at_end? \\ false)

  def decode_header(<<"\r\n", rest::binary>>, _emit_at_end?), do: {:ok, :eof, rest}
  def decode_header(<<"\n", rest::binary>>, _emit_at_end?), do: {:ok, :eof, rest}
  def decode_header(data, _emit_at_end?) when data in ["", "\r"], do: :more

  def decode_header(binary, emit_at_end?) do
    case find_colon(binary, 0) do
      {:ok, 0} ->
        :error

      {:ok, name_size} ->
        <<name::binary-size(^name_size), ?:, rest::binary>> = binary
        decode_header_value(rest, [], emit_at_end?, Headers.lower_raw(name))

      other ->
        other
    end
  end

  defp decode_header_value(data, segments, emit_at_end?, name) do
    with {:ok, size} <- find_line_end(data, 0) do
      <<segment::binary-size(^size), rest::binary>> = data

      with {:ok, rest} <- skip_line_end(rest) do
        segments = [segment | segments]

        case rest do
          <<char, _::binary>> when char in ~c"\s\t" ->
            decode_header_value(rest, segments, emit_at_end?, name)

          <<>> when not emit_at_end? ->
            :more

          _other ->
            {:ok, {name, join_segments(segments)}, rest}
        end
      end
    end
  end

  defp skip_line_end(<<"\r\n", rest::binary>>), do: {:ok, rest}
  defp skip_line_end(<<"\n", rest::binary>>), do: {:ok, rest}
  defp skip_line_end("\r"), do: :more
  defp skip_line_end(_other), do: :error

  # RFC 9112 5.1 excludes the whitespace around the value from it, and RFC 9112
  # 5.2 has a user agent replace each obs-fold (OWS CRLF RWS) with a space.
  defp join_segments([segment]), do: trim_whitespace(segment)

  defp join_segments(segments) do
    segments
    |> Enum.reverse()
    |> Enum.map(&trim_whitespace/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join(" ")
  end

  defp trim_whitespace(value),
    do: value |> trim_leading_whitespace() |> trim_trailing_whitespace()

  # RFC 9110 5.1: field-name = token, token = 1*tchar. Returns the position of
  # the colon, or :error on the first byte that isn't a tchar.
  defp find_colon(<<word::size(@bits)-little, rest::binary>>, index) do
    x7 = Bitwise.band(word, @lows)
    nx = Bitwise.band(Bitwise.bnot(word), @highs)

    mask =
      Bitwise.band(word, @highs) |||
        has_byte(word, @colons) |||
        has_less(word, @spaces + @ones) |||
        has_byte(word, @dels) |||
        has_between(x7, nx, 0x22, 0x22) |||
        has_between(x7, nx, 0x28, 0x29) |||
        has_between(x7, nx, 0x2C, 0x2C) |||
        has_between(x7, nx, 0x2F, 0x2F) |||
        has_between(x7, nx, 0x3B, 0x40) |||
        has_between(x7, nx, 0x5B, 0x5D) |||
        has_between(x7, nx, 0x7B, 0x7B) |||
        has_between(x7, nx, 0x7D, 0x7D)

    case check_colon(mask, word) do
      :continue -> find_colon(rest, index + @word)
      {:ok, position} -> {:ok, index + position}
      :error -> :error
    end
  end

  defp find_colon(<<?:, _rest::binary>>, index), do: {:ok, index}

  defp find_colon(<<char, rest::binary>>, index) when is_tchar(char),
    do: find_colon(rest, index + 1)

  defp find_colon(<<>>, _index), do: :more
  defp find_colon(_other, _index), do: :error

  defp check_colon(0, _word), do: :continue

  defp check_colon(mask, word) do
    position = lowest_position(mask)

    case Bitwise.band(Bitwise.bsr(word, position * 8), 0xFF) do
      ?: -> {:ok, position}
      char when is_tchar(char) -> check_colon(Bitwise.band(mask, mask - 1), word)
      _other -> :error
    end
  end

  # RFC 9110 5.5: field-value = *field-content, field-vchar = VCHAR / obs-text,
  # with HTAB and SP allowed between field-vchars. Returns the position of the
  # CR or LF ending the line, or :error on any other control character.
  defp find_line_end(
         <<w1::size(@bits)-little, w2::size(@bits)-little, rest::binary>> = data,
         index
       ) do
    mask =
      has_less(w1, @spaces) ||| has_byte(w1, @dels) ||| has_less(w2, @spaces) |||
        has_byte(w2, @dels)

    if mask == 0 do
      find_line_end(rest, index + 2 * @word)
    else
      find_line_end_in_word(data, index)
    end
  end

  defp find_line_end(data, index), do: find_line_end_in_word(data, index)

  defp find_line_end_in_word(<<word::size(@bits)-little, rest::binary>>, index) do
    mask = has_less(word, @spaces) ||| has_byte(word, @dels)

    case check_line_end(mask, word) do
      :continue -> find_line_end(rest, index + @word)
      {:ok, position} -> {:ok, index + position}
      :error -> :error
    end
  end

  defp find_line_end_in_word(<<char, _rest::binary>>, index) when char in ~c"\r\n",
    do: {:ok, index}

  defp find_line_end_in_word(<<?\t, rest::binary>>, index), do: find_line_end(rest, index + 1)

  defp find_line_end_in_word(<<char, rest::binary>>, index) when char >= 0x20 and char != 0x7F,
    do: find_line_end(rest, index + 1)

  defp find_line_end_in_word(<<>>, _index), do: :more
  defp find_line_end_in_word(_other, _index), do: :error

  defp check_line_end(0, _word), do: :continue

  defp check_line_end(mask, word) do
    position = lowest_position(mask)

    case Bitwise.band(Bitwise.bsr(word, position * 8), 0xFF) do
      char when char in ~c"\r\n" -> {:ok, position}
      ?\t -> check_line_end(Bitwise.band(mask, mask - 1), word)
      char when char < 0x20 or char == 0x7F -> :error
      _other -> check_line_end(Bitwise.band(mask, mask - 1), word)
    end
  end

  for k <- 0..(@word - 1) do
    defp lowest_position(mask) when Bitwise.band(mask, unquote(Bitwise.bsl(0x80, 8 * k))) != 0,
      do: unquote(k)
  end
end
