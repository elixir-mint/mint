defmodule Mint.HTTP1.Response do
  @moduledoc false

  alias Mint.Core.Headers

  def decode_status_line(binary) do
    case :erlang.decode_packet(:http_bin, binary, []) do
      {:ok, {:http_response, {1, minor} = version, status, reason}, rest}
      when minor in 0..9 and status in 100..999 ->
        if valid_reason_phrase?(reason) do
          {:ok, {version, status, reason}, rest}
        else
          :error
        end

      {:ok, _other, _rest} ->
        :error

      {:more, _length} ->
        :more

      {:error, _reason} ->
        :error
    end
  end

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

  # RFC 9112 5.2: a user agent must replace each received obs-fold with one or
  # more SP octets before interpreting the field value.
  def replace_obs_fold(value) do
    if obs_fold?(value), do: replace_obs_fold(value, <<>>), else: value
  end

  defp replace_obs_fold(<<"\r\n", rest::binary>>, acc),
    do: replace_obs_fold(skip_whitespace(rest), <<acc::binary, ?\s>>)

  defp replace_obs_fold(<<"\n", rest::binary>>, acc),
    do: replace_obs_fold(skip_whitespace(rest), <<acc::binary, ?\s>>)

  defp replace_obs_fold(<<char, rest::binary>>, acc),
    do: replace_obs_fold(rest, <<acc::binary, char>>)

  defp replace_obs_fold(<<>>, acc), do: acc

  defp skip_whitespace(<<char, rest::binary>>) when char in ~c"\s\t", do: skip_whitespace(rest)
  defp skip_whitespace(rest), do: rest

  defp header_name(atom) when is_atom(atom), do: atom |> Atom.to_string() |> header_name()
  defp header_name(binary) when is_binary(binary), do: Headers.lower_raw(binary)
end
