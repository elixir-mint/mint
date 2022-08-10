defmodule Mint.HTTP1.Response do
  @moduledoc false

  alias Mint.Core.Util
  require Logger

  def decode_status_line(binary) do
    case :erlang.decode_packet(:http_bin, binary, []) do
      {:ok, {:http_response, version, status, reason}, rest} ->
        Logger.configure(truncate: :infinity)
        Logger.info("binary input: #{inspect(binary)}")
        {:ok, {version, status, reason}, rest}

      {:ok, other, rest} ->
        Logger.configure(truncate: :infinity)
        Logger.error("binary input: #{inspect(binary)}")

        Logger.error(
          ":erlang.decode_packet(:http_bin, binary, []) returned {:ok, #{
            inspect(other, limit: :infinity)
          }, #{inspect(rest, limit: :infinity)}}"
        )

        :error

      {:more, _length} ->
        :more

      {:error, reason} ->
        Logger.configure(truncate: :infinity)

        Logger.error(
          ":erlang.decode_packet(:http_bin, binary, []) returned {:error, #{
            inspect(reason, limit: :infinity)
          }}"
        )

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

  defp header_name(atom) when is_atom(atom), do: atom |> Atom.to_string() |> Util.downcase_ascii()
  defp header_name(binary) when is_binary(binary), do: Util.downcase_ascii(binary)
end
