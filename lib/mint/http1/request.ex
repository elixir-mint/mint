defmodule Mint.HTTP1.Request do
  @moduledoc false

  import Mint.HTTP1.Parse

  alias Mint.Core.Util

  @user_agent "mint/" <> Mix.Project.config()[:version]

  def encode(method, target, host, headers, body) do
    headers =
      headers
      |> lower_header_keys()
      |> add_default_headers(host, body)

    [
      encode_request_line(method, target),
      encode_headers(headers),
      "\r\n",
      encode_body(body)
    ]
  end

  defp encode_request_line(method, target) do
    validate_target!(target)
    [method, ?\s, target, " HTTP/1.1\r\n"]
  end

  defp lower_header_keys(headers) do
    for {name, value} <- headers, do: {lower(name), value}
  end

  defp add_default_headers(headers, host, body) do
    headers
    |> add_content_length(body)
    |> Util.put_new_header("user-agent", @user_agent)
    |> Util.put_new_header("host", host)
  end

  defp add_content_length(headers, nil), do: headers

  defp add_content_length(headers, :stream), do: headers

  defp add_content_length(headers, body) do
    length = body |> IO.iodata_length() |> Integer.to_string()
    Util.put_new_header(headers, "content-length", length)
  end

  defp encode_headers(headers) do
    Enum.reduce(headers, "", fn {name, value}, acc ->
      validate_header_name!(name)
      validate_header_value!(name, value)
      [acc, name, ": ", value, "\r\n"]
    end)
  end

  defp encode_body(nil), do: ""
  defp encode_body(:stream), do: ""
  defp encode_body(body), do: body

  defp validate_target!(target) do
    _ =
      for <<char <- target>> do
        unless URI.char_unescaped?(char) do
          throw({:mint, :invalid_request_target})
        end
      end

    :ok
  end

  defp validate_header_name!(name) do
    _ =
      for <<char <- name>> do
        unless is_tchar(char) do
          throw({:mint, {:invalid_header_name, name}})
        end
      end

    :ok
  end

  defp validate_header_value!(name, value) do
    _ =
      for <<char <- value>> do
        unless is_vchar(char) or char in '\s\t' do
          throw({:mint, {:invalid_header_value, name, value}})
        end
      end

    :ok
  end
end
