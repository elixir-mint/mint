defmodule XHTTP.Request do
  @moduledoc false

  import XHTTP.Parse

  @user_agent "xhttp/0.1.0"

  def encode(method, target, host, headers, body) do
    headers = add_default_headers(headers, host, body)

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

  defp add_default_headers(headers, host, body) do
    headers
    |> add_content_length(body)
    |> put_new_header("user-agent", @user_agent)
    |> put_new_header("host", host)
  end

  defp add_content_length(headers, nil), do: headers

  defp add_content_length(headers, :stream), do: headers

  defp add_content_length(headers, body) do
    length = body |> IO.iodata_length() |> Integer.to_string()
    put_new_header(headers, "content-length", length)
  end

  defp put_new_header(headers, name, value) do
    case :lists.keyfind(name, 1, headers) do
      {^name, _} -> headers
      false -> [{name, value} | headers]
    end
  end

  # TODO: Consider ordering some of the headers, from RFC2616 4.2:
  # > The order in which header fields with differing field names are
  # > received is not significant. However, it is "good practice" to send
  # > general-header fields first, followed by request-header or response-
  # > header fields, and ending with the entity-header fields.
  defp encode_headers(headers) do
    # TODO: Consider validating header names and values, CRLF not allowed unless before LWS
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
          throw({:xhttp, :invalid_request_target})
        end
      end

    :ok
  end

  defp validate_header_name!(name) do
    _ =
      for <<char <- name>> do
        unless is_tchar(char) do
          throw({:xhttp, {:invalid_header_name, name}})
        end
      end

    :ok
  end

  defp validate_header_value!(name, value) do
    _ =
      for <<char <- value>> do
        unless is_vchar(char) or char in '\s\t' do
          throw({:xhttp, {:invalid_header_value, name, value}})
        end
      end

    :ok
  end
end
