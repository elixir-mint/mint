defmodule XHTTP.Request do
  @moduledoc false

  def encode(method, path, host, headers, body) do
    headers = add_default_headers(headers, host, body)

    [
      encode_request_line(method, path),
      encode_headers(headers),
      "\r\n",
      encode_body(body)
    ]
  end

  defp encode_request_line(method, path) do
    # TODO: URI.encode/1 the path?
    [method, ?\s, path, " HTTP/1.1\r\n"]
  end

  defp add_default_headers(headers, host, body) do
    headers
    |> put_new_header("host", host)
    |> add_content_length(body)
  end

  defp add_content_length(headers, nil) do
    headers
  end

  defp add_content_length(headers, body) do
    length = body |> byte_size() |> Integer.to_string()
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
      [acc, name, ": ", value, "\r\n"]
    end)
  end

  defp encode_body(nil), do: ""
  defp encode_body(body), do: body
end
