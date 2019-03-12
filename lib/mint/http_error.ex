defmodule Mint.HTTPError do
  @type t() :: %__MODULE__{reason: term()}

  defexception [:reason]

  def message(%__MODULE__{reason: reason}) do
    format_reason(reason)
  end

  ## HTTP/1 errors

  defp format_reason(:request_body_is_streaming) do
    "a request body is currently streaming, so no new requests can be issued"
  end

  defp format_reason({:unexpected_data, data}) do
    "received unexpected data: " <> inspect(data)
  end

  defp format_reason(:invalid_status_line) do
    "invalid status line"
  end

  defp format_reason(:invalid_header) do
    "invalid header"
  end

  defp format_reason(:invalid_chunk_size) do
    "invalid chunk size"
  end

  defp format_reason(:missing_crlf_after_chunk) do
    "missing CRLF after chunk"
  end

  defp format_reason(:invalid_trailer_header) do
    "invalid trailer header"
  end

  defp format_reason(:more_than_one_content_length_header) do
    "the response contains two or more Content-Length headers"
  end

  defp format_reason(:transfer_encoding_and_content_length) do
    "the response contained both a Transfer-Encoding header as well as a Content-Length header"
  end

  ## HTTP/2 errors

  defp format_reason({:max_concurrent_streams_reached, max_concurrent_streams}) do
    "the number of max concurrent HTTP/2 requests supported by the server (which is " <>
      "#{max_concurrent_streams}) has been reached"
  end

  defp format_reason({:max_header_list_size_exceeded, size, max_size}) do
    "the given header list (of size #{size}) goes over the max header list size of " <>
      "#{max_size} supported by the server. In HTTP/2, the header list size is calculated " <>
      "by summing up the size in bytes of each header name, value, plus 32 for each header."
  end

  defp format_reason({:exceeds_stream_window_size, window_size}) do
    "the given data exceeds the request window size, which is #{window_size}. " <>
      "The server will refill the window size of this request when ready."
  end

  defp format_reason({:exceeds_connection_window_size, window_size}) do
    "the given data exceeds the window size of the connection, which is #{window_size}. " <>
      "The server will refill the window size of the connection when ready."
  end
end
