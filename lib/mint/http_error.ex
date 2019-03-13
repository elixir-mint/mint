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

  # TODO: maybe add the target here.
  defp format_reason(:invalid_request_target) do
    "invalid request target"
  end

  defp format_reason({:invalid_header_name, name}) do
    "invalid header name: #{inspect(name)}"
  end

  defp format_reason({:invalid_header_value, name, value}) do
    "invalid value for header #{inspect(name)}: #{inspect(value)}"
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

  # TODO: maybe include the header value here.
  defp format_reason(:invalid_content_length_header) do
    "invalid Content-Length header"
  end

  # TODO: :invalid_token_list
  # TODO: :empty_token_list

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

  defp format_reason(:payload_too_big) do
    "frame payload was too big. This is a server encoding error."
  end

  defp format_reason({:frame_size_error, frame}) do
    humanized_frame = frame |> Atom.to_string() |> String.upcase()
    "frame size error for #{humanized_frame} frame"
  end

  defp format_reason({:protocol_error, reason}) do
    message =
      case reason do
        :bad_window_size_increment ->
          "bad WINDOW_SIZE increment"

        :pad_length_bigger_than_payload_length ->
          "the padding length is bigger than the payload length"

        :invalid_huffman_encoding ->
          "invalid Huffman encoding"
      end

    message <> ". This is a server encoding error."
  end

  ## HPACK

  defp format_reason({:index_not_found, index}) do
    "HPACK index not found: #{inspect(index)}"
  end

  defp format_reason(:bad_integer_encoding) do
    "bad HPACK integer encoding"
  end

  defp format_reason(:bad_binary_encoding) do
    "bad HPACK binary encoding"
  end

  ## Proxy

  defp format_reason(:tunnel_timeout) do
    "tunnel timeout"
  end

  defp format_reason({:unexpected_status, status}) do
    "unexpected status: #{inspect(status)}"
  end

  defp format_reason({:unexpected_trailing_responses, responses}) do
    "unexpected trailing responses: #{inspect(responses)}"
  end

  # TODO: {:proxy, _} errors.
end
