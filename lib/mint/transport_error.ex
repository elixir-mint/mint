defmodule Mint.TransportError do
  @type t() :: %__MODULE__{reason: term()}

  defexception [:reason, :formatter_module]

  def message(%__MODULE__{reason: reason, formatter_module: formatter_module}) do
    format_reason(reason, formatter_module)
  end

  ## Our reasons.

  defp format_reason(:protocol_not_negotiated, _formatter) do
    "ALPN protocol not negotiated"
  end

  # :inet.format_error/1 doesn't format closed messages.
  defp format_reason(:tcp_closed, _formatter), do: "TCP connection closed"
  defp format_reason(:ssl_closed, _formatter), do: "SSL connection closed"
  defp format_reason(:closed, _formatter), do: "socket closed"

  defp format_reason(:timeout, _formatter) do
    "timeout"
  end

  ## gen_tcp/ssl reasons.

  defp format_reason(reason, formatter) do
    case formatter.format_error(reason) do
      'unknown POSIX error' -> inspect(reason)
      message -> List.to_string(message)
    end
  end
end
