defmodule Mint.TransportError do
  @type t() :: %__MODULE__{reason: term()}

  defexception [:reason]

  def message(%__MODULE__{reason: reason}) do
    format_reason(reason)
  end

  ## Our reasons.

  defp format_reason({:bad_alpn_protocol, protocol}) do
    "bad ALPN protocol: #{inspect(protocol)}. Supported protocols are \"http/1.1\" and \"h2\"."
  end

  defp format_reason(:protocol_not_negotiated) do
    "ALPN protocol not negotiated"
  end

  # :inet.format_error/1 doesn't format closed messages.
  defp format_reason(:tcp_closed), do: "TCP connection closed"
  defp format_reason(:ssl_closed), do: "SSL connection closed"
  defp format_reason(:closed), do: "socket closed"

  # TODO: timeout

  ## gen_tcp/ssl reasons.

  defp format_reason(reason) do
    case :inet.format_error(reason) do
      'unknown POSIX error' -> inspect(reason)
      message -> List.to_string(message)
    end
  end
end
