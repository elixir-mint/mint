defmodule Mint.Error do
  @moduledoc """
  TODO: write docs.
  """

  @type t() :: %__MODULE__{reason: term()}

  defexception [:reason]

  def message(%__MODULE__{reason: reason}) do
    format_reason(reason)
  end

  # TODO: handle all of our possible reasons.

  # :inet.format_error/1 doesn't format closed messages.
  defp format_reason(:tcp_closed), do: "TCP connection closed"
  defp format_reason(:ssl_closed), do: "SSL connection closed"

  defp format_reason(reason) do
    case :inet.format_error(reason) do
      'unknown POSIX error' -> inspect(reason)
      message -> List.to_string(message)
    end
  end
end
