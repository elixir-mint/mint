defmodule Mint.TransportError do
  @moduledoc """
  Represents an error with the transport used by an HTTP connection.

  A `Mint.TransportError` struct is an exception, so it can be raised as any
  other exception.

  ## Struct fields

  This exception represents an error with the transport (TCP or SSL) used
  by an HTTP connection. The exception struct itself is opaque, that is,
  not all fields are public. The following are the public fields:

    * `:reason` - a term representing the error reason. The value of this field
      can be:

        * `:timeout` - if there's a timeout in interacting with the socket.

        * `:closed` - if the connection has been closed.

        * `:protocol_not_negotiated` - if the ALPN protocol negotiation failed.

        * the `:inet.posix/0` type - if there's any other error with the socket,
          such as `:econnrefused` or `:nxdomain`.

  ## Message representation

  If you want to convert an error reason to a human-friendly message (for example
  for using in logs), you can use `Exception.message/1`:

      iex> {:error, %Mint.TransportError{} = error} = Mint.HTTP.connect(:http, "nonexistent", 80)
      iex> Exception.message(error)
      "non-existing domain"

  """

  @opaque t() :: %__MODULE__{reason: term()}

  defexception [:reason, :formatter_module]

  def message(%__MODULE__{reason: reason, formatter_module: formatter_module}) do
    format_reason(reason, formatter_module)
  end

  ## Our reasons.

  defp format_reason(:protocol_not_negotiated, _formatter) do
    "ALPN protocol not negotiated"
  end

  # :inet.format_error/1 doesn't format these messages.
  defp format_reason(:closed, _formatter), do: "socket closed"
  defp format_reason(:timeout, _formatter), do: "timeout"

  ## gen_tcp/ssl reasons.

  defp format_reason(reason, formatter) do
    case formatter.format_error(reason) do
      'unknown POSIX error' -> inspect(reason)
      message -> List.to_string(message)
    end
  end
end
