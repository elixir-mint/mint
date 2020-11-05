defmodule Mint.UnixSocketExcludeHelper do
  def exclude(atom) when is_atom(atom), do: exclude([atom])

  def exclude(list) do
    cond do
      is_unix?() && otp_19?() -> list
      true -> list ++ [:unix_socket]
    end
  end

  defp is_unix?, do: match?({:unix, _}, :os.type())
  # NOTE: elixir >= 1.6.0 requires OTP >= 19
  defp otp_19?, do: Version.compare(System.version(), "1.6.0") == :gt
end
