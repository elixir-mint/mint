defmodule HTTP2.Frame.RstStream do
  defstruct [:flags, :stream_id, :error_code]
end
