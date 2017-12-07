defmodule HTTP2.Frame.Data do
  defstruct [:flags, :stream_id, :data, :padding]
end
