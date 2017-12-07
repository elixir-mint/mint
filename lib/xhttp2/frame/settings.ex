defmodule HTTP2.Frame.Settings do
  defstruct [:flags, :stream_id, :params]
end
