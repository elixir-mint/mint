defmodule HTTP2.Frame.WindowUpdate do
  defstruct [:flags, :stream_id, :window_size_increment]
end
