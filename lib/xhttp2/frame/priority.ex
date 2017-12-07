defmodule HTTP2.Frame.Priority do
  defstruct [:flags, :stream_id, :exclusive?, :stream_dependency, :weight]
end
