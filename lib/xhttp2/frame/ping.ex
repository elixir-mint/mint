defmodule HTTP2.Frame.Ping do
  defstruct [:flags, :stream_id, :opaque_data]
end
