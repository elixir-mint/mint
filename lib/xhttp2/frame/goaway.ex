defmodule HTTP2.Frame.Goaway do
  defstruct [:flags, :stream_id, :last_stream_id, :error_code, :debug_data]
end
