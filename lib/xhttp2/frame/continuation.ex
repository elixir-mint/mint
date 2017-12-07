defmodule HTTP2.Frame.Continuation do
  defstruct [:flags, :stream_id, :header_block_fragment]
end
