defmodule HTTP2.Frame.Headers do
  defstruct [:flags, :stream_id, :padding, :priority_data, :header_block_fragment]
end
