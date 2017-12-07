defmodule HTTP2.Frame.PushPromise do
  defstruct [:flags, :stream_id, :promised_stream_id, :header_block_fragment, :padding]
end
