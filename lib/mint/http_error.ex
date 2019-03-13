defmodule Mint.HTTPError do
  @type t() :: %__MODULE__{reason: term()}

  defexception [:reason, :module]

  def message(%__MODULE__{reason: reason, module: module}) do
    module.format_error(reason)
  end
end
