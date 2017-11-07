ExUnit.start()
Application.ensure_all_started(:ssl)

defmodule XHTTP.TestHelpers do
  def merge_body([{:body, request, body} | responses], request) do
    body <> merge_body(responses, request)
  end

  def merge_body([{:done, request}], request) do
    ""
  end
end
