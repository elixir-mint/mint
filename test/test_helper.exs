ExUnit.start()
Application.ensure_all_started(:ssl)

defmodule XHTTP.TestHelpers do
  def merge_body(responses, request) do
    merge_body(responses, request, "")
  end

  defp merge_body([{:body, request, new_body} | responses], request, body) do
    merge_body(responses, request, body <> new_body)
  end

  defp merge_body([{:headers, request, trailing}, {:done, request}], request, body) do
    {body, trailing}
  end

  defp merge_body([{:done, request}], request, body) do
    body
  end
end
