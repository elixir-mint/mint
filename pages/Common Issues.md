# Common Issues

## Handling Redirects

Because Mint is low level and connections are managed explicitly, redirects will not automatically be followed. That would require a new connection. You will need to make sure you are manually checking for and handling any redirects that happen.

```elixir
def make_request(%URI{} = uri) do
  {:ok, conn} = Mint.HTTP.connect(String.to_atom(uri.scheme), uri.host, 80)

  case Mint.HTTP.request(conn, "GET", uri.path || "/", [], nil) do
    [
      {:status, _request, code},
      {:headers, _request, headers} |
      _rest
      ] when code >= 300 && code < 400 ->
        headers
        |> get_header("location") # some function to pluck headers
        |> URI.parse()
        |> make_request()
    _ ->
      # not a redirect so handle as usual
  end
end
```

It is important to note that if you are maintaining your own connection pool, you will need to ensure the request that was redirected is cleaned up.
