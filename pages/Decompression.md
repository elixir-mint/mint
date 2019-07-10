# Decompression

Many web servers use compression to reduce the size of the payload to speed up
delivery to clients, expecting clients to decompress the body of the request.
The common compression algorithms used are [gzip], [brotli], [deflate], or no
compression at all.

Clients may specify acceptable compression algorithms in an HTTP header
`accept-encoding`. It's normal for clients to supply one or more values in
[Accept-Encoding], eg: `Accept-Encoding: gzip, deflate, identity` in the order
of preference.

Servers will read the `accept-encoding` header, and respond appropriately
indicating which compression is used in the response body with the header
[Content-Encoding]. It's not as common to use multiple compression algorithms,
but it is possible; eg: `Content-Encoding: gzip` or `Content-Encoding: br, gzip`
meaning it was compressed with br first, and then gzip.

[gzip]: https://tools.ietf.org/html/rfc1952
[brotli]: https://tools.ietf.org/html/rfc7932
[deflate]: https://tools.ietf.org/html/rfc1951
[Accept-Encoding]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding
[Content-Encoding]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding

## Example

Starting with the [architecture example](architecture.html#content), we're going add
some logic to handle a finished request's compressed body. This is where we
start:

```elixir
defp process_response({:done, request_ref}, state) do
  {%{response: response, from: from}, state} = pop_in(state.requests[request_ref])
  GenServer.reply(from, {:ok, response})
  state
end
```

This function handles the response back to the blocked process that's waiting
for the HTTP response. You'll see that it returns `{:ok, response}` with
`response` containing `:data, :headers, :status` keys.

We need to attempt to decompress the data if `content-encoding` header is
present; first we're going to find the header. Let's add a function:

```elixir
# Passing in response.headers
# Returns a list of found compressions or [] if none found.
defp find_content_encoding(headers) do
  Enum.find_value(
    headers,
    [],
    fn {name, value} ->
      if String.downcase(name) == "content-encoding" do
        value
        |> String.downcase()
        |> String.replace(~r|\s|, "")
        |> String.split(",")
        |> Enum.reverse()
      end
    end
  )
end
```

Now we should have a list like `["gzip"]`. Let's use this in another function
that handles the decompression. Thankfully, Erlang ships with built-in support
for gzip and deflate algorithms.

```elixir
# Passing in response.data and compressions we found above
# returns the decompressed body or unmodified body.
defp decompress_data(data, []), do: data
defp decompress_data(data, ["gzip" | rest]), do:
  data |> :zlib.gunzip() |> decompress_data(rest)
defp decompress_data(data, ["x-gzip" | rest]), do:
  data |> :zlib.gunzip() |> decompress_data(rest)
defp decompress_data(data, ["deflate" | rest]), do:
  data |> :zlib.unzip() |> decompress_data(rest)
defp decompress_data(data, ["identity" | rest]), do:
  decompress_data(data, rest)
defp decompress_data(data, [encoding | _rest]) do
  Logger.info "Could not decompress body with #{encoding}"
  # Let's also stop decompressing, since it won't work from this point on
  data
end
```

If there are no compressions, then the body just returns. Otherwise, we'll take
the first algorithm in the list and try to decompress the body. That
decompressed body will then be passed into the function again with the remaining
compressions until there are no more remaining. In case you come across an
unsupported algorithm, you might want to log or raise an exception so you can
see where you may be lacking support.

Now let's put it together. We can use these new functions when the request is
done and pass the result back to the client.

```elixir
defp process_response({:done, request_ref}, state) do
  {%{response: response, from: from}, state} = pop_in(state.requests[request_ref])

  # added these two lines:
  decompressed = decompress_data(response.data, find_content_encoding(response.headers))
  response = %{response | data: decompressed}

  GenServer.reply(from, {:ok, response})
  state
end
```

Now you can decompress responses! Above is a simple approach to a potentially
complex response, so there is room for error (for example, this guide does not
handle decompression errors). If you see room for improvement in this guide,
please submit a PR!
