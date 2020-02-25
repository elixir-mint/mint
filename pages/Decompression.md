# Decompression

Many web servers use compression to reduce the size of the payload to speed up delivery to clients, expecting clients to decompress the body of the request. Some of the common compression algorithms used are [gzip], [brotli], [deflate], or no compression at all.

Clients may specify acceptable compression algorithms through the [`accept-encoding`][accept-encoding] request header. It's common for clients to supply one or more values in `accept-encoding`, for example `accept-encoding: gzip, deflate, identity` in the order of preference.

Servers will read the `accept-encoding` and `TE` request headers, and respond appropriately indicating which compression is used in the response body through the [`content-encoding`][content-encoding] or [`transfer-encoding`][transfer-encoding] response headers respectively. It's not as common to use multiple compression algorithms, but it is possible: for example, `content-encoding: gzip` or `content-encoding: br, gzip` (meaning it was compressed with `br` first, and then `gzip`).

Mint is a low-level client so it doesn't have built-in support for decompression. In this guide we'll explore how to add support for decompression when using Mint.

## Decompressing the response body

Starting with the [architecture example](architecture.html#content), we're going add some logic to handle a finished request's compressed body. With some compression algorithms, it's possible to decompress body chunks as they come (in a streaming way), but let's look at an example that works for every compression algorithm by decompressing the whole response body when the response is done.

This is where we start:

```elixir
defp process_response({:done, request_ref}, state) do
  {%{response: response, from: from}, state} = pop_in(state.requests[request_ref])
  GenServer.reply(from, {:ok, response})
  state
end
```

This function handles the response back to the blocked process that's waiting for the HTTP response. You'll see that it returns `{:ok, response}` with `response` being a map with `:status`, `:headers`, and `:data` fields.

We need to attempt to decompress the data if the `content-encoding` header is present. We're going to work with `content-encoding`, but the same applies if compression is used in  `transfer-encoding`. First, we're going to find the header. Let's add a function to do that:

```elixir
# Returns a list of found compressions or [] if none found.
defp get_content_encoding_header(headers) do
  Enum.find_value(headers, [], fn {name, value} ->
    if String.downcase(name) == "content-encoding" do
      value
      |> String.downcase()
      |> String.split(",", trim: true)
      |> Stream.map(&String.trim/1)
      |> Enum.reverse()
    else
      nil
    end
  end)
end
```

Now we should have a list like `["gzip"]`. We reversed the compression algorithms so that we decompress from the last one to the first one. Let's use this in another function that handles the decompression. Thankfully, Erlang ships with built-in support for gzip and deflate algorithms.

```elixir
defp decompress_data(data, algorithms) do
  Enum.reduce(algorithms, data, &decompress_with_algorithm/2)
end

defp decompress_with_algorithm(gzip, data) when gzip in ["gzip", "x-gzip"],
  do: :zlib.gunzip(data)

defp decompress_with_algorithm("deflate", data),
  do: :zlib.unzip(data)

defp decompress_data("identity", data),
  do: data

defp decompress_data(algorithm, data),
  do: raise "unsupported decompression algorithm: #{inspect(algorithm)}"
```

In case you come across an unsupported algorithm, you might want to log or raise an exception so you can see where you may be lacking support.

Now let's put it together. We can use these new functions when the request is done and pass the result back to the client.

```elixir
defp process_response({:done, request_ref}, state) do
  {%{response: response, from: from}, state} = pop_in(state.requests[request_ref])

  # Handle compression here.
  compression_algorithms = get_content_encoding_header(response.headers)
  response = update_in(response.data, &decompress_data(&1, compression_algorithms))

  GenServer.reply(from, {:ok, response})

  state
end
```

Now you can decompress responses! Above is a simple approach to a potentially complex response, so there is room for error. For example, this guide does not handle decompression errors or compression through `transfer-encoding` (although the code stays very similar in that case).


[gzip]: https://tools.ietf.org/html/rfc1952
[brotli]: https://tools.ietf.org/html/rfc7932
[deflate]: https://tools.ietf.org/html/rfc1951
[accept-encoding]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding
[content-encoding]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
[transfer-encoding]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
