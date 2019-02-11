# Mint

Functional HTTP client for Elixir with support for HTTP/1 and HTTP/2.

This library is not yet production ready, but we do appreciate contributions and testers.

Mint contains two main APIs, a stateless connection API, and a stateful multi-host pooling API.

## Connection API

The two connection API exists in two modules, `Mint.HTTP1` and `Mint.HTTP2` with implementations for HTTP/1 and HTTP/2 respectively. `Mint` uses the same API but with version negotiation between the HTTP/1 and 2.

This API represents a connection with a single `conn` struct and are started by running:

```elixir
iex> {:ok, conn} = Mint.HTTP.connect(:http, "httpbin.org", 80)
```

Requests are sent with:

```elixir
iex> {:ok, conn, request_ref} = Mint.HTTP.request(conn, "GET", "/", [], "")
```

The connection socket runs in [active mode](http://erlang.org/doc/man/inet.html#setopts-2), that means the user of the library needs to handle [TCP messages](http://erlang.org/doc/man/gen_tcp.html#connect-4) and [SSL messages](http://erlang.org/doc/man/ssl.html#id66002):

```elixir
iex> flush()
{:tcp, #Port<0.8>,
 "HTTP/1.1 200 OK\r\n" <> _}
```

Responses are streamed back to the user in parts through response parts `:status`, `:headers`, `:data` and finally `:done` response:

```elixir
iex> {:ok, conn} = Mint.HTTP.connect(:http, "httpbin.org", 80)
iex> {:ok, conn, request_ref} = Mint.HTTP.request(conn, "GET", "/", [], "")
iex> receive do
...>   message ->
...>     {:ok, conn, responses} = Mint.HTTP.stream(conn, message)
...>     IO.inspect responses
...> end
[
  {:status, #Reference<...>, 200},
  {:headers, #Reference<...>, [{"connection", "keep-alive"}, ...},
  {:data, #Reference<...>, "<!DOCTYPE html>..."},
  {:done, #Reference<...>}
]
```

Multiple or none response parts can be returned for a single TCP/SSL message and response parts from different requests can be interleaved when using HTTP/2, users of `Mint` needs to handle these cases.

The connection API is stateless, this means that you need to make sure to always save the returned `conn`:

```elixir
# Wrong
{:ok, _conn, ref} = Mint.HTTP.request(conn, "GET", "/foo", [], "")
{:ok, conn, ref} = Mint.HTTP.request(conn, "GET", "/bar", [], "")

# Correct
{:ok, conn, ref} = Mint.HTTP.request(conn, "GET", "/foo", [], "")
{:ok, conn, ref} = Mint.HTTP.request(conn, "GET", "/bar", [], "")
```

## Pool API

The pooling API is not yet implemented, see [#32](https://github.com/ericmj/mint/issues/32).

## Contributing

Mint has not yet reached an initial 0.1.0 release and the current goal is to reach a minimal first release. Because of this Mint is still in a lot of flux and we want to focus on changes only required for getting to 0.1.0. If you wish to contribute check out the [issue list](https://github.com/ericmj/mint/issues) and let us know what you want to work on so we can discuss it and reduce duplicate work.

## License

Copyright 2018 Eric Meadows-Jönsson and Andrea Leopardi

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
