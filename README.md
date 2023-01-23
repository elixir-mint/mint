# Mint 🌱

[![Build status badge](https://travis-ci.org/elixir-mint/mint.svg?branch=master)](https://travis-ci.org/elixir-mint/mint)
[![Documentation badge](https://img.shields.io/badge/Documentation-ff69b4)][documentation]
[![Hex.pm badge](https://img.shields.io/badge/Package%20on%20hex.pm-informational)](https://hex.pm/packages/mint)
[![Coverage status badge](https://coveralls.io/repos/github/elixir-mint/mint/badge.svg?branch=main)](https://coveralls.io/github/elixir-mint/mint?branch=main)

> Functional, low-level HTTP client for Elixir with support for HTTP/1 and HTTP/2.

## Installation

To install Mint, add it to your `mix.exs` file. Unless you're using your own SSL certificate store, also add the [CAStore][castore] library to your dependencies.

```elixir
defp deps do
  [
    {:castore, "~> 1.0"},
    {:mint, "~> 1.0"}
  ]
end
```

Then, run `$ mix deps.get`.

## Usage

Mint is different from most Erlang and Elixir HTTP clients because it provides a *process-less architecture*. Instead, Mint is based on a functional and immutable data structure that represents an HTTP connection. This data structure wraps a TCP or SSL socket. This allows for more fine-tailored architectures where the developer is responsible for wrapping the connection struct, such as having one process handle multiple connections or having different kinds of processes handle connections. You can think of Mint as [`:gen_tcp`](https://erlang.org/doc/man/gen_tcp.html) and [`:ssl`](https://www.erlang.org/doc/man/ssl.html), but with an understanding of the HTTP/1.1 and HTTP/2 protocols.

Let's see an example of a basic interaction with Mint. First, we start a connection through `Mint.HTTP.connect/3`:

```elixir
iex> {:ok, conn} = Mint.HTTP.connect(:http, "httpbin.org", 80)
```

This transparently chooses between HTTP/1 and HTTP/2. Then, we can send requests with:

```elixir
iex> {:ok, conn, request_ref} = Mint.HTTP.request(conn, "GET", "/", [], "")
```

The connection socket runs in [*active mode*](http://erlang.org/doc/man/inet.html#setopts-2) (with `active: :once`), which means that the user of the library needs to handle [TCP messages](http://erlang.org/doc/man/gen_tcp.html#connect-4) and [SSL messages](http://erlang.org/doc/man/ssl.html#id66002):

```elixir
iex> flush()
{:tcp, #Port<0.8>,
 "HTTP/1.1 200 OK\r\n" <> _}
```

Users are not supposed to examine these messages. Instead, Mint provides a `stream/2` function that turns messages into HTTP responses. Mint streams responses back to the user in parts through response parts such as `:status`, `:headers`, `:data`, and `:done`.


```elixir
iex> {:ok, conn} = Mint.HTTP.connect(:https, "httpbin.org", 443)
iex> {:ok, conn, request_ref} = Mint.HTTP.request(conn, "GET", "/", [], "")
iex> receive do
...>   message ->
...>     {:ok, conn, responses} = Mint.HTTP.stream(conn, message)
...>     IO.inspect(responses)
...> end
[
  {:status, #Reference<...>, 200},
  {:headers, #Reference<...>, [{"connection", "keep-alive"}, ...},
  {:data, #Reference<...>, "<!DOCTYPE html>..."},
  {:done, #Reference<...>}
]
```

In the example above, we get all the responses as a single SSL message, but that might not always be the case. This means that `Mint.HTTP.stream/2` might not always return responses.

The connection API is *stateless*, whihc means that you need to make sure to always save the connection that functions return:

```elixir
# Wrong ❌
{:ok, _conn, ref} = Mint.HTTP.request(conn, "GET", "/foo", [], "")
{:ok, conn, ref} = Mint.HTTP.request(conn, "GET", "/bar", [], "")

# Correct ✅
{:ok, conn, ref} = Mint.HTTP.request(conn, "GET", "/foo", [], "")
{:ok, conn, ref} = Mint.HTTP.request(conn, "GET", "/bar", [], "")
```

For more information, see [the documentation][documentation].

### SSL certificates

When using SSL, you can pass in your own CA certificate store or use one provided by Mint. Mint doesn't ship with the certificate store itself, but it has an optional dependency on [CAStore][castore], which provides an up-to-date certificate store. If you don't want to use your own certificate store, just add `:castore` to your dependencies.

```elixir
defp deps do
  [
    # ...,
    {:castore, "~> 1.0.0"},
    {:mint, "~> 0.4.0"}
  ]
end
```

### WebSocket Support

Mint itself does not support the WebSocket protocol, but it can be used as the foundation to build a WebSocket client on top of. If you need WebSocket support, you can use [mint_web_socket].

### Connection Management and Pooling

Mint is a low-level client. If you need higher-level features such as connection management, pooling, metrics, and more, check out [Finch], a project built on top of Mint that provides those things.

## Contributing

If you wish to contribute, check out the [issue list][issues] and let us know what you want to work on, so that we can discuss it and reduce duplicate work.

Tests are organized with tags. Integration tests that hit real websites over the internet are tagged with `:requires_internet_connection`. Proxy tests are tagged with `:proxy` and require that you run `docker-compose up` from the Mint root directory in order to run (they are excluded by default when you run `$ mix test`). A few examples of running tests:

  * `$ mix test` to run the test suite without caring about Docker and `docker-compose up`.

  * `$ mix test --exclude integration` to only run local tests (for example, you don't have an internet connection available).

  * `$ mix test --include proxy` to run all tests, including proxy tests.

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

[castore]: https://github.com/elixir-mint/castore
[documentation]: https://hexdocs.pm/mint
[issues]: https://github.com/elixir-mint/mint/issues
[mint_web_socket]: https://github.com/elixir-mint/mint_web_socket
[Finch]: https://github.com/sneako/finch
