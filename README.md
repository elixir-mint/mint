# XHTTP

Functional HTTP client for Elixir with support for HTTP/1 and HTTP/2.

This library is not yet production ready, but we do appreciate contributions and testers.

XHTTP contains two main APIs, a stateless connection API, and a stateful multi-host pooling API.

## Connection API

The two connection API exists in two modules, `XHTTP1.Conn` and `XHTTP2.Conn` with implementations for HTTP/1 and HTTP/2 respectively. `XHTTPN.Conn` uses the same API but with version negotation between the HTTP/1 and 2.

This API represents a connection with a single `%Conn{}` struct and are started by running:

```elixir
{:ok, conn} = XHTTPN.Conn.connect("example.com", 80)
```

Requests are sent with:

```elixir
{:ok, conn} = XHTTPN.Conn.request(conn, "GET", "/", [], "")
```

The connection socket runs in [active mode](http://erlang.org/doc/man/inet.html#setopts-2), that means the user of the library needs to handle [TCP messages](http://erlang.org/doc/man/gen_tcp.html#connect-4) and [SSL messages](http://erlang.org/doc/man/ssl.html#id66002) and pass them to the connection struct:

```elixir
{:ok, responses, conn} = XHTTPN.Conn.stream(conn, {:tcp, #Port<0.1300>, ...})
```

Responses are streamed back to the user in parts through response parts `:status`, `:headers`, `:data` and finally `:done` response. Multiple or none response parts can be returned for a single TCP/SSL message and response parts from different requests can be interleaved when using HTTP/2, users of `XHTTP` needs to handle these cases.

The connection API is stateless, this means that you need to make sure to always save the returned `%Conn{}`:

```elixir
# Wrong
{:ok, _conn} = XHTTPN.Conn.request(conn, "GET", "/foo", [], "")
{:ok, conn} = XHTTPN.Conn.request(conn, "GET", "/bar", [], "")

# Correct
{:ok, conn} = XHTTPN.Conn.request(conn, "GET", "/foo", [], "")
{:ok, conn} = XHTTPN.Conn.request(conn, "GET", "/bar", [], "")
```

## Pool API

The pooling API is not yet implemented, see [#32](https://github.com/ericmj/xhttp/issues/32).

## Contributing

XHTTP has not yet reached an initial 0.1.0 release and the current goal is to reach a minimal first release. Because of this XHTTP is still in a lot of flux and we want to focus on changes only required for getting to 0.1.0. If you wish to contribute check out the [issue list]((https://github.com/ericmj/xhttp/issues) and let us know what you want to work on so we can discuss it and reduce duplicate work.
