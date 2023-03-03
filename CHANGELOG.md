# Changelog

## v1.5.1

### Bug fixes and improvements

  * Fix a `FunctionClauseError` that would happen when calling
    `Mint.HTTP2.close/1` on an HTTP/2 connection that hadn't completed the
    handshake yet. This bug was introduced in v1.5.0. See [issue
    #392](https://github.com/elixir-mint/mint/issues/392).

## v1.5.0

### Bug fixes and improvements

  * Properly close sockets on erroneous connections.
  * Fix `Mint.HTTP.is_connection_message/2` to support proxy connections.
  * Add support for CAStore v1.0.0+.
  * Support all HTTP/2 settings for clients as well (see
    `Mint.HTTP2.put_settings/2`).
  * Handle the first `SETTINGS` frame sent by the server *asynchronously* in
    HTTP/2. This means lower latency between connecting to a server and being
    able to send data to it.
  * Add more logging and make logging configurable through the `:log` option
    (see `Mint.HTTP.connect/4`, `Mint.HTTP1.connect/4`, `Mint.HTTP2.connect/4`).

## v1.4.2

### Bug fixes and improvements

  * Properly handle interim responses (informational `1xx` status codes) in
    HTTP/2. Now you might get zero or more sequences of `:status` and `:headers`
    responses with status `1xx` before the *final response* (with status
    non-`1xx`).

## v1.4.1

### Bug fixes and improvements

  * Emit the remaining buffer as a `:data` response when switching protocols
    from HTTP/1.
  * Respect closed-for-writing when streaming data frames in HTTP/2.
  * Fix handling of HTTP/2 frames of an unknown type.

## v1.4.0

### Bug fixes and improvements

  * Add support for `SETTINGS_ENABLE_CONNECT_PROTOCOL` HTTP/2 server setting.
  * Omit the `:scheme` and `:path` pseudo headers for HTTP/2 CONNECT.
  * Fix invalid connection state when data can't be sent.
  * Skip expired certs in partial chain hook.
  * Add `Mint.HTTP.get_proxy_headers/1`.
  * Add `Mint.HTTP.module/1`.

## v1.3.0

### Bug fixes and improvements

  * Improve compatibility with OTP 24.
  * Support HTTP/1 pipelining when streaming requests.
  * Add `Mint.HTTP.get_socket/1` for returning the connection socket.
  * Improve compatibility with TLS 1.3.

## v1.2.1

### Bug fixes and improvements

  * Fix a bug where we were not ignoring the return value of `:ssl.close/1` and `:gen_tcp.close/1`.
  * Fix a bug where we were not properly handling transport errors when doing ALPN protocol negotiation.
  * Fix a bug where we were not handling connection closed errors in a few places.

## v1.2.0

### Bug fixes and improvements

  * Fix a few bugs with passing the Mint connection around.
  * Add IPv6 support with `inet6: true` in the transport options.
  * Cache the `:cacertfile` option for faster certificate lookup and decoding.
  * Add TLS 1.3 to default versions.

## v1.1.0

### Bug fixes and improvements

  * Concatenate values in one `cookie` header if the `cookie` header is provided more than once in HTTP/2.
  * Fix headers merging in `Mint.UnsafeProxy`.
  * Remove some `Logger.debug/1` calls from the codebase.
  * Assume the HTTP/2 protocol on TCP connections if using `Mint.HTTP2`.
  * Fix a bug where we would send `WINDOW_UPDATE` frames with an increment of `0` in HTTP/2.
  * Make the empty body chunk a no-op for `Mint.HTTP.stream_request_body/3` (only for HTTP/1).
  * Add the `Mint.HTTP.is_connection_message/2` guard.
  * Fix wildcard certificate verification in OTP 23.

## v1.0.0

### Breaking changes

  * Remove the deprecated `Mint.HTTP.request/4`, `Mint.HTTP1.request/4`, and `Mint.HTTP2.request/4`.

## v0.5.0

### Bug fixes and improvements

  * Deprecate `Mint.HTTP.request/4` in favor of explicitly passing the body every time in `Mint.HTTP.request/5`. Same for `Mint.HTTP1` and `Mint.HTTP2`.
  * Don't include port in the `authority` header if it's the default port for the used protocol.
  * Add a default `content-length` header in HTTP/2
  * Allow passing headers to proxies with the `:proxy_headers` option.
  * Fix a bug with HTTP/1 chunking.

## v0.4.0

### Bug fixes and improvements

  * Fix a small bug with double "wrapping" of some `Mint.TransportError`s.
  * Prevent unnecessary buffer allocations in the connections (less memory waste!).
  * Add support for chunked transfer-encoding in HTTP/1 requests when you don't use `content-encoding`/`transfer-encoding` yourself.
  * Add support for trailing headers in HTTP/* requests through `stream_request_body/3`.
  * Add a page about decompressing responses in the guides.

## v0.3.0

### Breaking changes

  * Remove `Mint.HTTP1.get_socket/1`, `Mint.HTTP2.get_socket/1`, and `Mint.HTTP.get_socket/1`.

### Bug fixes and improvements

  * Downcase all headers in HTTP/2 to mimic the behavior in HTTP/1.1.

  * Add `Mint.HTTP.set_mode/2`, `Mint.HTTP1.set_mode/2`, and `Mint.HTTP2.set_mode/2` to change the mode of a socket between active and passive.

  * Add a `:mode` option to the `connect/4` functions to start the socket in active or passive mode.

  * Add `Mint.HTTP.recv/3`, `Mint.HTTP1.recv/3`, and `Mint.HTTP2.recv/3` to receive data from a passive socket in a blocking way.

  * Add `Mint.HTTP.controlling_process/2`, `Mint.HTTP1.controlling_process/2`, and `Mint.HTTP2.controlling_process/2` to change the controlling process of a connection.

  * Support trailing response headers in HTTP/2 connections.

## v0.2.1

### Bug fixes and improvements

  * Fix a bug with requests exceeding the window size in HTTP/2. We were sending the headers of a request even if the body was larger than the window size. Now, if the body is larger than the window size, we error out right away.

  * Fix a bug in the HTTP/2 handshake that would crash the connection in case the server sent unforeseen frames.

  * Improve buffering of body chunks in HTTP/1.

## v0.2.0

### Breaking changes

  * Add the `Mint.TransportError` and `Mint.HTTPError` exceptions. Change all the connection functions so that they return these error structs instead of generic terms.
  * Remove `Mint.HTTP2.get_setting/2` in favour of `Mint.HTTP2.get_server_setting/2` and `Mint.HTTP2.get_client_setting/2`.

### Bug fixes and enhancements

  * Add support for HTTP/2 server push with the new `:push_promise` response.
  * Add `Mint.HTTP2.cancel_request/5`.
  * Add `Mint.HTTP2.get_window_size/2`.
  * Add `open_request_count/1` function to `Mint.HTTP`, and `Mint.HTTP1`, `Mint.HTTP2`.
  * Add `open?/2` function to `Mint.HTTP`, and `Mint.HTTP1`, `Mint.HTTP2`.
  * Make the `Mint.HTTP2.HPACK` module private.
  * Take into account the max header list size advertised by the server in HTTP/2 connections.
  * Improve error handling in a bunch of `Mint.HTTP2` functions.
  * Fix flow control on `WINDOW_UPDATE` frames at the connection level in `Mint.HTTP2`.
  * Correctly return timeout errors when connecting.
  * Treat HTTP/1 header keys as case-insensitive.
  * Prohibit users from streaming on unknown requests in HTTP/2.
  * Prohibit the server from violating the client's max concurrent streams setting in HTTP/2.
  * Strip whitespace when parsing the `content-length` header in HTTP/1.
  * Fix path validation when building HTTP/1 requests, fixes paths with `%NN` escapes.
