# Changelog

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
