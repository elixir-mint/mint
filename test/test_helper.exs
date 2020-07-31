ExUnit.start(exclude: :proxy)
Application.ensure_all_started(:ssl)
Logger.configure(level: :info)

Mint.CowboyTestServer.start_http(:http1, 8101)
Mint.CowboyTestServer.start_https(:http1, 8102, ref: Mint.CowboyTestServer.HTTP1.HTTPS)

Mint.CowboyTestServer.start_https(:http2, 8202, ref: Mint.CowboyTestServer.HTTP2)
