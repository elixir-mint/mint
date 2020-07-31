defmodule Mint.CowboyTestServer do
  @moduledoc false

  @protocol_options [
    idle_timeout: 5_000_000,
    max_keepalive: 100,
    inactivity_timeout: 10_000,
    request_timeout: 10_000,
    shutdown_timeout: 10_000
  ]

  @certfile Path.absname("../mint/certificate.pem", __DIR__)

  @keyfile Path.absname("../mint/key.pem", __DIR__)

  def start_http(scheme, port, options \\ [])

  def start_http(:http1, port, options) do
    start(:http, Keyword.put(options, :port, port))
  end

  def start_http(:http2, port, options) do
    start(:http, Keyword.put(options, :port, port))
  end

  def start_https(scheme, port, options \\ [])

  def start_https(:http1, port, options) do
    options =
      [certfile: @certfile, keyfile: @keyfile, cipher_suite: :strong, port: port]
      |> Keyword.merge(options)
      |> Keyword.put(:alpn_preferred_protocols, :undefined)

    start(:https, options)
  end

  def start_https(:http2, port, options) do
    options =
      Keyword.merge(
        [certfile: @certfile, keyfile: @keyfile, cipher_suite: :strong, port: port],
        options
      )

    start(:https, options)
  end

  defp start(scheme, options) do
    options = Keyword.merge([otp_app: :mint, protocol_options: @protocol_options], options)

    children = [
      Plug.Adapters.Cowboy.child_spec(
        scheme: scheme,
        plug: Mint.CowboyTestServer.PlugRouter,
        options: options
      )
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
