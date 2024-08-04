defmodule Mint.HttpBin do
  def host() do
    "localhost"
  end

  def proxy_host() do
    # the proxy runs in docker so we use the
    # docker compose name to connect
    "caddyhttpbin"
  end

  def http_port() do
    8080
  end

  def https_port() do
    8443
  end

  def https_transport_opts() do
    [cacertfile: "caddy_storage/pki/authorities/local/root.crt"]
  end
end
