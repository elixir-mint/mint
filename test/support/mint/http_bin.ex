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
    get_env_port("HTTPBIN_HTTP_PORT", 8080)
  end

  def https_port() do
    get_env_port("HTTPBIN_HTTPS_PORT", 8443)
  end

  def proxy_port() do
    get_env_port("TINYPROXY_PORT", 8888)
  end

  def proxy_auth_port() do
    get_env_port("TINYPROXY_AUTH_PORT", 8889)
  end

  def https_transport_opts() do
    [cacertfile: "caddy_storage/pki/authorities/local/root.crt"]
  end

  defp get_env_port(env_var, default) do
    case System.get_env(env_var) do
      nil -> default
      value -> String.to_integer(value)
    end
  end
end
