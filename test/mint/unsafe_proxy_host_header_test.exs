defmodule Mint.UnsafeProxyHostHeaderTest do
  use ExUnit.Case, async: true

  alias Mint.HTTP

  # Regression for #446. When proxying over plain HTTP, the request is sent to
  # the proxy but its Host header must identify the origin server, not the proxy.
  # These tests use a local TCP server as the "proxy" and inspect the raw bytes
  # it receives, so they need no live proxy or internet connection. They live in
  # their own module (rather than in unsafe_proxy_test.exs) so they run in the
  # default suite instead of being excluded by that module's `:proxy` tag.

  test "sets the Host header to the origin, not the proxy" do
    request = proxied_request(:http, "example.com", 80, "GET", "/", [])

    # The request line still targets the absolute origin URI (proxy form)...
    assert request =~ "GET http://example.com/ HTTP/1.1"

    # ...but the Host header is the origin, not the proxy's "localhost:<port>".
    assert host_header(request) == "host: example.com"
    refute request =~ ~r/localhost:\d+/
  end

  test "keeps the origin port in the Host header when it is not the default" do
    request = proxied_request(:http, "example.com", 8080, "GET", "/", [])

    assert host_header(request) == "host: example.com:8080"
  end

  test "does not override a caller-supplied Host header" do
    request = proxied_request(:http, "example.com", 80, "GET", "/", [{"host", "other.example"}])

    assert host_header(request) == "host: other.example"
  end

  # Connects to `host:port` through a local TCP server acting as the proxy, sends
  # one request, and returns the raw bytes the proxy received.
  defp proxied_request(scheme, host, port, method, path, headers) do
    proxy_port = start_capturing_proxy()

    assert {:ok, conn} =
             HTTP.connect(scheme, host, port, proxy: {:http, "localhost", proxy_port, []})

    assert {:ok, _conn, _ref} = HTTP.request(conn, method, path, headers, nil)

    assert_receive {:proxy_request, request}, 2000
    request
  end

  # Starts a one-shot TCP server that accepts a single connection, reads the
  # request head, and forwards the raw bytes back to the test process. It owns
  # the accepted socket and does its own passive `recv`, so there is no socket
  # ownership race with the test process.
  defp start_capturing_proxy do
    test_pid = self()

    {:ok, listen_socket} =
      :gen_tcp.listen(0, mode: :binary, packet: :raw, active: false, reuseaddr: true)

    {:ok, port} = :inet.port(listen_socket)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen_socket)
      send(test_pid, {:proxy_request, recv_request_head(socket)})
      :gen_tcp.close(socket)
      :gen_tcp.close(listen_socket)
    end)

    port
  end

  defp recv_request_head(socket, acc \\ "") do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 2000)
      recv_request_head(socket, acc <> data)
    end
  end

  defp host_header(request) do
    request
    |> String.split("\r\n")
    |> Enum.find(&(&1 |> String.downcase() |> String.starts_with?("host:")))
    |> String.downcase()
  end
end
