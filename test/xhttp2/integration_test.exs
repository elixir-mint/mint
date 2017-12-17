defmodule XHTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  alias XHTTP2.Conn

  @moduletag :integration

  describe "http2.golang.org" do
    test "connecting" do
      assert {:ok, %Conn{} = conn} = Conn.connect("http2.golang.org", 443, settings: [])
      assert Conn.open?(conn)
      settings = Conn.read_server_settings(conn)
      max_concurrent_streams = Keyword.fetch!(settings, :max_concurrent_streams)
      assert is_integer(max_concurrent_streams) and max_concurrent_streams >= 0
    end
  end
end
