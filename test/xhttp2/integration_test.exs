defmodule XHTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  alias XHTTP2.Conn

  @moduletag :integration

  describe "http2.golang.org" do
    test "connecting" do
      assert {:ok, %Conn{} = conn} = Conn.connect("http2.golang.org", 443, settings: [])
      assert Conn.open?(conn)
      IO.inspect(conn)
    end
  end
end
