defmodule Mint.HTTP1.RequestTest do
  use ExUnit.Case, async: true

  alias Mint.HTTP1.Request

  describe "encode/5" do
    test "with header" do
      assert encode_request("GET", "/", "example.com", [{"foo", "bar"}], nil) ==
               request_string("""
               GET / HTTP/1.1
               host: example.com
               user-agent: mint/#{Mix.Project.config()[:version]}
               foo: bar

               """)
    end

    test "with body" do
      assert encode_request("GET", "/", "example.com", [], "BODY") ==
               request_string("""
               GET / HTTP/1.1
               host: example.com
               user-agent: mint/#{Mix.Project.config()[:version]}
               content-length: 4

               BODY\
               """)
    end

    test "with overridden content-length" do
      assert encode_request("GET", "/", "example.com", [{"content-length", "10"}], "BODY") ==
               request_string("""
               GET / HTTP/1.1
               host: example.com
               user-agent: mint/#{Mix.Project.config()[:version]}
               content-length: 10

               BODY\
               """)
    end

    test "with overridden user-agent" do
      assert encode_request("GET", "/", "example.com", [{"user-agent", "myapp/1.0"}], "BODY") ==
               request_string("""
               GET / HTTP/1.1
               host: example.com
               content-length: 4
               user-agent: myapp/1.0

               BODY\
               """)
    end

    test "override with non-lowercase key" do
      assert encode_request("GET", "/", "example.com", [{"User-Agent", "myapp/1.0"}], "BODY") ==
               request_string("""
               GET / HTTP/1.1
               host: example.com
               content-length: 4
               user-agent: myapp/1.0

               BODY\
               """)
    end

    test "validates request target" do
      for invalid_target <- ["/ /", "/%foo", "/foo%x"] do
        assert Request.encode("GET", invalid_target, "example.com", [], nil) ==
                 {:error, {:invalid_request_target, invalid_target}}
      end

      request = encode_request("GET", "/foo%20bar", "example.com", [], nil)
      assert String.starts_with?(request, request_string("GET /foo%20bar HTTP/1.1"))
    end

    test "invalid header name" do
      assert Request.encode("GET", "/", "example.com", [{"f oo", "bar"}], nil) ==
               {:error, {:invalid_header_name, "f oo"}}
    end

    test "invalid header value" do
      assert Request.encode("GET", "/", "example.com", [{"foo", "bar\r\n"}], nil) ==
               {:error, {:invalid_header_value, "foo", "bar\r\n"}}
    end
  end

  defp encode_request(method, target, host, headers, body) do
    assert {:ok, iodata} = Request.encode(method, target, host, headers, body)
    IO.iodata_to_binary(iodata)
  end

  defp request_string(string) do
    String.replace(string, "\n", "\r\n")
  end
end
