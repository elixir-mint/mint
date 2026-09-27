defmodule Mint.HTTP1.RequestTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Mint.HTTP1.Request

  describe "encode/5" do
    test "with header" do
      assert encode_request("GET", "/", [{"foo", "bar"}], nil) ==
               request_string("""
               GET / HTTP/1.1
               foo: bar

               """)
    end

    test "with body" do
      assert encode_request("GET", "/", [], "BODY") ==
               request_string("""
               GET / HTTP/1.1

               BODY\
               """)
    end

    test "with body and headers" do
      assert encode_request("POST", "/some-url", [{"foo", "bar"}], "hello!") ==
               request_string("""
               POST /some-url HTTP/1.1
               foo: bar

               hello!\
               """)
    end

    test "invalid header name" do
      assert Request.encode("GET", "/", [{"f oo", "bar"}], nil) ==
               {:error, {:invalid_header_name, "f oo"}}
    end

    test "invalid header value" do
      assert Request.encode("GET", "/", [{"foo", "bar\r\n"}], nil) ==
               {:error, {:invalid_header_value, "foo", "bar\r\n"}}
    end

    test "method with CRLF is rejected" do
      method = "GET / HTTP/1.1\r\nX-Smuggled: 1\r\nGET /admin"

      assert Request.encode(method, "/", [], nil) ==
               {:error, {:invalid_request_method, method}}
    end

    test "method with a space is rejected" do
      assert Request.encode("GET /admin", "/", [], nil) ==
               {:error, {:invalid_request_method, "GET /admin"}}
    end

    test "method with a control character is rejected" do
      assert Request.encode("GET\t", "/", [], nil) ==
               {:error, {:invalid_request_method, "GET\t"}}
    end

    test "custom token method is accepted" do
      assert encode_request("PROPFIND", "/", [], nil) ==
               request_string("""
               PROPFIND / HTTP/1.1

               """)
    end
  end

  describe "encode_chunk/1" do
    test ":eof" do
      assert IO.iodata_to_binary(Request.encode_chunk(:eof)) == "0\r\n\r\n"
    end

    test "iodata" do
      iodata = "foo"
      assert IO.iodata_to_binary(Request.encode_chunk(iodata)) == "3\r\nfoo\r\n"

      iodata = ["hello ", ?w, [["or"], ?l], ?d]
      assert IO.iodata_to_binary(Request.encode_chunk(iodata)) == "B\r\nhello world\r\n"
    end

    property "encoded chunk always contains at least two CRLFs" do
      check all iodata <- iodata() do
        encoded = iodata |> Request.encode_chunk() |> IO.iodata_to_binary()
        assert String.ends_with?(encoded, "\r\n")
        assert encoded |> String.replace_suffix("\r\n", "") |> String.contains?("\r\n")
      end
    end
  end

  defp encode_request(method, target, headers, body) do
    assert {:ok, iodata} = Request.encode(method, target, headers, body)
    IO.iodata_to_binary(iodata)
  end

  defp request_string(string) do
    String.replace(string, "\n", "\r\n")
  end
end
