defmodule Mint.HTTP1.ParseTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Mint.HTTP1.Parse

  test "content_length_header/1" do
    assert content_length_header("0") == {:ok, 0}
    assert content_length_header("100") == {:ok, 100}
    assert content_length_header("200  ") == {:ok, 200}

    assert content_length_header("foo") ==
             {:error, {:invalid_content_length_header, "foo"}}

    assert content_length_header("-10") ==
             {:error, {:invalid_content_length_header, "-10"}}
  end

  test "connection_header/1" do
    assert connection_header("close") == {:ok, ["close"]}
    assert connection_header("close  ") == {:ok, ["close"]}
    assert connection_header("Keep-Alive") == {:ok, ["keep-alive"]}
    assert connection_header("keep-alive, Upgrade") == {:ok, ["keep-alive", "upgrade"]}
    assert connection_header("keep-alive,  Upgrade  ") == {:ok, ["keep-alive", "upgrade"]}

    assert connection_header("\n") == {:error, {:invalid_token_list, "\n"}}
    assert connection_header("") == {:error, :empty_token_list}
  end

  test "transfer_encoding_header/1" do
    assert transfer_encoding_header("deflate") == {:ok, ["deflate"]}
    assert transfer_encoding_header("deflate  ") == {:ok, ["deflate"]}
    assert transfer_encoding_header("gzip, Chunked") == {:ok, ["gzip", "chunked"]}
    assert transfer_encoding_header("gzip,   Chunked  ") == {:ok, ["gzip", "chunked"]}

    assert transfer_encoding_header("\n") == {:error, {:invalid_token_list, "\n"}}
    assert transfer_encoding_header("") == {:error, :empty_token_list}
  end

  describe "token_list_downcase/1" do
    property "returns an empty list if there's no token" do
      check all string <- string([?\s, ?\t, ?,]) do
        assert token_list_downcase(string) == {:ok, []}
      end
    end

    property "parses lists of tokens and downcases them" do
      check all tokens <- list_of(string(:alphanumeric, min_length: 1)),
                whitespace <- string([?\s, ?\t]),
                string = Enum.join(tokens, whitespace <> "," <> whitespace) do
        assert token_list_downcase(string) == {:ok, Enum.map(tokens, &String.downcase/1)}
      end
    end

    test "parses practical examples" do
      assert token_list_downcase("foo") == {:ok, ["foo"]}
      assert token_list_downcase("foo, bar") == {:ok, ["foo", "bar"]}
      assert token_list_downcase("FOO,bAr") == {:ok, ["foo", "bar"]}
      assert token_list_downcase("   ,  ,,,  foo  , ,  ") == {:ok, ["foo"]}
    end

    test "throws {:mint, :invalid_token_list} for invalid tokens" do
      assert token_list_downcase("\n") == :error
    end
  end
end
