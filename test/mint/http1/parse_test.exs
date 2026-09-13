defmodule Mint.HTTP1.ParseTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Mint.HTTP1.Parse

  test "chunk_size/1" do
    assert chunk_size("0\r\n") == {:ok, 0, "\r\n"}
    assert chunk_size("aF;extension\r\n") == {:ok, 175, ";extension\r\n"}
    assert chunk_size("2;meta\r\n") == {:ok, 2, ";meta\r\n"}
    assert chunk_size("F") == :more

    assert chunk_size("+5\r\n") == :error
    assert chunk_size("+0\r\n") == :error
    assert chunk_size("-0\r\n") == :error
    assert chunk_size("") == :error
  end

  test "chunk_size/1 limits the size to 16 hexadecimal digits" do
    max_chunk_size = String.duplicate("F", 16)

    assert chunk_size(max_chunk_size <> "\r\n") ==
             {:ok, 0xFFFFFFFFFFFFFFFF, "\r\n"}

    assert chunk_size(max_chunk_size) == :more
    assert chunk_size("0" <> max_chunk_size) == :error
  end

  describe "chunk_extensions/1" do
    test "accepts extensions and leaves bytes after CRLF unconsumed" do
      for extensions <- [
            "",
            ";name",
            ";name=value",
            ";name=\"\"",
            ";name=\"a;\\\"b\\\\c\"",
            ";name=\"\t ![]~\x80\xFF\"",
            ";name=\"\\\t\\ \\!\\\x80\\\xFF\"",
            ";!#$%&'*+-.^_`|~=!#$%&'*+-.^_`|~",
            " \t; \tname \t= \tvalue \t; \tflag;other=\"value\""
          ] do
        line = extensions <> "\r\n"
        assert chunk_extensions(line <> "body") == {:ok, "body"}

        for length <- 0..(byte_size(line) - 1) do
          assert chunk_extensions(binary_part(line, 0, length)) == :more
        end
      end
    end

    test "rejects malformed extensions" do
      for extensions <- [
            "ZZZZZ",
            " anything at all",
            "\tfoo",
            " 9",
            "}~!",
            " ",
            ";",
            "; ",
            ";=value",
            ";name=",
            ";name= ",
            ";name ",
            ";name=value ",
            ";name=\"value\" ",
            ";name;;other",
            ";name,other",
            ";name=value extra",
            ";name=\"unterminated",
            ";name=\"value\"extra",
            ";name=\"value\"=extra",
            ";name=\"bad\x00value\"",
            ";name=\"bad\x7Fvalue\"",
            ";name=\"bad\\\nvalue\"",
            ";name=\"bad\\\rvalue\"",
            ";name=\"bad\\\x00value\"",
            ";name=\"bad\\\x7Fvalue\"",
            ";name=\x80",
            ";\x80=value",
            "\nignored",
            "\rignored"
          ] do
        assert chunk_extensions(extensions <> "\r\n") == :error,
               "accepted malformed extensions: #{inspect(extensions)}"
      end
    end

    test "rejects invalid bytes without waiting for CRLF" do
      for extensions <- ["Z", " f", ";=", ";name=\"\n", ";name=\"\\\n", "\rX"] do
        assert chunk_extensions(extensions) == :error
      end
    end
  end

  test "content_length_header/1" do
    assert content_length_header("0") == {:ok, 0}
    assert content_length_header("100") == {:ok, 100}
    assert content_length_header("200  ") == {:ok, 200}
    assert content_length_header("200\t") == {:ok, 200}
    assert content_length_header("200 \t ") == {:ok, 200}

    assert content_length_header("200\v") ==
             {:error, {:invalid_content_length_header, "200\v"}}

    assert content_length_header("200\f") ==
             {:error, {:invalid_content_length_header, "200\f"}}

    assert content_length_header("200\u00A0") ==
             {:error, {:invalid_content_length_header, "200\u00A0"}}

    assert content_length_header("200\u0085") ==
             {:error, {:invalid_content_length_header, "200\u0085"}}

    assert content_length_header("200\u3000") ==
             {:error, {:invalid_content_length_header, "200\u3000"}}

    assert content_length_header("foo") ==
             {:error, {:invalid_content_length_header, "foo"}}

    assert content_length_header("-10") ==
             {:error, {:invalid_content_length_header, "-10"}}

    assert content_length_header("+0") ==
             {:error, {:invalid_content_length_header, "+0"}}

    assert content_length_header("+123") ==
             {:error, {:invalid_content_length_header, "+123"}}

    assert content_length_header("") ==
             {:error, {:invalid_content_length_header, ""}}

    assert content_length_header("  100") ==
             {:error, {:invalid_content_length_header, "  100"}}

    assert content_length_header("1 0") ==
             {:error, {:invalid_content_length_header, "1 0"}}

    assert content_length_header("0x10") ==
             {:error, {:invalid_content_length_header, "0x10"}}
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
      no_tokens_generator = string([?\s, ?\t, ?,])

      check all string <- no_tokens_generator, max_runs: 25 do
        assert token_list_downcase(string) == {:ok, []}
      end
    end

    property "parses lists of tokens and downcases them" do
      whitespace_generator = string([?\s, ?\t])

      check all tokens <- list_of(string(:alphanumeric, min_length: 1)),
                whitespace <- whitespace_generator,
                string = Enum.join(tokens, whitespace <> "," <> whitespace),
                max_runs: 30 do
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
