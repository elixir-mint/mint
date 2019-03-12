defmodule Mint.HTTP1.ParseTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.Parse

  test "content_length_header/1" do
    assert content_length_header("0") == 0
    assert content_length_header("100") == 100
    assert content_length_header("200  ") == 200

    assert catch_throw(content_length_header("foo")) == {:mint, :invalid_content_length_header}
    assert catch_throw(content_length_header("-10")) == {:mint, :invalid_content_length_header}
  end

  test "connection_header/1" do
    assert connection_header("close") == ["close"]
    assert connection_header("Keep-Alive") == ["keep-alive"]
    assert connection_header("keep-alive, Upgrade") == ["keep-alive", "upgrade"]

    assert catch_throw(connection_header("\n")) == {:mint, :invalid_token_list}
  end

  test "token_list/1" do
    assert token_list("") == []
    assert token_list("foo") == ["foo"]
    assert token_list("foo, bar") == ["foo", "bar"]
    assert token_list("foo,bAr") == ["foo", "bAr"]
    assert token_list(",, , ,   ,") == []
    assert token_list("   ,  ,,,  foo  , ,  ") == ["foo"]

    assert catch_throw(token_list("\n")) == {:mint, :invalid_token_list}
  end

  test "token_list_downcase/1" do
    assert token_list_downcase("") == []
    assert token_list_downcase("foo") == ["foo"]
    assert token_list_downcase("foo, bar") == ["foo", "bar"]
    assert token_list_downcase("FOO,bAr") == ["foo", "bar"]
    assert token_list_downcase(",, , ,   ,") == []
    assert token_list_downcase("   ,  ,,,  foo  , ,  ") == ["foo"]

    assert catch_throw(token_list_downcase("\n")) == {:mint, :invalid_token_list}
  end
end
