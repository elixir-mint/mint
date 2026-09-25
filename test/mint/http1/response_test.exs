defmodule Mint.HTTP1.ResponseTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Mint.HTTP1.Response, only: [decode_status_line: 1, decode_header: 1, decode_header: 2]

  describe "decode_status_line/1" do
    test "valid status lines" do
      assert decode_status_line("HTTP/1.1 200 OK\r\nrest") == {:ok, {{1, 1}, 200, "OK"}, "rest"}

      assert decode_status_line("HTTP/1.0 404 Not Found\r\n") ==
               {:ok, {{1, 0}, 404, "Not Found"}, ""}

      assert decode_status_line("HTTP/1.1 200 OK\nrest") == {:ok, {{1, 1}, 200, "OK"}, "rest"}
      assert decode_status_line("HTTP/1.1 204\r\n") == {:ok, {{1, 1}, 204, ""}, ""}
      assert decode_status_line("HTTP/1.1 204 \r\n") == {:ok, {{1, 1}, 204, ""}, ""}
      assert decode_status_line("HTTP/1.1 200 OK \r\n") == {:ok, {{1, 1}, 200, "OK "}, ""}
      assert decode_status_line("HTTP/1.1 200  OK\r\n") == {:ok, {{1, 1}, 200, " OK"}, ""}
      assert decode_status_line("HTTP/1.1 200 A\tB\r\n") == {:ok, {{1, 1}, 200, "A\tB"}, ""}
      assert decode_status_line("HTTP/1.1 200 caf\xE9\r\n") == {:ok, {{1, 1}, 200, "caf\xE9"}, ""}
      assert decode_status_line("HTTP/1.9 999 X\r\n") == {:ok, {{1, 9}, 999, "X"}, ""}
    end

    test "incomplete status lines" do
      for line <- ["", "H", "HTTP/1.", "HTTP/1.1 20", "HTTP/1.1 200", "HTTP/1.1 200 OK\r"] do
        assert decode_status_line(line) == :more, "expected #{inspect(line)} to need more data"
      end
    end

    test "invalid status lines" do
      lines = [
        "\r\nHTTP/1.1 200 OK\r\n",
        "HTTP/1.1 2000 OK\r\n",
        "HTTP/1.1 99 OK\r\n",
        "HTTP/1.1 099 OK\r\n",
        "HTTP/1.1 0200 OK\r\n",
        "HTTP/2.0 200 OK\r\n",
        "HTTP/0.9 200 OK\r\n",
        "HTTP/01.1 200 OK\r\n",
        "HTTP/1.01 200 OK\r\n",
        "HTTP/1.10 200 OK\r\n",
        "http/1.1 200 OK\r\n",
        "HTTP/1.1  200 OK\r\n",
        "HTTP/1.1 200OK\r\n",
        "HTTP/1.1 2x0 OK\r\n",
        "HTTP/1.1 200 O\0K\r\n",
        "HTTP/1.1 200 OK\r\r\n",
        "HTTP/1.1 200 OK\rX\r\n"
      ]

      for line <- lines do
        assert decode_status_line(line) == :error, "expected #{inspect(line)} to be rejected"
      end
    end
  end

  describe "decode_header/2" do
    test "end of the header section" do
      assert decode_header("\r\nbody") == {:ok, :eof, "body"}
      assert decode_header("\nbody") == {:ok, :eof, "body"}
    end

    test "lowercases names and trims values" do
      assert decode_header("Content-Type: text/plain\r\nX") ==
               {:ok, {"content-type", "text/plain"}, "X"}

      assert decode_header("A:   x y  \t\r\nX") == {:ok, {"a", "x y"}, "X"}
      assert decode_header("A:\r\nX") == {:ok, {"a", ""}, "X"}
      assert decode_header("A: \t \r\nX") == {:ok, {"a", ""}, "X"}

      assert decode_header("Location: http://x.y:8080/p\r\nX") ==
               {:ok, {"location", "http://x.y:8080/p"}, "X"}
    end

    test "accepts LF-only line endings" do
      assert decode_header("A: b\nX") == {:ok, {"a", "b"}, "X"}
    end

    test "replaces obsolete line folds with a space" do
      assert decode_header("A: b\r\n c\r\nX") == {:ok, {"a", "b c"}, "X"}
      assert decode_header("A: b \t\r\n\t c\nX") == {:ok, {"a", "b c"}, "X"}
      assert decode_header("A:\r\n b\r\nX") == {:ok, {"a", "b"}, "X"}
      assert decode_header("A: b\r\n \r\n c\r\nX") == {:ok, {"a", "b c"}, "X"}
    end

    test "needs the next byte to know whether a line is folded" do
      assert decode_header("A: b\r\n") == :more
      assert decode_header("A: b\r\n c\r\n") == :more
      assert decode_header("A: b\r\n", true) == {:ok, {"a", "b"}, ""}
      assert decode_header("A: b\n", true) == {:ok, {"a", "b"}, ""}
    end

    test "incomplete lines" do
      line = "Content-Type: text/plain\r\nContent-Length: 12345\r\n\r\n"

      for size <- 0..(byte_size("Content-Type: text/plain\r\n") - 1) do
        <<prefix::binary-size(^size), _::binary>> = line
        assert decode_header(prefix) == :more, "prefix #{inspect(prefix)}"
      end

      assert decode_header(line) ==
               {:ok, {"content-type", "text/plain"}, "Content-Length: 12345\r\n\r\n"}
    end

    test "names and values across word boundaries" do
      for name_size <- 1..20, value_size <- 0..20 do
        name = String.duplicate("a", name_size)
        value = String.duplicate("b", value_size)

        assert decode_header("#{name}: #{value}\r\nX") == {:ok, {name, value}, "X"}

        assert decode_header("#{name}:\t#{value}\tc\r\nX") ==
                 {:ok, {name, String.trim_leading("#{value}\tc")}, "X"}
      end
    end

    test "all tchars are allowed in names" do
      tchars = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
      assert decode_header("#{tchars}: v\r\nX") == {:ok, {String.downcase(tchars), "v"}, "X"}
    end

    test "invalid names" do
      assert decode_header(": v\r\nX") == :error
      assert decode_header(" A: v\r\nX") == :error
      assert decode_header("no colon here\r\nX") == :error

      for separator <- ~c"\"(),/;<=>?@[\\]{} \t\x01\x7F" ++ [0x80, 0xFF], position <- 0..16 do
        name = String.duplicate("a", position) <> <<separator>> <> "b"
        assert decode_header("#{name}: v\r\nX") == :error, inspect(name)
      end
    end

    test "invalid values" do
      assert decode_header("A: b\rc\r\nX") == :error

      for byte <- [0x00, 0x01, 0x0B, 0x1F, 0x7F], position <- 0..16 do
        value = String.duplicate("v", position) <> <<byte>> <> "w"
        assert decode_header("A: #{value}\r\nX") == :error, inspect(value)
      end
    end

    property "decodes generated header lines" do
      tchars = ~c"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

      vchar = one_of([integer(0x21..0x7E), integer(0x80..0xFF)])
      whitespace = string(~c" \t", max_length: 3)
      word = map(list_of(vchar, min_length: 1, max_length: 12), &:erlang.list_to_binary/1)
      line_end = member_of(["\r\n", "\n"])

      check all name <- string(tchars, min_length: 1, max_length: 24),
                lines <-
                  list_of(list_of({word, whitespace}, max_length: 4),
                    min_length: 1,
                    max_length: 3
                  ),
                leading <- whitespace,
                trailing <- whitespace,
                line_ends <- list_of(line_end, length: length(lines)),
                fold_whitespace <-
                  list_of(string(~c" \t", min_length: 1, max_length: 3), length: length(lines)) do
        segments =
          Enum.map(lines, fn words -> Enum.map_join(words, fn {w, ws} -> w <> ws end) end)

        raw =
          [segments, line_ends, fold_whitespace]
          |> Enum.zip()
          |> Enum.with_index()
          |> Enum.map_join(fn {{segment, line_end, fold}, index} ->
            prefix = if index == 0, do: "", else: fold

            prefix <>
              segment <> if(index == length(segments) - 1, do: trailing, else: "") <> line_end
          end)

        expected =
          segments
          |> Enum.map(&String.trim(&1, " "))
          |> Enum.map(&trim_ows/1)
          |> Enum.reject(&(&1 == ""))
          |> Enum.join(" ")

        assert decode_header(name <> ":" <> leading <> raw <> "X") ==
                 {:ok, {String.downcase(name), expected}, "X"}
      end
    end

    test "obs-text and HTAB are allowed in values" do
      for position <- 0..16 do
        value = "x" <> String.duplicate("v", position) <> "\t\x80\xC3\xA9\xFFw"
        assert decode_header("A: #{value}\r\nX") == {:ok, {"a", value}, "X"}
      end
    end
  end

  defp trim_ows(value) do
    value |> String.replace(~r/^[ \t]+/, "") |> String.replace(~r/[ \t]+$/, "")
  end
end
