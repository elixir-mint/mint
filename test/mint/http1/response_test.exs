defmodule Mint.HTTP1.ResponseTest do
  use ExUnit.Case, async: true

  import Mint.HTTP1.Response, only: [decode_status_line: 1]

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
end
