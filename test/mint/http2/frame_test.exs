defmodule Mint.HTTP2.FrameTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  use Bitwise, skip_operators: true

  import Mint.HTTP2.Frame, except: [decode_next: 1, encode_raw: 4]

  alias Mint.HTTP2.{
    Frame,
    HPACK
  }

  test "set_flags/2" do
    assert set_flags(:ping, [:ack]) == 0x01
    assert set_flags(:data, [:end_stream]) == 0x01
    assert_raise FunctionClauseError, fn -> set_flags(:data, [:ack]) end
  end

  test "set_flags/3" do
    assert set_flags(0x01, :data, [:padded]) == bor(0x01, 0x08)
    assert_raise FunctionClauseError, fn -> set_flags(0x00, :data, [:ack]) end
  end

  test "flag_set?/3" do
    assert flag_set?(0x08, :data, :padded) == true
    assert flag_set?(0x00, :data, :padded) == false
    assert_raise FunctionClauseError, fn -> flag_set?(0x00, :data, :ack) end
  end

  test "decode_next/1 with an incomplete frame" do
    assert Frame.decode_next(<<>>) == :more
  end

  describe "DATA" do
    test "without padding" do
      check all stream_id <- non_zero_stream_id(),
                data <- binary() do
        assert_round_trip data(stream_id: stream_id, flags: 0x00, data: data, padding: nil)
      end
    end

    test "with padding" do
      check all stream_id <- non_zero_stream_id(),
                data <- binary(),
                padding <- binary() do
        assert_round_trip data(stream_id: stream_id, flags: 0x08, data: data, padding: padding)
      end
    end

    test "with bad padding" do
      # "payload" is 4 bytes, the pad length is >= 5 bytes
      payload = <<5::8, "data">>
      debug_data = "the padding length of a :data frame is bigger than the payload length"

      assert Frame.decode_next(encode_raw(0x00, 0x08, 3, payload)) ==
               {:error, {:protocol_error, debug_data}}
    end
  end

  describe "HEADERS" do
    test "with meaningful hbf" do
      headers = [{"foo", "bar"}, {"baz", "bong"}, {"foo", "badung"}]

      {encoded_headers, _} =
        headers
        |> Enum.map(fn {name, value} -> {:no_store, name, value} end)
        |> HPACK.encode(HPACK.new(100_000))

      assert {:ok, headers(stream_id: 3, flags: 0x00, hbf: hbf, padding: nil), "rest"} =
               Frame.decode_next(encode_raw(0x01, 0x00, 3, encoded_headers) <> "rest")

      assert {:ok, ^headers, _} = HPACK.decode(hbf, HPACK.new(100_000))
    end

    test "without padding and without priority" do
      check all stream_id <- non_zero_stream_id(),
                hbf <- binary() do
        assert_round_trip headers(
                            stream_id: stream_id,
                            flags: 0x00,
                            exclusive?: nil,
                            stream_dependency: nil,
                            weight: nil,
                            hbf: hbf,
                            padding: nil
                          )
      end
    end

    test "with padding and priority" do
      check all stream_id <- non_zero_stream_id(),
                hbf <- binary(),
                padding <- binary() do
        assert_round_trip headers(
                            stream_id: stream_id,
                            flags: bor(0x08, 0x20),
                            exclusive?: true,
                            stream_dependency: 19,
                            weight: 10,
                            hbf: hbf,
                            padding: padding
                          )
      end
    end
  end

  describe "PRIORITY" do
    test "regular" do
      check all stream_id <- non_zero_stream_id(),
                stream_dependency <- non_zero_stream_id(),
                weight <- positive_integer() do
        assert_round_trip priority(
                            stream_id: stream_id,
                            exclusive?: true,
                            stream_dependency: stream_dependency,
                            weight: weight,
                            flags: 0x00
                          )
      end
    end

    test "with bad length" do
      assert Frame.decode_next(encode_raw(0x02, 0x00, 3, "")) ==
               {:error, {:frame_size_error, :priority}}
    end
  end

  describe "RST_STREAM" do
    test "regular" do
      check all stream_id <- non_zero_stream_id(),
                error_code <- error_code() do
        assert_round_trip rst_stream(
                            stream_id: stream_id,
                            flags: 0x00,
                            error_code: error_code
                          )
      end
    end

    test "with bad length" do
      assert Frame.decode_next(encode_raw(0x03, 0x00, 3, <<3::8>>)) ==
               {:error, {:frame_size_error, :rst_stream}}
    end
  end

  describe "SETTINGS" do
    test "with empty settings" do
      assert_round_trip settings(stream_id: 0, flags: 0x00, params: [])
    end

    test "with parameters" do
      check all header_table_size <- positive_integer(),
                enable_push <- boolean(),
                max_concurrent_streams <- non_negative_integer(),
                initial_window_size <- positive_integer(),
                max_frame_size <- positive_integer(),
                max_header_list_size <- positive_integer() do
        params = [
          header_table_size: header_table_size,
          enable_push: enable_push,
          max_concurrent_streams: max_concurrent_streams,
          initial_window_size: initial_window_size,
          max_frame_size: max_frame_size,
          max_header_list_size: max_header_list_size
        ]

        assert_round_trip settings(stream_id: 0, flags: 0x01, params: params)
      end
    end

    test "with bad length" do
      assert Frame.decode_next(encode_raw(0x04, 0x00, 0, <<_not_multiple_of_6 = 3::8>>)) ==
               {:error, {:frame_size_error, :settings}}
    end
  end

  describe "PUSH_PROMISE" do
    test "without padding" do
      check all stream_id <- non_zero_stream_id(),
                promised_stream_id <- non_zero_stream_id(),
                hbf <- binary() do
        assert_round_trip push_promise(
                            stream_id: stream_id,
                            flags: 0x00,
                            promised_stream_id: promised_stream_id,
                            hbf: hbf,
                            padding: nil
                          )
      end
    end

    test "with padding" do
      check all stream_id <- non_zero_stream_id(),
                promised_stream_id <- non_zero_stream_id(),
                hbf <- binary(),
                padding <- binary() do
        assert_round_trip push_promise(
                            stream_id: stream_id,
                            flags: 0x08,
                            promised_stream_id: promised_stream_id,
                            hbf: hbf,
                            padding: padding
                          )
      end
    end
  end

  describe "PING" do
    test "regular" do
      check all opaque_data <- binary(length: 8) do
        assert_round_trip ping(stream_id: 0, flags: 0x01, opaque_data: opaque_data)
      end
    end

    test "with bad length" do
      assert Frame.decode_next(encode_raw(0x06, 0x00, 0, <<_not_multiple_of_6 = 3::8>>)) ==
               {:error, {:frame_size_error, :ping}}
    end
  end

  describe "GOAWAY" do
    test "regular" do
      check all last_stream_id <- non_zero_stream_id(),
                error_code <- error_code(),
                debug_data <- binary() do
        assert_round_trip goaway(
                            stream_id: 0,
                            flags: 0x00,
                            last_stream_id: last_stream_id,
                            error_code: error_code,
                            debug_data: debug_data
                          )
      end
    end
  end

  describe "WINDOW_UPDATE" do
    test "regular" do
      check all stream_id <- one_of([constant(0), non_zero_stream_id()]),
                wsi <- positive_integer() do
        assert_round_trip window_update(
                            stream_id: stream_id,
                            flags: 0x00,
                            window_size_increment: wsi
                          )
      end
    end

    test "invalid window size increment" do
      assert Frame.decode_next(encode_raw(0x08, 0x00, 0, <<0::1, 0::31>>)) ==
               {:error, {:protocol_error, "bad WINDOW_SIZE increment"}}
    end

    test "with bad length" do
      assert Frame.decode_next(encode_raw(0x08, 0x00, 0, <<>>)) ==
               {:error, {:frame_size_error, :window_update}}
    end
  end

  describe "CONTINUATION" do
    test "regular" do
      check all stream_id <- non_zero_stream_id(),
                hbf <- binary() do
        assert_round_trip continuation(stream_id: stream_id, flags: 0x00, hbf: hbf)
      end
    end
  end

  defp assert_round_trip(frame) do
    encoded = frame |> Frame.encode() |> IO.iodata_to_binary()
    assert Frame.decode_next(encoded <> "rest") == {:ok, frame, "rest"}
  end

  defp encode_raw(type, flags, stream_id, payload) do
    IO.iodata_to_binary(Frame.encode_raw(type, flags, stream_id, payload))
  end

  defp non_zero_stream_id() do
    map(positive_integer(), &(&1 * 2 + 1))
  end

  defp non_negative_integer() do
    map(integer(), &abs/1)
  end

  defp error_code() do
    member_of([
      :no_error,
      :protocol_error,
      :internal_error,
      :flow_control_error,
      :settings_timeout,
      :stream_closed,
      :frame_size_error,
      :refused_stream,
      :cancel,
      :compression_error,
      :connect_error,
      :enhance_your_calm,
      :inadequate_security,
      :http_1_1_required
    ])
  end
end
