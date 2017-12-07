defmodule XHTTP2.FrameTest do
  use ExUnit.Case, async: true

  use Bitwise, skip_operators: true

  import XHTTP2.Frame, except: [parse_next: 1, pack_raw: 4]

  alias XHTTP2.{
    Frame,
    HPACK
  }

  @headers [{"foo", "bar"}, {"baz", "bong"}, {"foo", "badung"}]

  describe "DATA" do
    test "without padding" do
      assert_round_trip frame_data(
                          stream_id: 3,
                          flags: 0x00,
                          data: "foo",
                          padding: nil
                        )
    end

    @tag skip: "packing not implemented"
    test "with padding" do
      assert_round_trip frame_data(
                          stream_id: 3,
                          flags: 0x08,
                          data: "foo",
                          padding: "pad"
                        )
    end

    test "with bad padding" do
      # "payload" is 4 bytes, the pad length is >= 5 bytes
      payload = <<5::8, "data">>

      assert Frame.parse_next(pack_raw(0x00, 0x08, 3, payload)) ==
               {:error, {:pad_length_bigger_than_payload_length, :frame_data}}
    end

    test "with bad stream id" do
      # TODO: use :frame_data not 0
      assert Frame.parse_next(pack_raw(0x00, 0x00, 0, "")) ==
               {:error, {:frame_not_allowed_on_stream_0, 0}}
    end
  end

  describe "HEADERS" do
    test "without padding" do
      {encoded_headers, _} =
        @headers
        |> Enum.map(fn {name, value} -> {:no_store, name, value} end)
        |> HPACK.encode(HPACK.new(100_000))

      assert frame_headers(stream_id: 3, flags: 0x00, hbf: hbf, padding: nil) =
               parse_next(pack_raw(0x01, 0x00, 3, encoded_headers))

      assert {:ok, @headers, _} = HPACK.decode(hbf, HPACK.new(100_000))
    end

    test "with padding" do
      {encoded_headers, _} =
        @headers
        |> Enum.map(fn {name, value} -> {:no_store, name, value} end)
        |> HPACK.encode(HPACK.new(100_000))

      assert frame_headers(stream_id: 3, flags: 0x08, hbf: hbf, padding: "pad") =
               parse_next(pack_raw(0x01, 0x08, 3, [3, encoded_headers, "pad"]))

      assert {:ok, @headers, _} = HPACK.decode(hbf, HPACK.new(100_000))
    end

    test "with padding and priority" do
      {encoded_headers, _} =
        @headers
        |> Enum.map(fn {name, value} -> {:no_store, name, value} end)
        |> HPACK.encode(HPACK.new(100_000))

      flags = bor(0x08, 0x20)

      payload = [3, <<1::1, 8::31>>, 0, encoded_headers, "pad"]

      assert frame_headers(
               stream_id: 3,
               flags: ^flags,
               hbf: hbf,
               padding: "pad",
               exclusive?: true,
               stream_dependency: 8,
               weight: 1
             ) = parse_next(pack_raw(0x01, flags, 3, payload))

      assert {:ok, @headers, _} = HPACK.decode(hbf, HPACK.new(100_000))
    end

    test "with bad stream id" do
      # TODO: use :frame_headers not 0x01
      assert Frame.parse_next(pack_raw(0x01, 0x00, 0, "")) ==
               {:error, {:frame_not_allowed_on_stream_0, 0x01}}
    end
  end

  describe "PRIORITY" do
    test "regular" do
      assert_round_trip frame_priority(
                          stream_id: 3,
                          exclusive?: true,
                          stream_dependency: 5,
                          weight: 11,
                          flags: 0x00
                        )
    end

    test "with bad length" do
      assert Frame.parse_next(pack_raw(0x02, 0x00, 3, "")) ==
               {:error, {:bad_size, :frame_priority, 0}}
    end

    test "with bad stream id" do
      # TODO: use :frame_priority not 0x02
      assert Frame.parse_next(pack_raw(0x02, 0x00, 0, <<_5_bytes = 0::40>>)) ==
               {:error, {:frame_not_allowed_on_stream_0, 0x02}}
    end
  end

  describe "RST_STREAM" do
    test "regular" do
      assert_round_trip frame_rst_stream(
                          stream_id: 3,
                          flags: 0x00,
                          error_code: :flow_control_error
                        )
    end

    test "with bad stream id" do
      # TODO: use :frame_rst_stream not 0x03
      assert Frame.parse_next(pack_raw(0x03, 0x00, 0, <<_5_bytes = 0::40>>)) ==
               {:error, {:frame_not_allowed_on_stream_0, 0x03}}
    end

    test "with bad length" do
      assert Frame.parse_next(pack_raw(0x03, 0x00, 3, <<3::8>>)) ==
               {:error, {:bad_size, :frame_rst_stream, 1}}
    end
  end

  describe "SETTINGS" do
    test "with empty settings" do
      assert_round_trip frame_settings(
                          stream_id: 0,
                          flags: 0x00,
                          params: []
                        )
    end

    @tag skip: "multiple parameters not supported yet in encoding"
    test "with parameters" do
      assert_round_trip frame_settings(
                          stream_id: 0,
                          flags: 0x01,
                          params: [
                            header_table_size: 10,
                            enable_push: false,
                            max_concurrent_streams: 250
                          ]
                        )
    end

    test "with bad stream id" do
      # TODO: use :frame_settings not 0x03
      assert Frame.parse_next(pack_raw(0x04, 0x00, 3, "")) ==
               {:error, {:frame_only_allowed_on_stream_0, 0x04}}
    end

    test "with bad length" do
      assert Frame.parse_next(pack_raw(0x04, 0x00, 0, <<_not_multiple_of_6 = 3::8>>)) ==
               {:error, {:bad_size, :frame_settings, 1}}
    end
  end

  describe "PUSH_PROMISE" do
    @describetag skip: "packing not implemented yet"

    test "without padding" do
      # assert_round_trip(%Frame.PushPromise{
      #   stream_id: 3,
      #   flags: 0x00,
      #   promised_stream_id: 5,
      #   header_block_fragment: "some header block fragment",
      #   padding: nil
      # })
    end

    test "with padding" do
      # assert_round_trip(%Frame.PushPromise{
      #   stream_id: 3,
      #   flags: 0x00,
      #   promised_stream_id: 5,
      #   header_block_fragment: "some header block fragment",
      #   padding: "some padding"
      # })
    end

    test "with bad stream id" do
      # assert Frame.parse_next(Frame.pack_raw(0x05, 0x00, 0, "")) ==
      #          {:error, %ProtocolError{frame: 0x05, reason: :frame_not_allowed_on_stream_0}}
    end
  end

  describe "PING" do
    test "regular" do
      assert_round_trip frame_ping(
                          stream_id: 0,
                          flags: 0x01,
                          opaque_data: "8 bytes!"
                        )
    end

    test "with bad stream id" do
      # TODO: use :frame_ping not 0x06
      assert Frame.parse_next(pack_raw(0x06, 0x00, 3, "")) ==
               {:error, {:frame_only_allowed_on_stream_0, 0x06}}
    end

    test "with bad length" do
      assert Frame.parse_next(pack_raw(0x06, 0x00, 0, <<_not_multiple_of_6 = 3::8>>)) ==
               {:error, {:bad_size, :frame_ping, 1}}
    end
  end

  describe "GOAWAY" do
    @describetag skip: "packing not implemented yet"

    test "regular" do
      # assert_round_trip(%Frame.Goaway{
      #   stream_id: 0,
      #   flags: 0x00,
      #   last_stream_id: 1000,
      #   error_code: :enhance_your_calm,
      #   debug_data: "some debug data"
      # })
    end

    test "with bad stream id" do
      # assert Frame.parse_next(Frame.pack_raw(0x07, 0x00, 3, "")) ==
      #          {:error, %ProtocolError{frame: 0x07, reason: :frame_only_allowed_on_stream_0}}
    end
  end

  describe "WINDOW_UPDATE" do
    test "on connection-level (stream 0)" do
      assert_round_trip frame_window_update(
                          stream_id: 0,
                          flags: 0x00,
                          window_size_increment: 10
                        )
    end

    test "on stream-level (stream non-0)" do
      assert_round_trip frame_window_update(
                          stream_id: 3,
                          flags: 0x00,
                          window_size_increment: 10
                        )
    end

    test "invalid window size increment" do
      assert Frame.parse_next(pack_raw(0x08, 0x00, 0, <<0::1, 0::31>>)) ==
               {:error, {:bad_window_size_increment, :frame_window_update, 0}}
    end

    test "with bad length" do
      assert Frame.parse_next(pack_raw(0x08, 0x00, 0, <<>>)) ==
               {:error, {:bad_size, :frame_window_update, 0}}
    end
  end

  describe "CONTINUATION" do
    @describetag skip: "packing not implemented yet"

    test "regular" do
      # {:ok, {hbf, _context}} = :hpack.encode(@headers, :hpack.new_context())
      #
      # assert_round_trip(%Frame.Continuation{
      #   flags: 0x00,
      #   stream_id: 3,
      #   header_block_fragment: hbf
      # })
    end

    test "with bad stream id" do
      # assert Frame.parse_next(Frame.pack_raw(0x09, 0x00, 0, "")) ==
      #          {:error, %ProtocolError{frame: 0x06, reason: :frame_not_allowed_on_stream_0}}
    end
  end

  defp assert_round_trip(frame) do
    assert frame |> Frame.pack() |> IO.iodata_to_binary() |> parse_next() == frame
  end

  defp pack_raw(type, flags, stream_id, payload) do
    IO.iodata_to_binary(Frame.pack_raw(type, flags, stream_id, payload))
  end

  defp parse_next(frame) do
    {:ok, parsed_frame, "rest"} = Frame.parse_next(frame <> "rest")
    parsed_frame
  end
end
