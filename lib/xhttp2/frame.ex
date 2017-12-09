defmodule XHTTP2.Frame do
  use Bitwise, skip_operators: true

  import Record

  shared = [:stream_id, :flags]
  defrecord :frame_data, shared ++ [:data, :padding]
  defrecord :frame_headers, shared ++ [:exclusive?, :stream_dependency, :weight, :hbf, :padding]
  defrecord :frame_priority, shared ++ [:exclusive?, :stream_dependency, :weight]
  defrecord :frame_rst_stream, shared ++ [:error_code]
  defrecord :frame_settings, shared ++ [:params]
  defrecord :frame_push_promise, shared ++ [:promised_stream_id, :hbf, :padding]
  defrecord :frame_ping, shared ++ [:opaque_data]
  defrecord :frame_goaway, shared ++ [:last_stream_id, :error_code, :debug_data]
  defrecord :frame_window_update, shared ++ [:window_size_increment]
  defrecord :frame_continuation, shared ++ [:hbf]

  defmacrop is_flag_set(flags, flag) do
    quote do
      band(unquote(flags), unquote(flag)) == unquote(flag)
    end
  end

  @types %{
    frame_data: 0x00,
    frame_headers: 0x01,
    frame_priority: 0x02,
    frame_rst_stream: 0x03,
    frame_settings: 0x04,
    frame_push_promise: 0x05,
    frame_ping: 0x06,
    frame_goaway: 0x07,
    frame_window_update: 0x08,
    frame_continuation: 0x09
  }

  ## Parsing

  def parse_next(bin) when is_binary(bin) do
    {{type, flags, stream_id, payload}, rest} = parse_next_raw(bin)
    {:ok, parse_contents(type, flags, stream_id, payload), rest}
  catch
    :throw, {:xhttp, reason} -> {:error, reason}
  end

  defp parse_next_raw(<<
         length::24,
         type,
         flags,
         _reserved::1,
         stream_id::31,
         payload::size(length)-binary,
         rest::binary
       >>) do
    {{type, flags, stream_id, payload}, rest}
  end

  defp parse_next_raw(other) do
    throw({:xhttp, {:malformed_frame, other}})
  end

  not_allowed_on_stream_0 = [
    @types[:frame_data],
    @types[:frame_headers],
    @types[:frame_priority],
    @types[:frame_rst_stream],
    @types[:frame_push_promise],
    @types[:frame_continuation]
  ]

  defp parse_contents(type, _flags, _stream_id = 0, _payload)
       when type in unquote(not_allowed_on_stream_0) do
    # TODO: use human-readable type
    throw({:xhttp, {:frame_not_allowed_on_stream_0, type}})
  end

  only_allowed_on_stream_0 = [
    @types[:frame_settings],
    @types[:frame_ping],
    @types[:frame_goaway]
  ]

  defp parse_contents(type, _flags, stream_id, _payload)
       when type in unquote(only_allowed_on_stream_0) and stream_id != 0 do
    # TODO: use human-readable type
    throw({:xhttp, {:frame_only_allowed_on_stream_0, type}})
  end

  for {frame, type} <- @types do
    function = :"parse_#{frame}"

    defp parse_contents(unquote(type), flags, stream_id, payload) do
      unquote(function)(flags, stream_id, payload)
    end
  end

  # Parsing of specific frames

  defp parse_frame_data(flags, stream_id, payload) do
    {data, padding} = parse_padding(:frame_data, flags, payload)
    frame_data(stream_id: stream_id, flags: flags, data: data, padding: padding)
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.2
  defp parse_frame_headers(flags, stream_id, payload) do
    {data, padding} = parse_padding(:frame_headers, flags, payload)

    {exclusive?, stream_dependency, weight, data} =
      if is_flag_set(flags, _priority = 0x20) do
        <<exclusive::1, stream_dependency::31, weight::8, rest::binary>> = data
        {exclusive == 1, stream_dependency, weight + 1, rest}
      else
        {nil, nil, nil, data}
      end

    frame_headers(
      stream_id: stream_id,
      flags: flags,
      padding: padding,
      exclusive?: exclusive?,
      stream_dependency: stream_dependency,
      weight: weight,
      hbf: data
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.3
  defp parse_frame_priority(_flags, _stream_id, payload) when byte_size(payload) != 5 do
    throw({:xhttp, {:bad_size, :frame_priority, byte_size(payload)}})
  end

  defp parse_frame_priority(flags, stream_id, payload) do
    <<exclusive::1, stream_dependency::31, weight::8>> = payload

    frame_priority(
      stream_id: stream_id,
      flags: flags,
      exclusive?: exclusive == 1,
      stream_dependency: stream_dependency,
      weight: weight + 1
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.4
  defp parse_frame_rst_stream(_flags, _stream_id, payload) when byte_size(payload) != 4 do
    throw({:xhttp, {:bad_size, :frame_rst_stream, byte_size(payload)}})
  end

  defp parse_frame_rst_stream(flags, stream_id, <<error_code::32>>) do
    frame_rst_stream(
      stream_id: stream_id,
      flags: flags,
      error_code: humanize_error_code(error_code)
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  defp parse_frame_settings(_flags, _stream_id, payload) when rem(byte_size(payload), 6) != 0 do
    throw({:xhttp, {:bad_size, :frame_settings, byte_size(payload)}})
  end

  defp parse_frame_settings(flags, _stream_id = 0, payload) do
    frame_settings(stream_id: 0, flags: flags, params: parse_settings_params(payload))
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.6
  defp parse_frame_push_promise(flags, stream_id, payload) do
    {data, padding} = parse_padding(:frame_push_promise, flags, payload)
    <<_reserved::1, promised_stream_id::31, header_block_fragment::binary>> = data

    frame_push_promise(
      stream_id: stream_id,
      flags: flags,
      promised_stream_id: promised_stream_id,
      hbf: header_block_fragment,
      padding: padding
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.7
  defp parse_frame_ping(_flags, _stream_id, payload) when byte_size(payload) != 8 do
    throw({:xhttp, {:bad_size, :frame_ping, byte_size(payload)}})
  end

  defp parse_frame_ping(flags, 0, payload) do
    frame_ping(stream_id: 0, flags: flags, opaque_data: payload)
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.8
  defp parse_frame_goaway(flags, stream_id, payload) do
    <<_reserved::1, last_stream_id::31, error_code::32, debug_data::binary>> = payload

    frame_goaway(
      stream_id: stream_id,
      flags: flags,
      last_stream_id: last_stream_id,
      error_code: humanize_error_code(error_code),
      debug_data: debug_data
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.9
  defp parse_frame_window_update(_flags, _stream_id, payload) when byte_size(payload) != 4 do
    throw({:xhttp, {:bad_size, :frame_window_update, byte_size(payload)}})
  end

  defp parse_frame_window_update(_flags, _stream_id, <<_reserved::1, 0::31>>) do
    throw({:xhttp, {:bad_window_size_increment, :frame_window_update, 0}})
  end

  defp parse_frame_window_update(flags, stream_id, <<_reserved::1, window_size_increment::31>>) do
    frame_window_update(
      stream_id: stream_id,
      flags: flags,
      window_size_increment: window_size_increment
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.10
  defp parse_frame_continuation(flags, stream_id, payload) do
    frame_continuation(stream_id: stream_id, flags: flags, hbf: payload)
  end

  defp parse_padding(frame, flags, <<pad_length, rest::binary>> = payload)
       when is_flag_set(flags, 0x08) do
    if pad_length >= byte_size(payload) do
      throw({:xhttp, {:pad_length_bigger_than_payload_length, frame}})
    else
      # 1 byte is for the space taken by pad_length
      data_length = byte_size(payload) - pad_length - 1
      <<data::size(data_length)-binary, padding::size(pad_length)-binary>> = rest
      {data, padding}
    end
  end

  defp parse_padding(_frame, _flags, payload) do
    {payload, nil}
  end

  defp parse_settings_params(payload) do
    parse_settings_params(payload, _acc = [])
  end

  defp parse_settings_params(<<>>, acc), do: Enum.reverse(acc)

  defp parse_settings_params(<<identifier::16, value::32, rest::binary>>, acc),
    do: parse_settings_params(rest, [parse_settings_param(identifier, value) | acc])

  defp parse_settings_param(0x01, value), do: {:header_table_size, value}
  defp parse_settings_param(0x02, value), do: {:enable_push, value == 1}
  defp parse_settings_param(0x03, value), do: {:max_concurrent_streams, value}
  defp parse_settings_param(0x04, value), do: {:initial_window_size, value}
  defp parse_settings_param(0x05, value), do: {:max_frame_size, value}
  defp parse_settings_param(0x06, value), do: {:max_header_list_size, value}

  ## Encoding

  def pack(frame)

  # TODO: implement padding
  def pack(frame_data(stream_id: stream_id, flags: flags, data: data, padding: nil)) do
    pack_raw(@types[:frame_data], flags, stream_id, data)
  end

  def pack(
        frame_headers(
          flags: flags,
          stream_id: stream_id,
          exclusive?: exclusive?,
          stream_dependency: stream_dependency,
          weight: weight,
          hbf: hbf,
          padding: nil
        )
      ) do
    pack_raw(@types[:frame_headers], flags, stream_id, hbf)
  end

  def pack(frame_priority() = frame) do
    frame_priority(
      stream_id: stream_id,
      flags: flags,
      exclusive?: exclusive?,
      stream_dependency: stream_dependency,
      weight: weight
    ) = frame

    payload = [
      <<if(exclusive?, do: 1, else: 0)::1, stream_dependency::31>>,
      weight - 1
    ]

    pack_raw(@types[:frame_priority], flags, stream_id, payload)
  end

  def pack(frame_rst_stream(stream_id: stream_id, flags: flags, error_code: error_code)) do
    payload = <<dehumanize_error_code(error_code)::32>>
    pack_raw(@types[:frame_rst_stream], flags, stream_id, payload)
  end

  # TODO: pack actual settings
  def pack(frame_settings(stream_id: stream_id, flags: flags, params: [])) do
    payload = <<>>
    pack_raw(@types[:frame_settings], flags, stream_id, payload)
  end

  def pack(frame_ping(stream_id: 0, flags: flags, opaque_data: opaque_data)) do
    pack_raw(@types[:frame_ping], flags, 0, opaque_data)
  end

  def pack(frame_goaway() = frame) do
    frame_goaway(
      stream_id: 0,
      flags: flags,
      last_stream_id: last_stream_id,
      error_code: error_code,
      debug_data: debug_data
    ) = frame

    payload = [<<0::1, last_stream_id::31, dehumanize_error_code(error_code)::32>>, debug_data]
    pack_raw(@types[:frame_goaway], flags, 0, payload)
  end

  def pack(frame_window_update(stream_id: stream_id, flags: flags, window_size_increment: wsi)) do
    payload = <<0::1, wsi::31>>
    pack_raw(@types[:frame_window_update], flags, stream_id, payload)
  end

  def pack(frame_continuation(stream_id: stream_id, flags: flags, hbf: hbf)) do
    pack_raw(@types[:frame_continuation], flags, stream_id, _payload = hbf)
  end

  def pack_raw(type, flags, stream_id, payload) do
    [<<IO.iodata_length(payload)::24>>, type, flags, <<0::1, stream_id::31>>, payload]
  end

  ## Helpers

  error_codes = %{
    0x00 => :no_error,
    0x01 => :protocol_error,
    0x02 => :internal_error,
    0x03 => :flow_control_error,
    0x04 => :settings_timeout,
    0x05 => :stream_closed,
    0x06 => :frame_size_error,
    0x07 => :refused_stream,
    0x08 => :cancel,
    0x09 => :compression_error,
    0x0A => :connect_error,
    0x0B => :enhance_your_calm,
    0x0C => :inadequate_security,
    0x0D => :http_1_1_required
  }

  for {code, human_code} <- error_codes do
    defp humanize_error_code(unquote(code)), do: unquote(human_code)
    defp dehumanize_error_code(unquote(human_code)), do: unquote(code)
  end
end
