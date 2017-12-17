defmodule XHTTP2.Frame do
  use Bitwise, skip_operators: true

  import Record

  shared = [:stream_id, {:flags, 0x00}]
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

  ## Flag handling

  @flags %{
    frame_data: [end_stream: 0x01, padded: 0x08],
    frame_headers: [end_stream: 0x01, end_headers: 0x04, padded: 0x08, priority: 0x20],
    frame_settings: [ack: 0x01],
    frame_push_promise: [end_headers: 0x04, padded: 0x08],
    frame_ping: [ack: 0x01],
    frame_continuation: [end_headers: 0x04]
  }

  @doc """
  Sets the flag specified by `flag_name` on the given `flags`.

  `flags` is an integer. `frame_name` should be the name of the frame
  `flags` belong to (used for ensuring `flag_name`) belongs to that frame.
  """
  @spec set_flag(byte(), :frame_data, :end_stream | :padded) :: byte()
  @spec set_flag(byte(), :frame_settings, :ack) :: byte()
  @spec set_flag(byte(), :frame_push_promise, :end_headers | :padded) :: byte()
  @spec set_flag(byte(), :frame_ping, :ack) :: byte()
  @spec set_flag(byte(), :frame_continuation, :end_headers) :: byte()
  @spec set_flag(byte(), :frame_headers, :end_stream | :end_headers | :padded | :priority) ::
          byte()
  def set_flag(flags, frame_name, flag_name)

  @spec set_flag(:frame_data, :end_stream | :padded) :: byte()
  @spec set_flag(:frame_settings, :ack) :: byte()
  @spec set_flag(:frame_push_promise, :end_headers | :padded) :: byte()
  @spec set_flag(:frame_ping, :ack) :: byte()
  @spec set_flag(:frame_continuation, :end_headers) :: byte()
  @spec set_flag(:frame_headers, :end_stream | :end_headers | :padded | :priority) :: byte()
  def set_flag(frame_name, flag_name)

  @spec flag_set?(byte(), :frame_data, :end_stream | :padded) :: boolean()
  @spec flag_set?(byte(), :frame_settings, :ack) :: boolean()
  @spec flag_set?(byte(), :frame_push_promise, :end_headers | :padded) :: boolean()
  @spec flag_set?(byte(), :frame_ping, :ack) :: boolean()
  @spec flag_set?(byte(), :frame_continuation, :end_headers) :: boolean()
  @spec flag_set?(byte(), :frame_headers, :end_stream | :end_headers | :padded | :priority) ::
          boolean()
  def flag_set?(flags, frame_name, flag_name)

  for {frame, flags} <- @flags,
      {flag_name, flag_value} <- flags do
    def set_flag(flags, unquote(frame), unquote(flag_name)), do: bor(flags, unquote(flag_value))
    def set_flag(unquote(frame), unquote(flag_name)), do: unquote(flag_value)

    def flag_set?(flags, unquote(frame), unquote(flag_name)),
      do: band(flags, unquote(flag_value)) == unquote(flag_value)
  end

  defmacrop is_flag_set(flags, flag) do
    quote do
      band(unquote(flags), unquote(flag)) == unquote(flag)
    end
  end

  ## Parsing

  @doc """
  Decodes the next frame of the given binary.

  Returns `{:ok, frame, rest}` if successful, `{:error, reason}` if not.
  """
  @spec decode_next(binary()) :: {:ok, tuple(), binary()} | {:error, term()}
  def decode_next(bin) when is_binary(bin) do
    {{type, flags, stream_id, payload}, rest} = decode_next_raw(bin)
    {:ok, decode_contents(type, flags, stream_id, payload), rest}
  catch
    :throw, {:xhttp, reason} -> {:error, reason}
  end

  defp decode_next_raw(<<
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

  defp decode_next_raw(other) do
    throw({:xhttp, {:malformed_frame, other}})
  end

  not_allowed_on_stream_0 = [
    :frame_data,
    :frame_headers,
    :frame_priority,
    :frame_rst_stream,
    :frame_push_promise,
    :frame_continuation
  ]

  for {frame, type} <- Map.take(@types, not_allowed_on_stream_0) do
    defp decode_contents(unquote(type), _flags, _stream_id = 0, _payload) do
      throw({:xhttp, {:frame_not_allowed_on_stream_0, unquote(frame)}})
    end
  end

  only_allowed_on_stream_0 = [
    :frame_settings,
    :frame_ping,
    :frame_goaway
  ]

  for {frame, type} <- Map.take(@types, only_allowed_on_stream_0) do
    defp decode_contents(unquote(type), _flags, stream_id, _payload) when stream_id != 0 do
      throw({:xhttp, {:frame_only_allowed_on_stream_0, unquote(frame)}})
    end
  end

  for {frame, type} <- @types do
    function = :"decode_#{frame}"

    defp decode_contents(unquote(type), flags, stream_id, payload) do
      unquote(function)(flags, stream_id, payload)
    end
  end

  # Parsing of specific frames

  defp decode_frame_data(flags, stream_id, payload) do
    {data, padding} = decode_padding(:frame_data, flags, payload)
    frame_data(stream_id: stream_id, flags: flags, data: data, padding: padding)
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.2
  defp decode_frame_headers(flags, stream_id, payload) do
    {data, padding} = decode_padding(:frame_headers, flags, payload)

    {exclusive?, stream_dependency, weight, data} =
      if flag_set?(flags, :frame_headers, :priority) do
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
  defp decode_frame_priority(_flags, _stream_id, payload) when byte_size(payload) != 5 do
    throw({:xhttp, {:bad_size, :frame_priority, byte_size(payload)}})
  end

  defp decode_frame_priority(flags, stream_id, payload) do
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
  defp decode_frame_rst_stream(_flags, _stream_id, payload) when byte_size(payload) != 4 do
    throw({:xhttp, {:bad_size, :frame_rst_stream, byte_size(payload)}})
  end

  defp decode_frame_rst_stream(flags, stream_id, <<error_code::32>>) do
    frame_rst_stream(
      stream_id: stream_id,
      flags: flags,
      error_code: humanize_error_code(error_code)
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  defp decode_frame_settings(_flags, _stream_id, payload) when rem(byte_size(payload), 6) != 0 do
    throw({:xhttp, {:bad_size, :frame_settings, byte_size(payload)}})
  end

  defp decode_frame_settings(flags, _stream_id = 0, payload) do
    frame_settings(stream_id: 0, flags: flags, params: decode_settings_params(payload))
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.6
  defp decode_frame_push_promise(flags, stream_id, payload) do
    {data, padding} = decode_padding(:frame_push_promise, flags, payload)
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
  defp decode_frame_ping(_flags, _stream_id, payload) when byte_size(payload) != 8 do
    throw({:xhttp, {:bad_size, :frame_ping, byte_size(payload)}})
  end

  defp decode_frame_ping(flags, 0, payload) do
    frame_ping(stream_id: 0, flags: flags, opaque_data: payload)
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.8
  defp decode_frame_goaway(flags, stream_id, payload) do
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
  defp decode_frame_window_update(_flags, _stream_id, payload) when byte_size(payload) != 4 do
    throw({:xhttp, {:bad_size, :frame_window_update, byte_size(payload)}})
  end

  defp decode_frame_window_update(_flags, _stream_id, <<_reserved::1, 0::31>>) do
    throw({:xhttp, {:bad_window_size_increment, :frame_window_update, 0}})
  end

  defp decode_frame_window_update(flags, stream_id, <<_reserved::1, window_size_increment::31>>) do
    frame_window_update(
      stream_id: stream_id,
      flags: flags,
      window_size_increment: window_size_increment
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.10
  defp decode_frame_continuation(flags, stream_id, payload) do
    frame_continuation(stream_id: stream_id, flags: flags, hbf: payload)
  end

  defp decode_padding(frame, flags, <<pad_length, rest::binary>> = payload)
       when is_flag_set(flags, unquote(@flags[:frame_data][:padded])) do
    if pad_length >= byte_size(payload) do
      throw({:xhttp, {:pad_length_bigger_than_payload_length, frame}})
    else
      # 1 byte is for the space taken by pad_length
      data_length = byte_size(payload) - pad_length - 1
      <<data::size(data_length)-binary, padding::size(pad_length)-binary>> = rest
      {data, padding}
    end
  end

  defp decode_padding(_frame, _flags, payload) do
    {payload, nil}
  end

  defp decode_settings_params(payload) do
    decode_settings_params(payload, _acc = [])
  end

  defp decode_settings_params(<<>>, acc), do: Enum.reverse(acc)

  defp decode_settings_params(<<identifier::16, value::32, rest::binary>>, acc),
    do: decode_settings_params(rest, [decode_settings_param(identifier, value) | acc])

  defp decode_settings_param(0x01, value), do: {:header_table_size, value}
  defp decode_settings_param(0x02, value), do: {:enable_push, value == 1}
  defp decode_settings_param(0x03, value), do: {:max_concurrent_streams, value}
  defp decode_settings_param(0x04, value), do: {:initial_window_size, value}
  defp decode_settings_param(0x05, value), do: {:max_frame_size, value}
  defp decode_settings_param(0x06, value), do: {:max_header_list_size, value}

  ## Encoding

  @doc """
  Encodes the given `frame`.
  """
  @spec encode(tuple()) :: iodata()
  def encode(frame)

  def encode(frame_data(stream_id: stream_id, flags: flags, data: data, padding: nil)) do
    encode_raw(@types[:frame_data], flags, stream_id, data)
  end

  def encode(frame_data(stream_id: stream_id, flags: flags, data: data, padding: padding)) do
    flags = set_flag(flags, :frame_data, :padded)
    payload = [byte_size(padding), data, padding]
    encode_raw(@types[:frame_data], flags, stream_id, payload)
  end

  def encode(frame_headers() = frame) do
    frame_headers(
      flags: flags,
      stream_id: stream_id,
      exclusive?: exclusive?,
      stream_dependency: stream_dependency,
      weight: weight,
      hbf: hbf,
      padding: padding
    ) = frame

    payload = hbf

    {payload, flags} =
      if stream_dependency && weight && is_boolean(exclusive?) do
        {
          [<<if(exclusive?, do: 1, else: 0)::1, stream_dependency::31>>, weight - 1, payload],
          set_flag(flags, :frame_headers, :priority)
        }
      else
        {payload, flags}
      end

    {payload, flags} =
      if padding do
        {[byte_size(padding), payload, padding], set_flag(flags, :frame_headers, :padded)}
      else
        {payload, flags}
      end

    encode_raw(@types[:frame_headers], flags, stream_id, payload)
  end

  def encode(frame_priority() = frame) do
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

    encode_raw(@types[:frame_priority], flags, stream_id, payload)
  end

  def encode(frame_rst_stream(stream_id: stream_id, flags: flags, error_code: error_code)) do
    payload = <<dehumanize_error_code(error_code)::32>>
    encode_raw(@types[:frame_rst_stream], flags, stream_id, payload)
  end

  def encode(frame_settings(stream_id: stream_id, flags: flags, params: params)) do
    payload =
      Enum.map(params, fn
        {:header_table_size, value} -> <<0x01::16, value::32>>
        {:enable_push, value} -> <<0x02::16, if(value, do: 1, else: 0)::32>>
        {:max_concurrent_streams, value} -> <<0x03::16, value::32>>
        {:initial_window_size, value} -> <<0x04::16, value::32>>
        {:max_frame_size, value} -> <<0x05::16, value::32>>
        {:max_header_list_size, value} -> <<0x06::16, value::32>>
      end)

    encode_raw(@types[:frame_settings], flags, stream_id, payload)
  end

  def encode(frame_push_promise() = frame) do
    frame_push_promise(
      stream_id: stream_id,
      flags: flags,
      promised_stream_id: promised_stream_id,
      hbf: hbf,
      padding: padding
    ) = frame

    payload = [<<0::1, promised_stream_id::31>>, hbf]

    {payload, flags} =
      if padding do
        {
          [byte_size(padding), payload, padding],
          set_flag(flags, :frame_push_promise, :padded)
        }
      else
        {payload, flags}
      end

    encode_raw(@types[:frame_push_promise], flags, stream_id, payload)
  end

  def encode(frame_ping(stream_id: 0, flags: flags, opaque_data: opaque_data)) do
    encode_raw(@types[:frame_ping], flags, 0, opaque_data)
  end

  def encode(frame_goaway() = frame) do
    frame_goaway(
      stream_id: 0,
      flags: flags,
      last_stream_id: last_stream_id,
      error_code: error_code,
      debug_data: debug_data
    ) = frame

    payload = [<<0::1, last_stream_id::31, dehumanize_error_code(error_code)::32>>, debug_data]
    encode_raw(@types[:frame_goaway], flags, 0, payload)
  end

  def encode(frame_window_update(stream_id: stream_id, flags: flags, window_size_increment: wsi)) do
    payload = <<0::1, wsi::31>>
    encode_raw(@types[:frame_window_update], flags, stream_id, payload)
  end

  def encode(frame_continuation(stream_id: stream_id, flags: flags, hbf: hbf)) do
    encode_raw(@types[:frame_continuation], flags, stream_id, _payload = hbf)
  end

  def encode_raw(type, flags, stream_id, payload) do
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
