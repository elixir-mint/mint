defmodule XHTTP2.Frame do
  use Bitwise, skip_operators: true

  import Record

  shared_stream = [:stream_id, {:flags, 0x00}]
  shared_conn = [stream_id: 0, flags: 0x00]

  defrecord :data, shared_stream ++ [:data, :padding]
  defrecord :headers, shared_stream ++ [:exclusive?, :stream_dependency, :weight, :hbf, :padding]
  defrecord :priority, shared_stream ++ [:exclusive?, :stream_dependency, :weight]
  defrecord :rst_stream, shared_stream ++ [:error_code]
  defrecord :settings, shared_conn ++ [:params]
  defrecord :push_promise, shared_stream ++ [:promised_stream_id, :hbf, :padding]
  defrecord :ping, shared_conn ++ [:opaque_data]
  defrecord :goaway, shared_conn ++ [:last_stream_id, :error_code, :debug_data]
  defrecord :window_update, shared_stream ++ [:window_size_increment]
  defrecord :continuation, shared_stream ++ [:hbf]

  @types %{
    data: 0x00,
    headers: 0x01,
    priority: 0x02,
    rst_stream: 0x03,
    settings: 0x04,
    push_promise: 0x05,
    ping: 0x06,
    goaway: 0x07,
    window_update: 0x08,
    continuation: 0x09
  }

  ## Flag handling

  @flags %{
    data: [end_stream: 0x01, padded: 0x08],
    headers: [end_stream: 0x01, end_headers: 0x04, padded: 0x08, priority: 0x20],
    settings: [ack: 0x01],
    push_promise: [end_headers: 0x04, padded: 0x08],
    ping: [ack: 0x01],
    continuation: [end_headers: 0x04]
  }

  @doc """
  Sets the flag specified by `flag_name` on the given `flags`.

  `flags` is an integer. `frame_name` should be the name of the frame
  `flags` belong to (used for ensuring `flag_name`) belongs to that frame.
  """
  @spec set_flag(byte(), :data, :end_stream | :padded) :: byte()
  @spec set_flag(byte(), :settings, :ack) :: byte()
  @spec set_flag(byte(), :push_promise, :end_headers | :padded) :: byte()
  @spec set_flag(byte(), :ping, :ack) :: byte()
  @spec set_flag(byte(), :continuation, :end_headers) :: byte()
  @spec set_flag(byte(), :headers, :end_stream | :end_headers | :padded | :priority) :: byte()
  def set_flag(flags, frame_name, flag_name)

  @spec set_flag(:data, :end_stream | :padded) :: byte()
  @spec set_flag(:settings, :ack) :: byte()
  @spec set_flag(:push_promise, :end_headers | :padded) :: byte()
  @spec set_flag(:ping, :ack) :: byte()
  @spec set_flag(:continuation, :end_headers) :: byte()
  @spec set_flag(:headers, :end_stream | :end_headers | :padded | :priority) :: byte()
  def set_flag(frame_name, flag_name)

  @spec flag_set?(byte(), :data, :end_stream | :padded) :: boolean()
  @spec flag_set?(byte(), :settings, :ack) :: boolean()
  @spec flag_set?(byte(), :push_promise, :end_headers | :padded) :: boolean()
  @spec flag_set?(byte(), :ping, :ack) :: boolean()
  @spec flag_set?(byte(), :continuation, :end_headers) :: boolean()
  @spec flag_set?(byte(), :headers, :end_stream | :end_headers | :padded | :priority) :: boolean()
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

  def set_flags(initial_flags, frame_name, flags_to_set)
      when is_integer(initial_flags) and is_list(flags_to_set) do
    Enum.reduce(flags_to_set, initial_flags, &set_flag(&2, frame_name, &1))
  end

  def set_flags(frame_name, flags_to_set) do
    set_flags(0x00, frame_name, flags_to_set)
  end

  ## Parsing

  @doc """
  Decodes the next frame of the given binary.

  Returns `{:ok, frame, rest}` if successful, `{:error, reason}` if not.
  """
  @spec decode_next(binary()) :: {:ok, tuple(), binary()} | :more | {:error, reason}
        when reason:
               {:frame_size_error, atom()}
               | {:protocol_error, term()}
               | :payload_too_big
  def decode_next(bin, max_frame_size \\ 16_384) when is_binary(bin) do
    case decode_next_raw(bin) do
      {:ok, {type, flags, stream_id, payload}, rest} ->
        if byte_size(payload) > max_frame_size do
          {:error, :payload_too_big}
        else
          {:ok, decode_contents(type, flags, stream_id, payload), rest}
        end

      :more ->
        :more
    end
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
    {:ok, {type, flags, stream_id, payload}, rest}
  end

  defp decode_next_raw(_other) do
    :more
  end

  for {frame, type} <- @types do
    function = :"decode_#{frame}"

    defp decode_contents(unquote(type), flags, stream_id, payload) do
      unquote(function)(flags, stream_id, payload)
    end
  end

  # Parsing of specific frames

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.1
  defp decode_data(flags, stream_id, payload) do
    {data, padding} = decode_padding(:data, flags, payload)
    data(stream_id: stream_id, flags: flags, data: data, padding: padding)
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.2
  defp decode_headers(flags, stream_id, payload) do
    {data, padding} = decode_padding(:headers, flags, payload)

    {exclusive?, stream_dependency, weight, data} =
      if flag_set?(flags, :headers, :priority) do
        <<exclusive::1, stream_dependency::31, weight::8, rest::binary>> = data
        {exclusive == 1, stream_dependency, weight + 1, rest}
      else
        {nil, nil, nil, data}
      end

    headers(
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
  defp decode_priority(_flags, _stream_id, payload) when byte_size(payload) != 5 do
    throw({:xhttp, {:frame_size_error, :priority}})
  end

  defp decode_priority(flags, stream_id, payload) do
    <<exclusive::1, stream_dependency::31, weight::8>> = payload

    priority(
      stream_id: stream_id,
      flags: flags,
      exclusive?: exclusive == 1,
      stream_dependency: stream_dependency,
      weight: weight + 1
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.4
  defp decode_rst_stream(_flags, _stream_id, payload) when byte_size(payload) != 4 do
    throw({:xhttp, {:frame_size_error, :rst_stream}})
  end

  defp decode_rst_stream(flags, stream_id, <<error_code::32>>) do
    rst_stream(
      stream_id: stream_id,
      flags: flags,
      error_code: humanize_error_code(error_code)
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.5
  defp decode_settings(_flags, _stream_id, payload) when rem(byte_size(payload), 6) != 0 do
    throw({:xhttp, {:frame_size_error, :settings}})
  end

  defp decode_settings(flags, stream_id, payload) do
    settings(stream_id: stream_id, flags: flags, params: decode_settings_params(payload))
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.6
  defp decode_push_promise(flags, stream_id, payload) do
    {data, padding} = decode_padding(:push_promise, flags, payload)
    <<_reserved::1, promised_stream_id::31, header_block_fragment::binary>> = data

    push_promise(
      stream_id: stream_id,
      flags: flags,
      promised_stream_id: promised_stream_id,
      hbf: header_block_fragment,
      padding: padding
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.7
  defp decode_ping(_flags, _stream_id, payload) when byte_size(payload) != 8 do
    throw({:xhttp, {:frame_size_error, :ping}})
  end

  defp decode_ping(flags, stream_id, payload) do
    ping(stream_id: stream_id, flags: flags, opaque_data: payload)
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.8
  defp decode_goaway(flags, stream_id, payload) do
    <<_reserved::1, last_stream_id::31, error_code::32, debug_data::binary>> = payload

    goaway(
      stream_id: stream_id,
      flags: flags,
      last_stream_id: last_stream_id,
      error_code: humanize_error_code(error_code),
      debug_data: debug_data
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.9
  defp decode_window_update(_flags, _stream_id, payload) when byte_size(payload) != 4 do
    throw({:xhttp, {:frame_size_error, :window_update}})
  end

  defp decode_window_update(_flags, _stream_id, <<_reserved::1, 0::31>>) do
    throw({:xhttp, {:protocol_error, :bad_window_size_increment}})
  end

  defp decode_window_update(flags, stream_id, <<_reserved::1, window_size_increment::31>>) do
    window_update(
      stream_id: stream_id,
      flags: flags,
      window_size_increment: window_size_increment
    )
  end

  # http://httpwg.org/specs/rfc7540.html#rfc.section.6.10
  defp decode_continuation(flags, stream_id, payload) do
    continuation(stream_id: stream_id, flags: flags, hbf: payload)
  end

  defp decode_padding(frame, flags, <<pad_length, rest::binary>> = payload)
       when is_flag_set(flags, unquote(@flags[:data][:padded])) do
    if pad_length >= byte_size(payload) do
      throw({:xhttp, {:protocol_error, {:pad_length_bigger_than_payload_length, frame}}})
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

  def encode(data(stream_id: stream_id, flags: flags, data: data, padding: nil)) do
    encode_raw(@types[:data], flags, stream_id, data)
  end

  def encode(data(stream_id: stream_id, flags: flags, data: data, padding: padding)) do
    flags = set_flag(flags, :data, :padded)
    payload = [byte_size(padding), data, padding]
    encode_raw(@types[:data], flags, stream_id, payload)
  end

  def encode(headers() = frame) do
    headers(
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
          set_flag(flags, :headers, :priority)
        }
      else
        {payload, flags}
      end

    {payload, flags} =
      if padding do
        {[byte_size(padding), payload, padding], set_flag(flags, :headers, :padded)}
      else
        {payload, flags}
      end

    encode_raw(@types[:headers], flags, stream_id, payload)
  end

  def encode(priority() = frame) do
    priority(
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

    encode_raw(@types[:priority], flags, stream_id, payload)
  end

  def encode(rst_stream(stream_id: stream_id, flags: flags, error_code: error_code)) do
    payload = <<dehumanize_error_code(error_code)::32>>
    encode_raw(@types[:rst_stream], flags, stream_id, payload)
  end

  def encode(settings(stream_id: stream_id, flags: flags, params: params)) do
    payload =
      Enum.map(params, fn
        {:header_table_size, value} -> <<0x01::16, value::32>>
        {:enable_push, value} -> <<0x02::16, if(value, do: 1, else: 0)::32>>
        {:max_concurrent_streams, value} -> <<0x03::16, value::32>>
        {:initial_window_size, value} -> <<0x04::16, value::32>>
        {:max_frame_size, value} -> <<0x05::16, value::32>>
        {:max_header_list_size, value} -> <<0x06::16, value::32>>
      end)

    encode_raw(@types[:settings], flags, stream_id, payload)
  end

  def encode(push_promise() = frame) do
    push_promise(
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
          set_flag(flags, :push_promise, :padded)
        }
      else
        {payload, flags}
      end

    encode_raw(@types[:push_promise], flags, stream_id, payload)
  end

  def encode(ping(stream_id: 0, flags: flags, opaque_data: opaque_data)) do
    encode_raw(@types[:ping], flags, 0, opaque_data)
  end

  def encode(goaway() = frame) do
    goaway(
      stream_id: 0,
      flags: flags,
      last_stream_id: last_stream_id,
      error_code: error_code,
      debug_data: debug_data
    ) = frame

    payload = [<<0::1, last_stream_id::31, dehumanize_error_code(error_code)::32>>, debug_data]
    encode_raw(@types[:goaway], flags, 0, payload)
  end

  def encode(window_update(stream_id: stream_id, flags: flags, window_size_increment: wsi)) do
    payload = <<0::1, wsi::31>>
    encode_raw(@types[:window_update], flags, stream_id, payload)
  end

  def encode(continuation(stream_id: stream_id, flags: flags, hbf: hbf)) do
    encode_raw(@types[:continuation], flags, stream_id, _payload = hbf)
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
