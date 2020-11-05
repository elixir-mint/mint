defmodule Mint.Core.Util do
  @moduledoc false

  @unallowed_trailing_headers MapSet.new([
                                "content-encoding",
                                "content-length",
                                "content-range",
                                "content-type",
                                "trailer",
                                "transfer-encoding",

                                # Control headers (https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7231.html#rfc.section.5.1)
                                "cache-control",
                                "expect",
                                "host",
                                "max-forwards",
                                "pragma",
                                "range",
                                "te",

                                # Conditionals (https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7231.html#rfc.section.5.2)
                                "if-match",
                                "if-none-match",
                                "if-modified-since",
                                "if-unmodified-since",
                                "if-range",

                                # Authentication/authorization (https://tools.ietf.org/html/rfc7235#section-5.3)
                                "authorization",
                                "proxy-authenticate",
                                "proxy-authorization",
                                "www-authenticate",

                                # Cookie management (https://tools.ietf.org/html/rfc6265)
                                "cookie",
                                "set-cookie",

                                # Control data (https://svn.tools.ietf.org/svn/wg/httpbis/specs/rfc7231.html#rfc.section.7.1)
                                "age",
                                "cache-control",
                                "expires",
                                "date",
                                "location",
                                "retry-after",
                                "vary",
                                "warning"
                              ])

  # We have to do this if/else dance inside the macro because defguard
  # is not available in Elixir 1.5, and macro expansion would raise
  # when expanding the if even if we were on Elixir 1.5. This way, we
  # only expand to the defguard code if we are on Elixir 1.10 and on
  # (which is where this macro is supported).
  defmacro define_is_connection_message_guard do
    # TODO: Remove the conditional definition when we depend on Elixir 1.10+
    # TODO: Use is_struct/2 and map.field access when we depend on Elixir 1.11+
    if Version.match?(System.version(), ">= 1.10.0") do
      quote do
        @doc since: "1.1.0"
        defguard is_connection_message(conn, message)
                 when is_map(conn) and
                        is_tuple(message) and
                        is_map_key(conn, :__struct__) and
                        is_map_key(conn, :socket) and
                        is_atom(:erlang.map_get(:__struct__, conn)) and
                        elem(message, 1) == :erlang.map_get(:socket, conn) and
                        ((elem(message, 0) in [:ssl, :tcp] and tuple_size(message) == 3) or
                           (elem(message, 0) in [:ssl_closed, :tcp_closed] and
                              tuple_size(message) == 2) or
                           (elem(message, 0) in [:ssl_error, :tcp_error] and
                              tuple_size(message) == 3))
      end
    else
      quote do
        defmacro is_connection_message(_conn, _message) do
          raise ArgumentError,
                "the is_connection_message/2 macro is only available with Elixir 1.10+"
        end
      end
    end
  end

  def hostname(opts, address) do
    case Keyword.fetch(opts, :hostname) do
      {:ok, hostname} ->
        hostname

      :error when is_binary(address) ->
        address

      :error ->
        raise ArgumentError, "the :hostname option is required when address is not a binary"
    end
  end

  def inet_opts(transport, socket) do
    with {:ok, opts} <- transport.getopts(socket, [:sndbuf, :recbuf, :buffer]),
         buffer = calculate_buffer(opts),
         :ok <- transport.setopts(socket, buffer: buffer) do
      :ok
    end
  end

  def scheme_to_transport(:http), do: Mint.Core.Transport.TCP
  def scheme_to_transport(:https), do: Mint.Core.Transport.SSL
  def scheme_to_transport(module) when is_atom(module), do: module

  defp calculate_buffer(opts) do
    Keyword.fetch!(opts, :buffer)
    |> max(Keyword.fetch!(opts, :sndbuf))
    |> max(Keyword.fetch!(opts, :recbuf))
  end

  # Adds a header to the list of headers unless it's nil or it's already there.
  def put_new_header(headers, name, value)

  def put_new_header(headers, _name, nil) do
    headers
  end

  def put_new_header(headers, name, value) do
    if List.keymember?(headers, name, 0) do
      headers
    else
      [{name, value} | headers]
    end
  end

  def put_new_header_lazy(headers, name, fun) do
    if List.keymember?(headers, name, 0) do
      headers
    else
      [{name, fun.()} | headers]
    end
  end

  # Lowercases an ASCII string more efficiently than
  # String.downcase/1.
  def downcase_ascii(string),
    do: for(<<char <- string>>, do: <<downcase_ascii_char(char)>>, into: "")

  def downcase_ascii_char(char) when char in ?A..?Z, do: char + 32
  def downcase_ascii_char(char) when char in 0..127, do: char

  # If the buffer is empty, reusing the incoming data saves
  # a potentially large allocation of memory.
  # This should be fixed in a subsequent OTP release.
  def maybe_concat(<<>>, data), do: data
  def maybe_concat(buffer, data) when is_binary(buffer), do: buffer <> data

  def find_unallowed_trailing_header(headers) do
    Enum.find(headers, fn {name, _value} -> name in @unallowed_trailing_headers end)
  end

  def remove_unallowed_trailing_headers(headers) do
    Enum.reject(headers, fn {name, _value} -> name in @unallowed_trailing_headers end)
  end
end
