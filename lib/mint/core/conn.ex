defmodule Mint.Core.Conn do
  @moduledoc false

  @type conn() :: term()

  @type request_ref() :: reference()
  @type socket_message() ::
          {:tcp | :ssl, :gen_tcp.sockeconn(), binary()}
          | {:tcp_closed | :ssl_closed, :gen_tcp.sockeconn()}
          | {:tcp_error | :ssl_error, :gen_tcp.sockeconn(), term()}
  @type response() ::
          {:status, request_ref(), status()}
          | {:headers, request_ref(), headers()}
          | {:data, request_ref(), binary()}
          | {:done, request_ref()}
          | {:pong, request_ref()}
          | {:error, request_ref(), term()}
  @type status() :: non_neg_integer()
  @type reason() :: String.t()
  @type headers() :: [{String.t(), String.t()}]

  # @callback close(conn()) :: :ok
  #
  # @callback shutdown(conn(), :read | :write | :read_write) :: :ok | {:error, term()}

  @callback initiate(
              module(),
              Mint.Core.Transport.socket(),
              String.t(),
              :inet.port_number(),
              keyword()
            ) :: {:ok, conn()} | {:error, term()}

  @callback open?(conn()) :: boolean()

  @callback request(
              conn(),
              String.t(),
              String.t(),
              headers(),
              iodata() | nil | :stream
            ) ::
              {:ok, conn(), request_ref()}
              | {:error, conn(), term()}

  @callback stream_request_body(conn(), request_ref(), iodata() | :eof) ::
              {:ok, conn()} | {:error, conn(), term()}

  @callback stream(conn(), socket_message()) ::
              {:ok, conn(), [response()]}
              | {:error, conn(), term(), [response()]}
              | :unknown

  @callback put_private(conn(), atom(), term()) :: conn()

  @callback get_private(conn(), atom(), term()) :: term()

  @callback delete_private(conn(), atom()) :: conn()

  @callback get_socket(conn()) :: Mint.Core.Transport.socket()
end
