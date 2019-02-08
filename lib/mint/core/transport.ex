defmodule Mint.Core.Transport do
  @type socket() :: term()
  @type error() :: {:error, reason :: term()}

  @callback connect(host :: String.t(), port :: :inet.port_number(), opts :: keyword()) ::
              {:ok, socket()} | error()

  @callback upgrade(
              socket(),
              old_transport :: module(),
              hostname :: String.t(),
              :inet.port_number(),
              opts :: keyword()
            ) :: {:ok, {module(), socket()}} | error()

  @callback negotiated_protocol(socket()) ::
              {:ok, protocol :: binary()} | {:error, :protocol_not_negotiated}

  @callback send(socket(), payload :: iodata()) :: :ok | error()

  @callback close(socket()) :: :ok | error()

  @callback recv(socket(), bytes :: non_neg_integer()) :: {:ok, binary()} | error()

  @callback setopts(socket(), opts :: keyword()) :: :ok | error()

  @callback getopts(socket(), opts :: keyword()) :: {:ok, opts :: keyword()} | error()
end
