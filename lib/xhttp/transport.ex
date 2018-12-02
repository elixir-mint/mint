defmodule XHTTP.Transport do
  @type state() :: term()
  @type error() :: {:error, reason :: term()}

  @callback connect(host :: String.t(), port :: :inet.port_number(), opts :: keyword()) ::
              {:ok, state()} | error()

  @callback upgrade(
              state(),
              old_transport :: module(),
              hostname :: String.t(),
              port :: non_neg_integer(),
              opts :: keyword()
            ) :: {:ok, {module(), state()}} | error()

  @callback negotiated_protocol(state()) ::
              {:ok, protocol :: binary()} | {:error, :protocol_not_negotiated}

  @callback send(state(), payload :: iodata()) :: {:ok, state()} | error()

  @callback close(state()) :: {:ok, state()} | error()

  @callback recv(state(), bytes :: non_neg_integer()) :: {:ok, binary(), state()} | error()

  @callback setopts(state(), opts :: keyword()) :: :ok | error()

  @callback getopts(state(), opts :: keyword()) :: {:ok, opts :: keyword()} | error()

  @callback socket(state()) :: port()
end
