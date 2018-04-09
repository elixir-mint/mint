defmodule XHTTP.Transport do
  @type state() :: term()

  @callback connect(host :: String.t(), port :: :inet.port_number(), opts :: Keyword.t()) ::
              {:ok, state()} | {:error, reason :: term()}

  @callback negotiated_protocol(state()) ::
              {:ok, protocol :: binary()} | {:error, reason :: term()}

  @callback send(state(), payload :: iodata()) :: :ok | {:error, reason :: term()}

  @callback close(state()) :: :ok | {:error, reason :: term()}

  @callback recv(state(), bytes :: non_neg_integer()) ::
              {:ok, binary()} | {:error, reason :: term()}

  @callback setopts(state(), opts :: Keyword.t()) :: :ok | {:error, reason :: term()}

  @callback getopts(state(), opts :: Keyword.t()) ::
              {:ok, Keyword.t()} | {:error, reason :: term()}

  @optional_callbacks [negotiated_protocol: 1]
end
