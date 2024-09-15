defmodule Mint.Core.Transport do
  @moduledoc false

  @type error() :: {:error, %Mint.TransportError{}}

  alias Mint.Types

  @callback connect(Mint.HTTP.t(), address :: Types.address(), opts :: keyword()) ::
              {:ok, Mint.HTTP.t()} | error()

  @callback upgrade(Mint.HTTP.t(), opts :: keyword()) :: {:ok, Mint.HTTP.t()} | error()

  @callback negotiated_protocol(Types.socket()) ::
              {:ok, protocol :: binary()} | {:error, :protocol_not_negotiated}

  @callback send(Types.socket(), payload :: iodata()) :: :ok | error()

  @callback close(Types.socket()) :: :ok | error()

  @callback recv(Types.socket(), bytes :: non_neg_integer(), timeout()) ::
              {:ok, binary()} | error()

  @callback controlling_process(Types.socket(), pid()) :: :ok | error()

  @callback setopts(Types.socket(), opts :: keyword()) :: :ok | error()

  @callback getopts(Types.socket(), opts :: keyword()) :: {:ok, opts :: keyword()} | error()

  @callback wrap_error(reason :: term()) :: %Mint.TransportError{}
end
