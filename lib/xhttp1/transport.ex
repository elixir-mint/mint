defmodule XHTTP1.Transport do
  @callback connect(hostname :: charlist(), :inet.port_number(), opts :: Keyword.t()) ::
              {:ok, socket :: term()} | {:error, reason :: term()}

  @callback getopts(socket :: term(), option_names :: [atom()]) ::
              {:ok, opts :: Keyword.t()} | {:error, reason :: term()}

  @callback setopts(socket :: term(), opts :: Keyword.t()) :: :ok | {:error, reason :: term()}

  @callback close(socket :: term()) :: :ok

  @callback send(socket :: term(), packet :: iodata()) :: :ok | {:error, reason :: term()}

  @callback message_tags() :: {ok_tag :: atom(), error_tag :: atom(), close_tag :: atom()}
end
