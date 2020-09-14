defmodule Mint.Application do
  use Application

  def start(_type, _args) do
    Application.put_env(:mint, :persistent_term, Code.ensure_loaded?(:persistent_term))

    opts = [strategy: :one_for_one, name: Mint.Supervisor]
    Supervisor.start_link([], opts)
  end
end
