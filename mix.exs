defmodule Mint.MixProject do
  use Mix.Project

  @version "0.1.0"
  @repo_url "https://github.com/ericmj/mint"

  def project do
    [
      app: :mint,
      version: @version,
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),

      # Hex
      package: package(),
      description: "Small and composable HTTP client.",

      # Docs
      name: "Mint",
      docs: [
        source_ref: "v#{@version}",
        source_url: @repo_url,
        extras: ["pages/Architecture.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp package do
    [
      licenses: ["Apache 2.0"],
      links: %{"GitHub" => @repo_url}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:castore, "~> 0.1.0"},
      {:ex_doc, "~> 0.19.3", only: :dev},
      {:hpack, ">= 0.0.0", hex: :hpack_erl, only: :test},
      {:stream_data, "~> 0.4.0", only: :test}
    ]
  end
end
