defmodule MimeSniff.MixProject do
  use Mix.Project

  def project do
    [
      app: :mime_sniff,
      version: "0.1.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: dialyzer()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp dialyzer do
    [
      plt_core_path: "priv/plts",
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.6", [only: [:dev, :test], runtime: false]},
      {:dialyxir, "~> 1.1", [only: [:dev, :test], runtime: false]}
    ]
  end
end
