defmodule MimeSniff.MixProject do
  use Mix.Project

  @source_url "https://github.com/cchaiyatad/mime_sniff"
  @version "0.1.0"

  def project do
    [
      app: :mime_sniff,
      version: @version,
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      dialyzer: dialyzer(),
      description: description(),
      package: package(),
      docs: docs()
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
      {:benchee, "~> 1.1", [only: [:dev]]},
      {:credo, "~> 1.6", [only: [:dev, :test], runtime: false]},
      {:dialyxir, "~> 1.1", [only: [:dev, :test], runtime: false]},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      bench: ["run support/benchmark.exs"]
    ]
  end

  defp description() do
    """
    A MIME Type detection by magic number in Elixir.
    """
  end

  defp package() do
    [
      maintainers: ["Chaiyatad Chanasuppakul"],
      licenses: ["MIT License"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs() do
    [
      main: "readme",
      name: "mime_sniff",
      source_ref: "v#{@version}",
      canonical: "http://hexdocs.pm/mime_sniff",
      source_url: @source_url,
      extras: ["README.md", "docs/support_types.md", "LICENSE.md"]
    ]
  end
end
