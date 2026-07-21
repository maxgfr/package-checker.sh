defmodule ElixirProject.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixir_project,
      version: "0.1.0",
      elixir: "~> 1.15",
      description: "Test fixture demonstrating hex (Elixir/Erlang) lockfile scanning.",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:paginator, "~> 1.2"},
      {:sweet_xml, "~> 0.6"},
      {:telemetry, "~> 1.2"},
      {:internal_auth, git: "https://github.com/example-org/internal_auth.git"}
    ]
  end
end
