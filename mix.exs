defmodule EthWallet.MixProject do
  use Mix.Project

  def project do
    [
      app: :eth_wallet,
      version: "0.1.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      description: description,
      package: package,
      deps: deps()
    ]
  end

  defp description do
    """
      a Light Eth Wallet
    """
  end

  defp package do
    [
     files: ["lib", "mix.exs", "README.md"],
     maintainers: ["Leeduckgo"],
     licenses: ["Apache 2.0"],
     links: %{"GitHub" => "",
              "Docs" => "https://hexdocs.pm/simple_statistics/"}
     ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:libsecp256k1, "~> 0.1.9"},
      # Binary
      {:binary, "~> 0.0.5"},
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:earmark, ">= 0.0.0", only: :dev}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
