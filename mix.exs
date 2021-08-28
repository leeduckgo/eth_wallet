defmodule EthWallet.MixProject do
  use Mix.Project

  def project do
    [
      app: :eth_wallet,
      version: "0.0.8",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  defp description() do
    """
      a Light Eth Wallet.
    """
  end

  defp package() do
    [
     files: ["lib", "mix.exs", "README.md"],
     maintainers: ["Leeduckgo"],
     licenses: ["Apache 2.0"],
     links: %{"GitHub" => "https://github.com/leeduckgo/eth_wallet",
              "Docs" => "https://hexdocs.pm/eth_wallet/"}
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
      # ETH
      {:libsecp256k1, "~> 0.1.9"},
      {:ex_abi, "~> 0.5.2"},
      {:ex_rlp, "~> 0.2.1"},
      # Binary
      {:binary, "~> 0.0.5"},
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:earmark, ">= 0.0.0", only: :dev},
      {:dialyxir, ">= 0.0.0", only: [:dev]},

      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
