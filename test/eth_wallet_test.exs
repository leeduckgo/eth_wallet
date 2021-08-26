defmodule EthWalletTest do
  use ExUnit.Case
  doctest EthWallet

  test "greets the world" do
    assert EthWallet.hello() == :world
  end
end
