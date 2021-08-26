defmodule EthWallet do
  @moduledoc """
    Documentation for `EthWallet`.
  """

  alias Utils.Crypto

  @doc """
    generate keys with/without privkey.

    ## Examples

    iex> EthWallet.generate_keys()

    %{
      addr: "0xd705f740d934acfb27df7bf71aadc00f20d03c7a",
      priv: <<21, ..., 166>>,
      pub: <<4, ..., 165, ...>>
    }

  """
  def generate_keys() do
    %{pub: pub}
      = result
      = Crypto.generate_key_secp256k1()
    do_generate_keys(result, pub)
  end

  @doc """
    iex> EthWallet.generate_keys(<<21, ..., 166>>)

    %{
      addr: "0xd705f740d934acfb27df7bf71aadc00f20d03c7a",
      priv: <<21, ..., 166, ...>>,
      pub: <<4, ..., 165, ...>>
    }
  """
  def generate_keys(priv) do
    %{pub: pub}
      = result
      = Crypto.generate_key_secp256k1(priv)
    do_generate_keys(result, pub)
  end

  defp do_generate_keys(result, pub) do
    addr = Crypto.pubkey_to_address(pub)
    Map.put(result, :addr, addr)
  end
end
