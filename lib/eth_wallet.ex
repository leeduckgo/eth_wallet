defmodule EthWallet do
  @moduledoc """
    Documentation for `EthWallet`.
  """

  alias EthWallet.Utils.Crypto

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
  @spec generate_keys(Binary.t()) :: Map.t()
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

  @doc """
    encrypt key with password.

    ## Examples

    iex> EthWallet.encrypt_key("ddd", "abc")

    <<40, 28, 220, 122, 235, 180, 216, 145, 142, 171, 53, 146, 25, 136, 47, 215>>

  """
  defdelegate encrypt_key(encrypted_key, password), to: Crypto

  @doc """
    decrypt key with password.

    ## Examples

    iex> EthWallet.decrypt_key(payload, "bbc")

    "ddd"
  """
  defdelegate decrypt_key(payload, password), to: Crypto
end
