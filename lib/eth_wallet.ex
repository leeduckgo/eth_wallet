defmodule EthWallet do
  @moduledoc """
    Documentation for `EthWallet`.

    - 1. keys operations

    - 2. generate signed tx

      tx generated path:

      build_tx -> hash_for_signing(serialize -> rlp encode -> kec) -> gen sig -> get signed tx

      -> to raw tx-> send tx to node
  """

  alias EthWallet.Utils.Crypto
  alias EthWallet.Transaction
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
  @spec generate_keys(binary()) :: map()
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

  @doc """
    build transaction
  """
  @spec build_tx(String.t(), integer(), binary(), integer(), integer(), integer()) :: Transction.t()
  defdelegate build_tx(to_str, value, data, nonce, gas_price, gas_limit), to: Transaction

  @doc """
    sign transaction
  """
  @spec sign_tx(Transaction.t(), binary(), integer() | nil) :: Transaction.t()
  defdelegate sign_tx(tx, private_key, chain_id \\ nil), to: Transaction

  @doc """
    signed transaction to raw transaction
  """
  @spec signed_tx_to_raw_tx(Transaction.t()) :: String.t()
  defdelegate signed_tx_to_raw_tx(signed_tx), to: Transaction

  @spec sign_msg(binary(), binary()) :: binary()
  defdelegate sign_msg(msg, privkey), to: Crypto

  @spec verify_msg_sig(binary(), binary(), binary()) :: boolean()
  defdelegate verify_msg_sig(msg, sig, privkey), to: Crypto
end
