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
  alias EthWallet.Web3x.Wallet

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

  @doc """
    sign uncompact, as sign in bitcoin.
  """
  @spec sign(binary(), binary()) :: binary()
  defdelegate sign(digest, privkey), to: Crypto

  @doc """
    verify uncompact, fit to sign()
  """
  @spec verify(binary(), binary(), binary()) :: boolean()
  defdelegate verify(digest, sig, pubkey), to: Crypto

  # +----------------------+
  # | Ethereum Sign/Verify |
  # +----------------------+
  @doc """
    sign compact, as sign in ethereum.
  """
  @spec sign_compact(<<_ :: 256>>, <<_ :: 256>>, nil | integer()) :: %{v: integer(), r: integer(), s: integer(), sig: <<_::512>>}
  def sign_compact(digest, privkey, chain_id \\ nil) do
    digest
    |> standard_hash()
    |> Crypto.sign_compact(privkey, chain_id)
  end

    @doc """
    verify by msg, sig and addr, fit to "sign_compact()"
  """
  @spec verify_compact(String.t(), String.t(), String.t()) :: boolean()
  def verify_compact(msg_unhashed, sig, addr) do
    Wallet.verify_message?(addr, msg_unhashed, sig)
  end

  @doc """
    standard hash for msg signature.
  """
  @spec standard_hash(String.t()) :: binary()
  def standard_hash(msg_unhashed), do: Wallet.hash_message(msg_unhashed)

  # @doc """
  #   verify compact, fit to sign_compact()
  # """
  # @spec verify_compact(binary(), binary(), binary()) :: boolean()
  # defdelegate verify_compact(msg, sig, pubkey), to: Crypto

  @doc """
    recover pubkey by recovcery id, generated by sign compact
  """
  @spec recover(binary(), binary(), integer(), nil | integer()) :: {:ok, binary()} | {:error, String.t()}
  defdelegate recover(digest, signature, recovery_id_handled , chain_id \\ nil), to: Crypto

end
