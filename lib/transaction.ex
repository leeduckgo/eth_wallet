defmodule EthWallet.Transaction do
  @moduledoc """
    Tx about Ethereum.
  """
  alias EthWallet.Utils.{Crypto, TypeTranslator}

  alias EthWallet.Transaction

  defstruct nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: <<>>,
            value: 0,
            v: nil,
            r: nil,
            s: nil,
            init: <<>>,
            data: <<>>

  @type t :: %__MODULE__{
          nonce: integer(),
          gas_price: integer(),
          gas_limit: integer(),
          to: <<_::160>> | <<_::0>>,
          value: integer(),
          v: integer(),
          r: integer(),
          s: integer(),
          # contract machine code
          init: binary(),
          data: binary()
        }

  def build_tx(to_str, value, data, nonce, gas_price, gas_limit) do

    to_bin =
      TypeTranslator.addr_to_bin(to_str)

    %Transaction{
      nonce: nonce,
      gas_price: gas_price,
      gas_limit: gas_limit,
      to: to_bin,
      value: value,
      init: <<>>,
      data: data
    }
  end

  @spec signed_tx_to_raw_tx(Transaction.t()) :: String.t()
  def signed_tx_to_raw_tx(signed_tx) do
    raw_tx =
      signed_tx
      |> serialize()
      |> ExRLP.encode(encoding: :hex)

    "0x" <> raw_tx
  end

  @doc """
    v <> r <> s => Base64 编码，得最终版签名.
  """
  @spec sign_tx(Transaction.t(), binary(), integer() | nil) :: Transaction.t()
  def sign_tx(tx, private_key, chain_id \\ nil) do
    %{v: v, r: r, s: s} =
      tx
      |> hash_for_signing(chain_id)
      |> Crypto.sign_compact(private_key, chain_id)

    %{tx | v: v, r: r, s: s}
  end

  @spec hash_for_signing(Transaction.t(), integer() | nil) :: binary()
  def hash_for_signing(tx, chain_id \\ nil) do
    # See EIP-155
    tx
    |> serialize(false)
    |> Kernel.++(if chain_id, do: [:binary.encode_unsigned(chain_id), <<>>, <<>>], else: [])
    |> ExRLP.encode(encoding: :binary)
    |> Crypto.kec()
  end

  @spec serialize(Transaction.t(), boolean()) :: ExRLP.t()
  def serialize(tx, include_vrs \\ true) do
    base = [
      encode_unsigned(tx.nonce),
      encode_unsigned(tx.gas_price),
      encode_unsigned(tx.gas_limit),
      tx.to,
      encode_unsigned(tx.value),
      if(tx.to == <<>>, do: tx.init, else: tx.data)
    ]

    if include_vrs do
      base ++
        [
          encode_unsigned(tx.v),
          encode_unsigned(tx.r),
          encode_unsigned(tx.s)
        ]
    else
      base
    end
  end

  @doc """
    iex(80)> :binary.encode_unsigned(12345)

    "09"

    iex(81)> "09" <> <<0>>

    <<48, 57, 0>>

    iex(83)> 48 * 256 + 57

    12345
  """
  @spec encode_unsigned(number()) :: binary()
  def encode_unsigned(0), do: <<>>
  def encode_unsigned(n), do: :binary.encode_unsigned(n)
end
