defmodule EthWallet.Utils.Crypto do
  @moduledoc """
    Crypto Lib
  """

  alias EthWallet.Utils.ExSha3

  @address_prefix "0x"
  @address_size 40

  @base_recovery_id 27
  @base_recovery_id_eip_155 35

  def pubkey_to_address(public_key) do
    @address_prefix <> pubkey_to_hex(public_key)
  end

  defp pubkey_to_hex(public_key) do
    public_key
    |> strip_leading_byte()
    |> keccak_256sum()
    |> String.slice(@address_size * -1, @address_size)
    |> String.downcase()
  end

  defp strip_leading_byte(data = [_head | tail]) when is_list(data), do: tail

  defp strip_leading_byte(data) when is_binary(data) do
    data
    |> :binary.bin_to_list()
    |> strip_leading_byte()
    |> :binary.list_to_bin()
  end


  @doc """
    The test is here:

    https://github.com/exthereum/exth_crypto/blob/master/lib/signature/signature.ex

    Attention: hash should be 32 bytes.
  """
  @spec sign_hash(<<_ :: 256>>, <<_ :: 256>>, nil | integer()) ::
          {non_neg_integer(), non_neg_integer(), non_neg_integer()}
  def sign_hash(hash, privkey, chain_id \\ nil) do
    # {:libsecp256k1, "~> 0.1.9"} is useful.
    {:ok, <<r::size(256), s::size(256)>>, recovery_id} =
      :libsecp256k1.ecdsa_sign_compact(hash, privkey, :default, <<>>)

    recovery_id =
      if chain_id do
        chain_id * 2 + @base_recovery_id_eip_155 + recovery_id
      else
        @base_recovery_id + recovery_id
      end

    {recovery_id, r, s}
  end


  @doc """
    The test is here:

    https://github.com/exthereum/exth_crypto/blob/master/lib/signature/signature.ex

    Attention: hash should be 32 bytes.
  """
  @spec sign_hash(<<_ :: 256>>, <<_ :: 512>>, binary()) ::
  {non_neg_integer(), non_neg_integer(), non_neg_integer()}
  def verify_hash(hash, sig, pubkey) do
    case :libsecp256k1.ecdsa_verify(hash, sig, pubkey) do
      :ok -> true
      _ -> false
    end
  end

  def sha256(data), do: :crypto.hash(:sha256, data)
  def ripemd160(data), do: :crypto.hash(:ripemd160, data)

  @spec double_sha256(
          binary
          | maybe_improper_list(
              binary | maybe_improper_list(any, binary | []) | byte,
              binary | []
            )
        ) :: binary
  def double_sha256(data), do: data |> sha256 |> sha256

  def secp256k1_verify(data, sig, pubkey) do
    :crypto.verify(:ecdsa, :sha256, data, sig, [pubkey, :secp256k1])
  end

  def secp256k1_sign(data, privkey) do
    :crypto.sign(:ecdsa, :sha256, data, [privkey, :secp256k1])
  end

  def generate_key_secp256k1() do
    {pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1)

    do_generate_key_secp256k1(pubkey, privkey)
  end

  def generate_key_secp256k1(privkey) do
    {pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1, privkey)
    do_generate_key_secp256k1(pubkey, privkey)
  end

  defp do_generate_key_secp256k1(pubkey, privkey) do
    if byte_size(privkey) != 32 do
      generate_key_secp256k1()
    else
      %{pub: pubkey, priv: privkey}
    end
  end

  defp keccak_256sum(data) do
    data
    |> kec()
    |> Base.encode16()
  end

  def kec(data) do
    ExSha3.keccak_256(data)
  end

  # +------------------------------+
  # | encrypt the data in database |
  # +------------------------------+

  def encrypt_key(encrypted_key, password) do
    md5_pwd = md5(password)
    :crypto.block_encrypt(:aes_ecb, md5_pwd, pad(encrypted_key, 16))
  end

  def decrypt_key(payload, password) do
    md5_pwd = md5(password)

    :aes_ecb
    |> :crypto.block_decrypt(md5_pwd, payload)
    |> unpad()
  end

  defp pad(data, block_size) do
    to_add = block_size - rem(byte_size(data), block_size)
    data <> to_string(:string.chars(to_add, to_add))
  end

  defp unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end

  defp md5(data) do
    :md5
    |> :crypto.hash(data)
    |> Base.encode16(case: :lower)
  end
end
