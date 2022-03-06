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


  def recover(digest, signature, recovery_id_handled , chain_id \\ nil) do
    recovery_id =
      recovery_id_handled_to_recovery_id(recovery_id_handled, chain_id)
    case :libsecp256k1.ecdsa_recover_compact(digest, signature, :uncompressed, recovery_id) do
      {:ok, public_key} -> {:ok, public_key}
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  defp recovery_id_to_recovery_id_handled(recovery_id, chain_id) do
    if chain_id do
      chain_id * 2 + @base_recovery_id_eip_155 + recovery_id
    else
      @base_recovery_id + recovery_id
    end
  end

  defp recovery_id_handled_to_recovery_id(recovery_id_handled, chain_id) do
    if chain_id do
      recovery_id_handled - chain_id * 2 - @base_recovery_id_eip_155
    else
      recovery_id_handled - @base_recovery_id
    end
  end

  @doc """
    The test is here:

    https://github.com/exthereum/exth_crypto/blob/master/lib/signature/signature.ex

    Attention: hash should be 32 bytes.
  """
  def sign_compact(digest, privkey, chain_id \\ nil) do
    # {:libsecp256k1, "~> 0.1.9"} is useful.
    {:ok, <<r::size(256), s::size(256)>> = sig, recovery_id} =
      :libsecp256k1.ecdsa_sign_compact(digest, privkey, :default, <<>>)

    recovery_id_handled =
      recovery_id_to_recovery_id_handled(recovery_id, chain_id)
    sig_hex =
      sig
      |> Kernel.<>(<<recovery_id_handled>>)
      |> Base.encode16(case: :lower)
    %{v: recovery_id_handled, r: r, s: s, sig: "0x#{sig_hex}"}
  end

  @doc """
    The test is here:

    https://github.com/exthereum/exth_crypto/blob/master/lib/signature/signature.ex

    Attention: hash should be 32 bytes.
  """
  def verify(digest, sig, pubkey) do
    # :crypto.verify(:ecdsa, :sha256, msg, sig, [pubkey, :secp256k1])
    case :libsecp256k1.ecdsa_verify(digest, sig, pubkey) do
      :ok -> true
      _ -> false
    end
  end

  def verify_compact(digest, sig, pubkey) do
    case :libsecp256k1.ecdsa_verify_compact(digest, sig, pubkey) do
      :ok -> true
      _ -> false
    end
  end

  def sha256(data), do: :crypto.hash(:sha256, data)
  def ripemd160(data), do: :crypto.hash(:ripemd160, data)

  @spec double_sha256(binary) :: binary
  def double_sha256(data), do: data |> sha256() |> sha256()

  @doc """
    :crypto.sign(:ecdsa, :sha256, msg, [privkey, :secp256k1])

    equal to

    msg |> sha256() |> :libsecp256k1.ecdsa_sign

    > sig format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]

    - sha256 digest using for bitcoin
  """
  def sign(digest, priv) do
    {:ok, res} = :libsecp256k1.ecdsa_sign(digest, priv, :default, <<>>)
    res
  end

  def generate_key_secp256k1() do
    {pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1)
    do_generate_key_secp256k1(pubkey, privkey)
  end

  def generate_key_secp256k1(privkey) do
    {pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1, privkey)
    %{pub: pubkey, priv: privkey}
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

  @spec encrypt_key(binary(),binary()) :: binary()
  def encrypt_key(unencrypted_key, password) do
    md5_pwd = md5(password)
    {:ok, {init_vec, cipher_text}} = ExCrypto.encrypt(md5_pwd, unencrypted_key)
    # init_vec: 16 bytes
    init_vec <> cipher_text
  end

  @spec decrypt_key(binary(),binary()) :: binary()
  def decrypt_key(encrypted_key, password) do
    md5_pwd = md5(password)
    <<init_vec :: binary-size(16), cipher_text :: binary>> = encrypted_key

    {:ok, unencrypted_key} = ExCrypto.decrypt(md5_pwd, init_vec, cipher_text)
    unencrypted_key
  end

  def pad(data, block_size) do
    to_add = block_size - rem(byte_size(data), block_size)
    data <> to_string(:string.chars(to_add, to_add))
  end

  def unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end

  def md5(data) do
    :md5
    |> :crypto.hash(data)
    |> Base.encode16(case: :lower)
  end

end
