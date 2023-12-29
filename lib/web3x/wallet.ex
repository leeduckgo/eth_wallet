defmodule EthWallet.Web3x.Wallet do
  @moduledoc """
    Fetch from:
    > https://github.com/Metalink-App/web3x/blob/master/lib/web3x/wallet.ex
  """
  @ethereum_message_prefix "\x19Ethereum Signed Message:\n"
  @base_recovery_id 27
  @base_recovery_id_eip_155 35

  # @doc Returns a base64 encoded 16 byte (default) binary to be used as a nonce in a message used in the login with ethereum wallet flow.
  def get_nonce(bytes_num \\ 16) do
    rand_bytes = :crypto.strong_rand_bytes(bytes_num)
    Base.encode64(rand_bytes)
  end

  # @doc Hashes a binary message and removes ethereum message prefix & length from the beginning of the binary.
  def hash_message(message) when is_binary(message) do
    eth_message = @ethereum_message_prefix <> get_message_length_bytes(message) <> message
    ExKeccak.hash_256(eth_message)
  end

  defp get_message_length_bytes(message) when is_binary(message) do
    Integer.to_string(String.length(message))
  end

  @doc "Destructure a signature to r, s, v to be used by Secp256k1 recover"
  def destructure_sig(sig) do
    r = sig |> String.slice(2, 64) |> Base.decode16!(case: :lower)
    s = sig |> String.slice(66, 64) |> Base.decode16!(case: :lower)

    {v, _} =
      sig
      |> String.slice(130, 2)
      |> String.upcase()
      |> Integer.parse(16)

    {:ok, v, _} = decode_signature(v)

    {r, s, v}
  end

  defp decode_signature(signature_v) do
    # There are three cases:
    #  1. It is a simple 0,1 recovery id
    #  2. It is 0,1 + base recovery_id, in which case we need to subtract that and add EIP-155
    #  3. It is already EIP-155 compliant

    cond do
      is_simple_signature?(signature_v) ->
        {:ok, signature_v, nil}

      is_pre_eip_155_signature?(signature_v) ->
        {:ok, signature_v - @base_recovery_id, nil}

      true ->
        network_id = trunc((signature_v - @base_recovery_id_eip_155) / 2)

        {:ok, signature_v - @base_recovery_id_eip_155 - network_id * 2, network_id}
    end
  end

  # Returns true is signature is simple 0,1-type recovery_id
  defp is_simple_signature?(v), do: v < @base_recovery_id

  # Returns true if signature is pre EIP-155 Ethereum signature
  defp is_pre_eip_155_signature?(v), do: v < @base_recovery_id_eip_155

  @doc "Strip 0x prefix from a binary"
  def strip_hex_prefix(signature) do
    "0x" <> signature = signature
    signature
  end

  @doc "Get Public Ethereum Address from Public Key"
  def get_address(public_key) do
    <<4::size(8), key::binary-size(64)>> = public_key
    <<_::binary-size(12), eth_address::binary-size(20)>> = ExKeccak.hash_256(key)
    "0x#{Base.encode16(eth_address)}"
  end

  def verify_signature(hash, signature) do
    {r, s, v} = destructure_sig(signature)
    # :libsecp256k1.ecdsa_recover_compact(hash, r <> s, :uncompressed, v)
    ExSecp256k1.recover_compact(hash, r <> s, v)
  end

  @doc "Verifies if a message was signed by a wallet keypair given a the public address, message, signature"
  @spec verify_message?(any, binary, binary) :: boolean
  def verify_message?(public_address, message, signature) do
    hash = hash_message(message)

    case verify_signature(hash, signature) do
      {:ok, recovered_key} ->
        recovered_address = get_address(recovered_key)
        String.downcase(recovered_address) == String.downcase(public_address)

      _ ->
        false
    end
  end

  @doc "Verifies if a message was signed by a wallet keypair given a the public address, message, signature, and nonce in the message"
  def verify_message?(public_address, message, signature, nonce) do
    if is_nonce_in_message?(message, nonce) do
      try do
        verify_message?(public_address, message, signature)
      rescue
        _e -> false
      end
    else
      false
    end
  end

  defp is_nonce_in_message?(message, nonce) do
    String.contains?(message, nonce)
  end
end
