defmodule MimeSniff.Signatures.MaskedSignature do
  @moduledoc """
  It represent the signature in [MIME sniff](https://mimesniff.spec.whatwg.org)
  table that all bytes in `Pattern Mask` are not FF `Leading Bytes to Be Ignored` is None.

  e.g., For [webp type](https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern)
  * **Byte Pattern**: 52 49 46 46 00 00 00 00 57 45 42 50 56 50
  * **Pattern Mask**: FF FF FF FF 00 00 00 00 FF FF FF FF FF FF
  * **Leading Bytes to Be Ignored**: None.
  * **Image MIME Type**: image/webp

  can be represent as
  ``` elixir
  %MaskedSignature{
    byte_pattern: <<0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50>>,
    pattern_mask: <<0xFF ,0xFF ,0xFF ,0xFF ,0x00 ,0x00 ,0x00 ,0x00 ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF>>,
    mime_type: "image/webp"
  }
  ```

  The MaskedSignature struct implement MimeSniff.Signatures.Signature protocol,
  so it can be use with to do MIME sniffing

  ## Examples

      alias MimeSniff.Signatures.Signature
      alias MimeSniff.Signatures.MaskedSignature

      webp_sig = %MaskedSignature{
        byte_pattern: <<0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50>>,
        pattern_mask: <<0xFF ,0xFF ,0xFF ,0xFF ,0x00 ,0x00 ,0x00 ,0x00 ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF>>,
        mime_type: "image/webp"
      }

      # webp signature is "The string 'RIFF' followed by four bytes followed by the string 'WEBPVP'"
      test_data = "RIFFdataWEBPVPdata"

      Signature.match(webp_sig, test_data) # {:ok, "image/webp"}
  """

  @type t :: %__MODULE__{
          :byte_pattern => binary(),
          :pattern_mask => binary() | nil,
          :mime_type => String.t()
        }
  defstruct byte_pattern: <<>>, pattern_mask: nil, mime_type: ""
end

defimpl MimeSniff.Signatures.Signature, for: MimeSniff.Signatures.MaskedSignature do
  alias MimeSniff.Helpers
  alias MimeSniff.Signatures.MaskedSignature
  use Bitwise

  @doc """
  Function is implemented as defined in
  [Matching a MIME Type pattern](https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern)
  """
  @spec match(MaskedSignature.t(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def match(%MaskedSignature{byte_pattern: byte_pattern} = signature, data)
      when is_binary(data) do
    with :ok <- valid_signature_pattern(signature),
         true <- byte_size(data) >= byte_size(byte_pattern) do
      do_match(signature, data)
    else
      {:error, :invalid_pattern} -> {:error, :invalid_pattern}
      false -> {:error, :not_match}
    end
  end

  defp valid_signature_pattern(%MaskedSignature{byte_pattern: nil}),
    do: {:error, :invalid_pattern}

  defp valid_signature_pattern(%MaskedSignature{pattern_mask: nil}),
    do: {:error, :invalid_pattern}

  defp valid_signature_pattern(%MaskedSignature{} = signature) do
    case byte_size(signature.byte_pattern) == byte_size(signature.pattern_mask) do
      true -> :ok
      false -> {:error, :invalid_pattern}
    end
  end

  defp do_match(%MaskedSignature{} = signature, data),
    do: do_match(signature, data, signature.byte_pattern, signature.pattern_mask)

  defp do_match(%MaskedSignature{mime_type: mime_type}, _, <<>>, <<>>), do: {:ok, mime_type}

  defp do_match(
         %MaskedSignature{} = signature,
         <<d::bytes-size(1), data_rest::binary>>,
         <<b::bytes-size(1), byte_pattern_rest::binary>>,
         <<p::bytes-size(1), pattern_mask_rest::binary>>
       ) do
    is_match = (Helpers.c_to_b(p) &&& Helpers.c_to_b(d)) == Helpers.c_to_b(b)

    case is_match do
      false -> {:error, :not_match}
      true -> do_match(signature, data_rest, byte_pattern_rest, pattern_mask_rest)
    end
  end

  defp do_match(_, _, _, _), do: {:error, :not_match}
end
