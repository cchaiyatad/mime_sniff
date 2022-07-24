defimpl MimeSniff.Matchable, for: MimeSniff.MaskedSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """
  alias MimeSniff.{Helpers, MaskedSignature}
  use Bitwise

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
