defimpl MimeSniff.Matchable, for: MimeSniff.HTMLSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """
  import MimeSniff.Guards
  alias MimeSniff.{Helpers, HTMLSignature}
  use Bitwise

  @mime_type "text/html"

  def match(%HTMLSignature{byte_pattern: byte_pattern} = signature, data) when is_binary(data) do
    with :ok <- valid_signature_pattern(signature),
         data <- ignored_ws(data),
         true <- byte_size(data) >= byte_size(byte_pattern) do
      do_match(signature, data)
    else
      {:error, :invalid_pattern} -> {:error, :invalid_pattern}
      false -> {:error, :not_match}
    end
  end

  defp valid_signature_pattern(%HTMLSignature{byte_pattern: nil}), do: {:error, :invalid_pattern}
  defp valid_signature_pattern(%HTMLSignature{pattern_mask: nil}), do: {:error, :invalid_pattern}

  defp valid_signature_pattern(%HTMLSignature{} = signature) do
    case byte_size(signature.byte_pattern) == byte_size(signature.pattern_mask) do
      true -> :ok
      false -> {:error, :invalid_pattern}
    end
  end

  defp ignored_ws(<<token::bytes-size(1), rest::binary>>) when is_ws(token),
    do: ignored_ws(rest)

  defp ignored_ws(data), do: data

  defp do_match(%HTMLSignature{} = signature, data),
    do: do_match(signature, data, signature.byte_pattern, signature.pattern_mask)

  defp do_match(%HTMLSignature{}, <<d::bytes-size(1), _::binary>>, <<>>, <<>>) when is_tt(d),
    do: {:ok, @mime_type}

  defp do_match(
         %HTMLSignature{} = signature,
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
