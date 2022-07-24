defimpl MimeSniff.Matchable, for: MimeSniff.Signatures.ExactSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """
  import MimeSniff.MimeSniff.Guards
  alias MimeSniff.MimeSniff.Helpers
  alias MimeSniff.Signatures.ExactSignature

  def match(%ExactSignature{byte_pattern: byte_pattern} = signature, data) when is_binary(data) do
    with data <- ignored_ws_if_needed(signature, data),
         true <- byte_size(data) >= byte_size(byte_pattern) do
      do_match(signature, data, byte_pattern)
    else
      false -> {:error, :not_match}
    end
  end

  defp ignored_ws_if_needed(
         %ExactSignature{ignored_ws_leading_bytes: true} = signature,
         <<token::bytes-size(1), rest::binary>>
       )
       when is_ws(token),
       do: ignored_ws_if_needed(signature, rest)

  defp ignored_ws_if_needed(_signature, data), do: data

  defp do_match(%ExactSignature{mime_type: mime_type}, _, <<>>), do: {:ok, mime_type}

  defp do_match(
         %ExactSignature{} = signature,
         <<d::bytes-size(1), data_rest::binary>>,
         <<b::bytes-size(1), byte_pattern_rest::binary>>
       ) do
    case Helpers.c_to_b(d) == Helpers.c_to_b(b) do
      false -> {:error, :not_match}
      true -> do_match(signature, data_rest, byte_pattern_rest)
    end
  end

  defp do_match(_, _, _), do: {:error, :not_match}
end
