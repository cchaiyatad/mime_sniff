defimpl MimeSniff.Matchable, for: MimeSniff.Signatures.TextPlainSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """
  import MimeSniff.MimeSniff.Guards
  alias MimeSniff.Signatures.TextPlainSignature

  @mime_type "text/plain"

  def match(%TextPlainSignature{}, data) when is_binary(data), do: do_match(data)

  defp do_match(<<>>), do: {:ok, @mime_type}
  defp do_match(<<token::bytes-size(1), rest::binary>>) when not is_bd(token), do: do_match(rest)
  defp do_match(_), do: {:error, :not_match}
end
