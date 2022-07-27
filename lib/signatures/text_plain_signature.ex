defmodule MimeSniff.Signatures.TextPlainSignature do
  @moduledoc false
  @type t :: %__MODULE__{}

  defstruct []
end

defimpl MimeSniff.Signatures.Signature, for: MimeSniff.Signatures.TextPlainSignature do
  import MimeSniff.Guards
  alias MimeSniff.Signatures.TextPlainSignature

  @mime_type "text/plain"

  @doc """
  Function is implemented as defined in
  [section 7.1.9](https://mimesniff.spec.whatwg.org/#identifying-a-resource-with-an-unknown-mime-type)
  """
  @spec match(TextPlainSignature.t(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def match(%TextPlainSignature{}, data) when is_binary(data), do: do_match(data)

  defp do_match(<<>>), do: {:ok, @mime_type}
  defp do_match(<<token::bytes-size(1), rest::binary>>) when not is_bd(token), do: do_match(rest)
  defp do_match(_), do: {:error, :not_match}
end
