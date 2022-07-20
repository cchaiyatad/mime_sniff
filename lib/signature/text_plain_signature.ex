defmodule MimeSniff.TextPlainSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """
  @behaviour MimeSniff.Signature
  import MimeSniff.Guards

  defstruct []

  @mime_type "text/plain"

  def match(%__MODULE__{}, data) when is_binary(data), do: do_match(data)
  def match(_, _), do: {:error, :invalid_input_data}

  defp do_match(<<>>), do: {:ok, @mime_type}
  defp do_match(<<token::bytes-size(1), rest::binary>>) when not is_bd(token), do: do_match(rest)
  defp do_match(_), do: {:error, :not_match}

  def build(_args), do: %__MODULE__{}
end
