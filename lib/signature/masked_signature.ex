defmodule MimeSniff.MaskedSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """
  @behaviour MimeSniff.Signature
  alias MimeSniff.Helpers
  use Bitwise

  defstruct byte_pattern: <<>>, pattern_mask: nil, mime_type: ""

  def match(%__MODULE__{byte_pattern: byte_pattern} = signature, data) when is_binary(data) do
    with :ok <- valid_signature_pattern(signature),
         true <- String.length(data) >= String.length(byte_pattern) do
      do_match(signature, data)
    else
      {:error, :invalid_pattern} -> {:error, :invalid_pattern}
      false -> {:error, :invalid_input_data}
    end
  end

  def match(_signature, _data), do: {:error, :invalid_data}

  defp valid_signature_pattern(%__MODULE__{byte_pattern: nil}), do: {:error, :invalid_pattern}
  defp valid_signature_pattern(%__MODULE__{pattern_mask: nil}), do: {:error, :invalid_pattern}

  defp valid_signature_pattern(%__MODULE__{} = signature) do
    case String.length(signature.byte_pattern) == String.length(signature.pattern_mask) do
      true -> :ok
      false -> {:error, :invalid_pattern}
    end
  end

  defp do_match(%__MODULE__{} = signature, data),
    do: do_match(signature, data, signature.byte_pattern, signature.pattern_mask)

  defp do_match(%__MODULE__{mime_type: mime_type}, _, <<>>, <<>>), do: {:ok, mime_type}

  defp do_match(
         %__MODULE__{} = signature,
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

  def build([byte_pattern, pattern_mask, mime_type]),
    do: %__MODULE__{
      byte_pattern: Helpers.hexs_with_space_to_binaries(byte_pattern),
      pattern_mask: Helpers.hexs_with_space_to_binaries(pattern_mask),
      mime_type: mime_type
    }
end
