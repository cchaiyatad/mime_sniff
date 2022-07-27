defmodule MimeSniff.Signatures.ExactSignature do
  @moduledoc """
  It represent the signature in [MIME sniff](https://mimesniff.spec.whatwg.org)
  table that all bytes in `Pattern Mask` are FF.

  e.g., For [PNG type](https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern)
  * **Byte Pattern**: 89 50 4E 47 0D 0A 1A 0A
  * **Pattern Mask**: FF FF FF FF FF FF FF FF
  * **Leading Bytes to Be Ignored**: None.
  * **Image MIME Type**: image/png

  can be represent as
  ``` elixir
  %ExactSignature{
    byte_pattern: <<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A>>,
    ignored_ws_leading_bytes: false,
    mime_type: "image/png"
  }
  ```

  The ExactSignature struct implement MimeSniff.Signatures.Signature protocol,
  so it can be use with to do MIME sniffing

  ## Examples

      alias MimeSniff.Signatures.Signature
      alias MimeSniff.Signatures.ExactSignature

      png_sig = %ExactSignature{
        byte_pattern: <<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A>>,
        ignored_ws_leading_bytes: false,
        mime_type: "image/png"
      }

      # png signature is "An error-checking byte followed by the string 'PNG' followed by CR LF SUB LF, the PNG signature"
      test_data = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13>> # data strip from png file

      Signature.match(png_sig, test_data) # {:ok, "image/png"}
  """

  @type t :: %__MODULE__{
          :byte_pattern => binary(),
          :ignored_ws_leading_bytes => boolean(),
          :mime_type => String.t()
        }
  defstruct byte_pattern: <<>>, ignored_ws_leading_bytes: false, mime_type: ""
end

defimpl MimeSniff.Signatures.Signature, for: MimeSniff.Signatures.ExactSignature do
  import MimeSniff.Guards
  alias MimeSniff.Helpers
  alias MimeSniff.Signatures.ExactSignature

  @doc """
  Function is implemented as defined in
  [Matching a MIME Type pattern](https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern)
  except the masking part (6.1)
  """
  @spec match(ExactSignature.t(), binary()) :: {:ok, String.t()} | {:error, atom()}
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
