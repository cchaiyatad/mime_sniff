defmodule MimeSniff.Signatures do
  @moduledoc false

  alias MimeSniff.Signatures.{
    ExactSignature,
    HTMLSignature,
    MaskedSignature,
    MP4Signature,
    TextPlainSignature
  }

  @default_signatures_path Path.join([__DIR__, "default_signatures"])
  @comment_marker "#"
  @signature_type_map %{
    "ExactSignature" => :exact,
    "HTMLSignature" => :html,
    "MaskedSignature" => :masked,
    "TextPlainSignature" => :text_plain,
    "MP4Signature" => :mp4
  }
  @doc """
  Get default signature from default_signatures file
  return list of Signature
  """
  def get_default_signatures do
    for line <- File.stream!(@default_signatures_path, [], :line),
        not String.starts_with?(line, @comment_marker),
        do: build_signature_from_line(line)
  end

  defp build_signature_from_line(line) when is_binary(line) do
    [signature_type | parmas] = line |> String.split(",") |> Enum.map(&String.trim(&1))
    build_signature(@signature_type_map[signature_type], parmas)
  end

  defp build_signature(:exact, [byte_pattern, mime_type]),
    do: %ExactSignature{
      byte_pattern: hexs_with_space_to_binaries(byte_pattern),
      mime_type: mime_type
    }

  defp build_signature(:exact, [byte_pattern, _, mime_type]),
    do: %ExactSignature{
      byte_pattern: hexs_with_space_to_binaries(byte_pattern),
      mime_type: mime_type,
      ignored_ws_leading_bytes: true
    }

  defp build_signature(:html, [byte_pattern, pattern_mask]),
    do: %HTMLSignature{
      byte_pattern: hexs_with_space_to_binaries(byte_pattern),
      pattern_mask: hexs_with_space_to_binaries(pattern_mask)
    }

  defp build_signature(:masked, [byte_pattern, pattern_mask, mime_type]),
    do: %MaskedSignature{
      byte_pattern: hexs_with_space_to_binaries(byte_pattern),
      pattern_mask: hexs_with_space_to_binaries(pattern_mask),
      mime_type: mime_type
    }

  defp build_signature(:mp4, _args), do: %MP4Signature{}

  defp build_signature(:text_plain, _args), do: %TextPlainSignature{}

  defp hexs_with_space_to_binaries(hexs) when is_binary(hexs),
    do: hexs |> String.replace(~r/ /, "") |> Base.decode16!()
end
