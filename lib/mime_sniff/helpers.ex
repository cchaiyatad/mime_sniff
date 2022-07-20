defmodule MimeSniff.Helpers do
  @moduledoc false
  alias MimeSniff.{ExactSignature, HTMLSignature, MaskedSignature, TextPlainSignature}

  @signature_type_map %{
    "ExactSignature" => :exact,
    "HTMLSignature" => :html,
    "MaskedSignature" => :masked,
    "TextPlainSignature" => :text_plain
  }

  def c_to_b(<<c::bytes-size(1)>>), do: :binary.decode_unsigned(c)

  def read_byte_from_file(file_path, len) do
    file_path
    |> File.stream!([], len)
    |> Enum.take(1)
    |> case do
      [] -> <<>>
      [data] -> data
    end
  end

  def hexs_with_space_to_binaries(hexs) when is_binary(hexs),
    do: hexs |> String.replace(~r/ /, "") |> Base.decode16!()

  def build_signature_from_line(line) when is_binary(line) do
    [signature_type | parmas] = line |> String.split(",") |> Enum.map(&String.trim(&1))
    build_signature_from_line(@signature_type_map[signature_type], parmas)
  end

  defp build_signature_from_line(:exact, parmas), do: ExactSignature.build(parmas)
  defp build_signature_from_line(:html, parmas), do: HTMLSignature.build(parmas)
  defp build_signature_from_line(:masked, parmas), do: MaskedSignature.build(parmas)
  defp build_signature_from_line(:text_plain, _), do: TextPlainSignature.build([])
end
