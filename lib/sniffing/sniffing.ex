defmodule MimeSniff.Sniffing do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#determining-the-computed-mime-type-of-a-resource
  """
  alias MimeSniff.{DefaultSignatures, Helpers, Matchable}
  @default_signatures DefaultSignatures.get()

  # https://mimesniff.spec.whatwg.org/#reading-the-resource-header
  @default_sniff_len 1445

  def from_file(file_path, opts \\ []) do
    sniff_len = Keyword.get(opts, :sniff_len, @default_sniff_len)

    file_path
    |> Helpers.read_byte_from_file(sniff_len)
    |> from_binary(opts)
  end

  def from_binary(data, opts \\ []) when is_binary(data) do
    sniff_len = Keyword.get(opts, :sniff_len, @default_sniff_len)
    custom_signatures = Keyword.get(opts, :custom_signatures, [])

    trimmed_data = String.slice(data, 0, sniff_len)

    do_match(custom_signatures ++ @default_signatures, trimmed_data)
  end

  # 7.1.10 https://mimesniff.spec.whatwg.org/#identifying-a-resource-with-an-unknown-mime-type
  defp do_match([], _data), do: "application/octet-stream"

  defp do_match([sig | rest], data) do
    case Matchable.match(sig, data) do
      {:ok, mime_type} -> mime_type
      {:error, _} -> do_match(rest, data)
    end
  end
end
