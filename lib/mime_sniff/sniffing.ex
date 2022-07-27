defmodule MimeSniff.Sniffing do
  @moduledoc false

  alias MimeSniff.Signatures.Signature
  alias MimeSniff.{Helpers, Signatures}

  @default_signatures Signatures.get_default_signatures()

  # 36 is the minimum number of bytes to use
  # to support all file type that program can sniff
  @default_sniff_len 36

  @type sniff_opt :: {:sniff_len, integer()} | {:custom_signatures, term()}

  @spec from_file(binary(), list(sniff_opt())) :: {:ok, String.t()} | {:error, atom()}
  def from_file(file_path, opts \\ []) do
    sniff_len = Keyword.get(opts, :sniff_len, @default_sniff_len)

    file_path
    |> Helpers.read_byte_from_file(sniff_len)
    |> from_binary(opts)
  end

  @spec from_binary(String.t(), list(sniff_opt())) :: {:ok, String.t()} | {:error, atom()}
  def from_binary(data, opts \\ []) when is_binary(data) do
    sniff_len = Keyword.get(opts, :sniff_len, @default_sniff_len)
    custom_signatures = Keyword.get(opts, :custom_signatures, [])

    trimmed_data = String.slice(data, 0, sniff_len)

    do_match(custom_signatures ++ @default_signatures, trimmed_data)
  end

  # 7.1.10 https://mimesniff.spec.whatwg.org/#identifying-a-resource-with-an-unknown-mime-type
  defp do_match([], _data), do: {:ok, "application/octet-stream"}

  defp do_match([sig | rest], data) do
    case Signature.match(sig, data) do
      {:ok, mime_type} -> {:ok, mime_type}
      {:error, :not_match} -> do_match(rest, data)
      {:error, error} -> {:error, error}
    end
  end
end
