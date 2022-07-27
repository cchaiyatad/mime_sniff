defmodule MimeSniff do
  @moduledoc """
  A MIME Type detection by magic number in Elixir.
  """
  alias MimeSniff.Sniffing

  @type sniff_opt :: {:sniff_len, integer()} | {:custom_signatures, term()}

  @doc """
  Sniff a MIME Type from input binary.

  ## Options

    * `:sniff_len` - set how many bytes of data from the head that should
      be use to determine the MIME Type (default 32).

      If this value is less than `byte_size(data)` only `data[:sniff_len]` will be used;
      Otherwise, the whole data will be used

    * `:custom_signatures` - a list of Struct that implemented `MimeSniff.Signatures.Signature`
      the given list will be given more priority than the default signature as ordered in `Support types` section.
      (see `MimeSniff.Signatures.Signature` for more information of how to create custom Signature)

  ## Examples
      iex> bin = <<104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 115, 33>> # hello worlds!
      iex> MimeSniff.from_binary(bin)
      {:ok, "text/plain"}

      # for sniff_len and custom_signatures, see examples in from_binary/2

  """
  @spec from_binary(binary(), list(sniff_opt())) :: {:ok, String.t()} | {:error, atom()}
  def from_binary(data, opts \\ []), do: Sniffing.from_binary(data, opts)

  @doc """
  Sniff a MIME Type from file for the given path.

  ## Options

    same as `from_binary/2`

  ## Examples

      iex> MimeSniff.from_file("support/fixtures/png_file.png")
      {:ok, "image/png"}

      # example for sniff_len
      # only read 32 bytes, if not provided default is 32 bytes
      iex> MimeSniff.from_file("support/fixtures/jpg_file.jpg", sniff_len: 16)
      {:ok, "image/jpeg"}

      # example for custom_signatures
      # MimeSniff.Signatures.ExactSignature struct implemented MimeSniff.Signatures.Signature
      # utf8_file.txt contain a string "UTF8"
      iex> alias MimeSniff.Signatures.ExactSignature
      iex> custom_utf8_sig = %ExactSignature{byte_pattern: "UTF8", mime_type: "custom/utf8"}
      iex> custom_utf16_sig = %ExactSignature{byte_pattern: "UTF16", mime_type: "custom/utf16"}
      iex> MimeSniff.Sniffing.from_file("support/fixtures/utf8_file.txt")
      {:ok, "text/plain"}
      iex> MimeSniff.Sniffing.from_file("support/fixtures/utf8_file.txt", custom_signatures: [custom_utf16_sig, custom_utf8_sig])
      {:ok, "custom/utf8"}
  """
  @spec from_file(String.t(), list(sniff_opt())) :: {:ok, String.t()} | {:error, atom()}
  def from_file(file_path, opts \\ []), do: Sniffing.from_file(file_path, opts)
end
