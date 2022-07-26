defmodule MimeSniff do
  @moduledoc """
  A MIME Type detection by magic number in Elixir.
  """
  alias MimeSniff.MimeSniff.Sniffing

  @type sniff_opt :: {:sniff_len, integer()} | {:custom_signatures, term()}

  @doc """
  Sniff a MIME Type from input binary.

  ## Options

    * `:sniff_len` - set how many bytes of data from the head that should
      be use to determine the MIME Type (default 32).

      If this value is less than byte_size(data) only data[:sniff_len] will be used;
      Otherwise, the whole data will be used

    * `:custom_signatures` -

  ## Examples
      iex> bin = <<104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 115, 33>> # hello worlds!
      iex> MimeSniff.from_binary(bin)
      {:ok, "text/plain"}
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

      # only read 32 bytes, if not provided default is 32 bytes
      iex> MimeSniff.from_file("support/fixtures/jpg_file.jpg", sniff_len: 16)
      {:ok, "image/jpeg"}
  """
  @spec from_file(String.t(), list(sniff_opt())) :: {:ok, String.t()} | {:error, atom()}
  def from_file(file_path, opts \\ []), do: Sniffing.from_file(file_path, opts)
end
