defmodule MimeSniff do
  alias MimeSniff.MimeSniff.Sniffing

  @doc """

  ## Examples

    iex> MimeSniff.from_binary(<<104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 115, 33>>) # BitString of hello worlds!
    {:ok, "text/plain"}
  """
  @spec from_binary(binary(), keyword()) :: {:ok, String.t()} | {:error, atom()}
  def from_binary(data, opts \\ []), do: Sniffing.from_binary(data, opts)

  @doc """

  ## Examples

    iex> MimeSniff.from_file("support/fixtures/png_file.png")
    {:ok, "image/png"}
  """
  @spec from_file(binary(), keyword()) :: {:ok, String.t()} | {:error, atom()}
  def from_file(file_path, opts \\ []), do: Sniffing.from_file(file_path, opts)
end
