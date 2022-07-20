defmodule MimeSniff do
  alias MimeSniff.Sniffing

  @spec from_binary(binary(), keyword()) :: {:ok, String.t()} | {:error, atom()}
  def from_binary(data, opts \\ []), do: Sniffing.from_binary(data, opts)

  @spec from_file(binary(), keyword()) :: {:ok, String.t()} | {:error, atom()}
  def from_file(file_path, opts \\ []), do: Sniffing.from_file(file_path, opts)
end
