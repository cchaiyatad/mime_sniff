defmodule MimeSniff.Helpers do
  @moduledoc false

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
end
