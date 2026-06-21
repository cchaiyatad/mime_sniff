defmodule MimeSniff.Helpers do
  @moduledoc false

  def c_to_b(<<c::bytes-size(1)>>), do: :binary.decode_unsigned(c)

  def b_big_endian_to_uint(b), do: :binary.decode_unsigned(b)

  def read_byte_from_file(file_path, len) do
    file = File.open!(file_path, [:read, :binary])

    try do
      case IO.binread(file, len) do
        :eof -> <<>>
        data -> data
      end
    after
      File.close(file)
    end
  end
end
