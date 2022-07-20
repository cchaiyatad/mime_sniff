defmodule MimeSniff.Helpers do
  @moduledoc false
  def c_to_b(<<c::bytes-size(1)>>), do: :binary.decode_unsigned(c)
end
