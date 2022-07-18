defmodule MimeSniff.Sniffing do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#determining-the-computed-mime-type-of-a-resource
  """
  import MimeSniff.Guard
  alias MimeSniff.Mime

  # https://mimesniff.spec.whatwg.org/#reading-the-resource-header
  @sniff_len 1445

  def sniff(data) when is_binary(data),
    do: do_sniff(data, %Mime{})

  def sniff(_), do: {:error, :invalid_input}

  defp do_sniff(<<token::bytes-size(1), rest::binary>>, acc) when is_ws(token),
    do: do_sniff(rest, acc)

  defp do_sniff(rest, acc), do: rest
end
