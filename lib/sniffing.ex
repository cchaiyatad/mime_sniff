defmodule MimeSniff.Sniffing do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#determining-the-computed-mime-type-of-a-resource
  """

  # https://mimesniff.spec.whatwg.org/#reading-the-resource-header
  @sniff_len 1445

  def sniff(data),
    do: @sniff_len
end
