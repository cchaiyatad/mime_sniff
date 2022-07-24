defmodule MimeSniff.Signatures.HTMLSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """

  defstruct byte_pattern: <<>>, pattern_mask: nil
end
