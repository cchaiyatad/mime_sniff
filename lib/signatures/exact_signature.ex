defmodule MimeSniff.Signatures.ExactSignature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern
  """

  defstruct byte_pattern: <<>>, ignored_ws_leading_bytes: false, mime_type: ""
end
