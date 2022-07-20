defmodule MimeSniff.Signature do
  @callback match(signature :: term(), data :: String.t()) ::
              {:ok, String.t()} | {:error, reason :: atom()}

  @callback build(args :: list(term())) :: term()
end
