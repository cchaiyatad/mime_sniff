defmodule MimeSniff.Signature do
  @callback match(signature :: term(), data :: String.t()) ::
              {:ok, String.t()} | {:error, reason :: atom()}
end
