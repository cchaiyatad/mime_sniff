defprotocol MimeSniff.Matchable do
  @spec match(signature :: term(), data :: String.t()) ::
          {:ok, String.t()} | {:error, reason :: atom()}
  def match(signature, data)
end
