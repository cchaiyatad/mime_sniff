defprotocol MimeSniff.Signatures.Signature do
  @moduledoc """
  This protocol defines the API for Struct to be implemented
  in order to use with matching signature function.

  There are some out-of-the-box predefine signature such as `MimeSniff.Signatures.ExactSignature`
  and `MimeSniff.Signatures.MaskedSignature`. Please visit them for more infomation and examples.
  """

  @doc """
  Perform the matching with binary data by matching algorithm define in signature.
  """
  @spec match(signature :: term(), data :: binary()) ::
          {:ok, String.t()} | {:error, reason :: atom()}
  def match(signature, data)
end
