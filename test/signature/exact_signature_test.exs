defmodule MimeSniff.Signature.ExactSignatureTest do
  use ExUnit.Case
  alias MimeSniff.Signature.ExactSignature

  @png_byte_pattern <<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A>>
  @png_signature %ExactSignature{byte_pattern: @png_byte_pattern, mime_type: "image/png"}
  describe "match/2" do
    test "return {:ok, image/png} with valid png input" do
      png_data = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13>>

      assert ExactSignature.match(@png_signature, png_data) == {:ok, "image/png"}
    end

    test "return {:error, :not_match} with pdf input" do
      pdf_data = <<37, 80, 68, 70, 45, 49, 46, 53, 10, 37, 208>>

      assert ExactSignature.match(@png_signature, pdf_data) == {:error, :not_match}
    end
  end
end
