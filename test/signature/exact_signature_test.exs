defmodule MimeSniff.ExactSignatureTest do
  use ExUnit.Case
  alias MimeSniff.ExactSignature

  @png_byte_pattern <<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A>>
  @png_signature %ExactSignature{byte_pattern: @png_byte_pattern, mime_type: "image/png"}

  @xml_byte_pattern <<0x3C, 0x3F, 0x78, 0x6D, 0x6C>>
  @xml_signature %ExactSignature{
    byte_pattern: @xml_byte_pattern,
    mime_type: "text/xml",
    ignored_ws_leading_bytes: true
  }

  describe "match/2" do
    test "return {:ok, image/png} with valid png input" do
      png_data = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13>>

      assert ExactSignature.match(@png_signature, png_data) == {:ok, "image/png"}
    end

    test "return {:error, :not_match} with pdf input" do
      pdf_data = <<37, 80, 68, 70, 45, 49, 46, 53, 10, 37, 208>>

      assert ExactSignature.match(@png_signature, pdf_data) == {:error, :not_match}
    end

    test "return {:ok, text/xml} with valid xml input" do
      # "    <?xml  "
      xml_data = <<32, 32, 32, 32, 60, 63, 120, 109, 108, 32, 32>>
      assert ExactSignature.match(@xml_signature, xml_data) == {:ok, "text/xml"}
    end
  end
end
