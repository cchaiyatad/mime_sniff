defmodule MimeSniff.MaskedSignatureTest do
  use ExUnit.Case
  alias MimeSniff.MaskedSignature

  @xml_byte_pattern <<0x3C, 0x3F, 0x78, 0x6D, 0x6C>>
  @xml_pattern_mask <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>
  @xml_signature %MaskedSignature{
    byte_pattern: @xml_byte_pattern,
    pattern_mask: @xml_pattern_mask,
    mime_type: "text/xml",
    ignored_ws_leading_bytes: true
  }
  @utf_16be_bom_byte_pattern <<0xFE, 0xFF, 0x00, 0x00>>
  @utf_16be_bom_pattern_mask <<0xFF, 0xFF, 0x00, 0x00>>
  @utf_16be_bom_signature %MaskedSignature{
    byte_pattern: @utf_16be_bom_byte_pattern,
    pattern_mask: @utf_16be_bom_pattern_mask,
    mime_type: "text/plain"
  }

  describe "match/2" do
    test "return {:ok, text/xml} with valid xml input" do
      # "    <?xml  "
      xml_data = <<32, 32, 32, 32, 60, 63, 120, 109, 108, 32, 32>>
      assert MaskedSignature.match(@xml_signature, xml_data) == {:ok, "text/xml"}
    end

    test "return {:ok, text/plain} with valid utf_16be_bom input" do
      xml_data = <<254, 255, 15, 32>>
      assert MaskedSignature.match(@utf_16be_bom_signature, xml_data) == {:ok, "text/plain"}
    end
  end
end
