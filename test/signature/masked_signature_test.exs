defmodule MimeSniff.MaskedSignatureTest do
  use ExUnit.Case
  alias MimeSniff.MaskedSignature

  @utf_16be_bom_byte_pattern <<0xFE, 0xFF, 0x00, 0x00>>
  @utf_16be_bom_pattern_mask <<0xFF, 0xFF, 0x00, 0x00>>
  @utf_16be_bom_signature %MaskedSignature{
    byte_pattern: @utf_16be_bom_byte_pattern,
    pattern_mask: @utf_16be_bom_pattern_mask,
    mime_type: "text/plain"
  }

  describe "match/2" do
    test "return {:ok, text/plain} with valid utf_16be_bom input" do
      xml_data = <<254, 255, 15, 32>>
      assert MaskedSignature.match(@utf_16be_bom_signature, xml_data) == {:ok, "text/plain"}
    end
  end
end
