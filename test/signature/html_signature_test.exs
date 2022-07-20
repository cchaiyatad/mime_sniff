defmodule MimeSniff.HTMLSignatureTest do
  use ExUnit.Case
  alias MimeSniff.HTMLSignature

  @p_tag_byte_pattern <<0x3C, 0x50>>
  @p_tag_pattern_mask <<0xFF, 0xDF>>
  @p_tag_signature %HTMLSignature{
    byte_pattern: @p_tag_byte_pattern,
    pattern_mask: @p_tag_pattern_mask
  }

  describe "match/2" do
    test "return {:ok, image/png} with valid p tag upper case input" do
      # '          <P '
      p_tag_data = <<32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 80, 32, 0>>

      assert HTMLSignature.match(@p_tag_signature, p_tag_data) == {:ok, "text/html"}
    end

    test "return {:ok, image/png} with valid p tag lower case input" do
      # <p>
      p_tag_data = <<60, 112, 62, 0>>

      assert HTMLSignature.match(@p_tag_signature, p_tag_data) == {:ok, "text/html"}
    end

    test "return {:error, :not_match} with png input" do
      png_data = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13>>
      assert HTMLSignature.match(@p_tag_signature, png_data) == {:error, :not_match}
    end
  end
end
