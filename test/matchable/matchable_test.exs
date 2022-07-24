defmodule MimeSniff.MatchableTest do
  use ExUnit.Case

  alias MimeSniff.{
    ExactSignature,
    HTMLSignature,
    MaskedSignature,
    Matchable,
    MP4Signature,
    TextPlainSignature
  }

  describe "match/2 with ExactSignature" do
    setup do
      png_byte_pattern = <<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A>>
      png_signature = %ExactSignature{byte_pattern: png_byte_pattern, mime_type: "image/png"}

      xml_byte_pattern = <<0x3C, 0x3F, 0x78, 0x6D, 0x6C>>

      xml_signature = %ExactSignature{
        byte_pattern: xml_byte_pattern,
        mime_type: "text/xml",
        ignored_ws_leading_bytes: true
      }

      {:ok, %{png_signature: png_signature, xml_signature: xml_signature}}
    end

    test "return {:ok, image/png} with valid png input", %{png_signature: png_signature} do
      png_data = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13>>

      assert Matchable.match(png_signature, png_data) == {:ok, "image/png"}
    end

    test "return {:error, :not_match} with pdf input", %{png_signature: png_signature} do
      pdf_data = <<37, 80, 68, 70, 45, 49, 46, 53, 10, 37, 208>>

      assert Matchable.match(png_signature, pdf_data) == {:error, :not_match}
    end

    test "return {:ok, text/xml} with valid xml input", %{xml_signature: xml_signature} do
      # "    <?xml  "
      xml_data = <<32, 32, 32, 32, 60, 63, 120, 109, 108, 32, 32>>
      assert Matchable.match(xml_signature, xml_data) == {:ok, "text/xml"}
    end
  end

  describe "match/2 with HTMLSignature" do
    setup do
      p_tag_byte_pattern = <<0x3C, 0x50>>
      p_tag_pattern_mask = <<0xFF, 0xDF>>

      p_tag_signature = %HTMLSignature{
        byte_pattern: p_tag_byte_pattern,
        pattern_mask: p_tag_pattern_mask
      }

      {:ok, %{p_tag_signature: p_tag_signature}}
    end

    test "return {:ok, image/png} with valid p tag upper case input", %{
      p_tag_signature: p_tag_signature
    } do
      # '          <P '
      p_tag_data = <<32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 60, 80, 32, 0>>

      assert Matchable.match(p_tag_signature, p_tag_data) == {:ok, "text/html"}
    end

    test "return {:ok, image/png} with valid p tag lower case input", %{
      p_tag_signature: p_tag_signature
    } do
      # <p>
      p_tag_data = <<60, 112, 62, 0>>

      assert Matchable.match(p_tag_signature, p_tag_data) == {:ok, "text/html"}
    end

    test "return {:error, :not_match} with png input", %{p_tag_signature: p_tag_signature} do
      png_data = <<137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13>>
      assert Matchable.match(p_tag_signature, png_data) == {:error, :not_match}
    end
  end

  describe "match/2 with MaskedSignature" do
    setup do
      utf_16be_bom_byte_pattern = <<0xFE, 0xFF, 0x00, 0x00>>
      utf_16be_bom_pattern_mask = <<0xFF, 0xFF, 0x00, 0x00>>

      utf_16be_bom_signature = %MaskedSignature{
        byte_pattern: utf_16be_bom_byte_pattern,
        pattern_mask: utf_16be_bom_pattern_mask,
        mime_type: "text/plain"
      }

      {:ok, %{utf_16be_bom_signature: utf_16be_bom_signature}}
    end

    test "return {:ok, text/plain} with valid utf_16be_bom input", %{
      utf_16be_bom_signature: utf_16be_bom_signature
    } do
      xml_data = <<254, 255, 15, 32>>
      assert Matchable.match(utf_16be_bom_signature, xml_data) == {:ok, "text/plain"}
    end
  end

  describe "match/2 with MP4Signature" do
    test "return {:ok, video/mp4} with valid input" do
      # first 64 bytes from mp4 file
      mp4_data =
        <<0, 0, 0, 32, 102, 116, 121, 112, 105, 115, 111, 109, 0, 0, 2, 0, 105, 115, 111, 109,
          105, 115, 111, 50, 97, 118, 99, 49, 109, 112, 52, 49, 0, 0, 68, 128, 109, 111, 111, 118,
          0, 0, 0, 108, 109, 118, 104, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 232>>

      assert Matchable.match(%MP4Signature{}, mp4_data) == {:ok, "video/mp4"}
    end

    test "return {:error, :not_match} when input length(data) < 12 (6.2.1.3)" do
      # first 10 bytes from mp4 file
      mp4_data = <<0, 0, 0, 32, 102, 116, 121, 112, 105, 115>>

      assert Matchable.match(%MP4Signature{}, mp4_data) == {:error, :not_match}
    end

    test "return {:error, :not_match} when length(data) is less than box_size (6.2.1.5)" do
      # first 32 bytes from mp4 file with box_size = 64
      mp4_data =
        <<0, 0, 0, 64, 102, 116, 121, 112, 105, 115, 111, 109, 0, 0, 2, 0, 105, 115, 111, 109,
          105, 115, 111, 50, 97, 118, 99, 49, 109, 112, 52, 49>>

      assert Matchable.match(%MP4Signature{}, mp4_data) == {:error, :not_match}
    end

    test "return {:error, :not_match} when box_size % 4 != 0, (6.2.1.5)" do
      # first 32 bytes from mp4 file with box_size = 18
      mp4_data =
        <<0, 0, 0, 18, 102, 116, 121, 112, 105, 115, 111, 109, 0, 0, 2, 0, 105, 115, 111, 109,
          105, 115, 111, 50, 97, 118, 99, 49, 109, 112, 52, 49>>

      assert Matchable.match(%MP4Signature{}, mp4_data) == {:error, :not_match}
    end

    test "return {:error, :not_match} with valid input" do
      # first 32 bytes from mp4 file with mp4 at bytes[29:32]
      mp4_data =
        <<0, 0, 0, 20, 102, 116, 121, 112, 105, 115, 111, 109, 0, 0, 2, 0, 105, 115, 111, 109,
          105, 115, 111, 50, 97, 118, 99, 49, 109, 112, 52, 49>>

      assert Matchable.match(%MP4Signature{}, mp4_data) == {:error, :not_match}
    end
  end

  describe "match/2 with TextPlainSignature" do
    test "return {:ok, text/plain} with valid input" do
      # hello worlds!
      text_data = <<104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 115, 33>>

      assert Matchable.match(%TextPlainSignature{}, text_data) == {:ok, "text/plain"}
    end

    test "return {:error, :not_match} with binary data input" do
      binary_data = <<37, 80, 68, 70, 45, 0, 49, 46, 53, 10, 37, 208>>

      assert Matchable.match(%TextPlainSignature{}, binary_data) == {:error, :not_match}
    end
  end
end
