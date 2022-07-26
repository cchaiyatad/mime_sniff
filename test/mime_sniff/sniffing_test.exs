defmodule MimeSniff.MimeSniff.SniffingTest do
  use ExUnit.Case
  alias MimeSniff.MimeSniff.Sniffing
  alias MimeSniff.Signatures.{ExactSignature, MaskedSignature}

  describe "from_file/2" do
    test "return {:ok, mime_type} from file" do
      # text/plain
      assert Sniffing.from_file("support/fixtures/empty_file") == {:ok, "text/plain"}
      assert Sniffing.from_file("support/fixtures/text_as_jpg.jpg") == {:ok, "text/plain"}
      assert Sniffing.from_file("support/fixtures/text_as_png.png") == {:ok, "text/plain"}
      assert Sniffing.from_file("support/fixtures/text_file.txt") == {:ok, "text/plain"}
      assert Sniffing.from_file("support/fixtures/utf8_file.txt") == {:ok, "text/plain"}
      assert Sniffing.from_file("support/fixtures/utf16_file.txt") == {:ok, "text/plain"}

      assert Sniffing.from_file("support/fixtures/text_file_with_only_blank_space") ==
               {:ok, "text/plain"}

      # png
      assert Sniffing.from_file("support/fixtures/png_file.png") == {:ok, "image/png"}
      assert Sniffing.from_file("support/fixtures/png_file_as_jpg.jpg") == {:ok, "image/png"}

      # jpg
      assert Sniffing.from_file("support/fixtures/jpg_file.jpg") == {:ok, "image/jpeg"}

      assert Sniffing.from_file("support/fixtures/jpg_file_as_png.png") ==
               {:ok, "image/jpeg"}

      # html
      assert Sniffing.from_file("support/fixtures/google.html") == {:ok, "text/html"}

      # pdf
      assert Sniffing.from_file("support/fixtures/pdf_file.pdf") == {:ok, "application/pdf"}

      # mp4
      assert Sniffing.from_file("support/fixtures/mp4_file.mp4") == {:ok, "video/mp4"}

      # excel
      assert Sniffing.from_file("support/fixtures/excel_file.xlsx") ==
               {:ok, "application/zip"}

      # csv
      assert Sniffing.from_file("support/fixtures/csv_file.csv") == {:ok, "text/plain"}

      # application/octet-stream (text file that has binary data byte)
      assert Sniffing.from_file("support/fixtures/bd_at_30_file") ==
               {:ok, "application/octet-stream"}
    end

    test "return {:ok, mime_type} when provided custom signature" do
      custom_utf8_sig = %ExactSignature{byte_pattern: "UTF8", mime_type: "custom/utf8"}
      custom_utf16_sig = %ExactSignature{byte_pattern: "UTF16", mime_type: "custom/utf16"}

      assert Sniffing.from_file("support/fixtures/utf8_file.txt",
               custom_signatures: [custom_utf16_sig, custom_utf8_sig]
             ) ==
               {:ok, "custom/utf8"}
    end

    test "return {:error, :invalid_pattern} when provided custom signature is invalid" do
      invalid_sig = %MaskedSignature{
        byte_pattern: "UTF8",
        mime_type: "custom/invalid",
        pattern_mask: <<255, 255, 255>>
      }

      assert Sniffing.from_file("support/fixtures/utf8_file.txt",
               custom_signatures: [invalid_sig]
             ) == {:error, :invalid_pattern}
    end

    test "return {:ok, mime_type} when send sniff_len option" do
      # it return {:ok, "text/plain"} instead of {:ok, "application/octet-stream"}
      # because it only sniff to the part that doesn't have binary data bit
      assert Sniffing.from_file("support/fixtures/bd_at_30_file", sniff_len: 15) ==
               {:ok, "text/plain"}
    end
  end
end
