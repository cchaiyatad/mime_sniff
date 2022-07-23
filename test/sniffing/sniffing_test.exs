defmodule MimeSniff.SniffingTest do
  use ExUnit.Case
  doctest MimeSniff
  alias MimeSniff.Sniffing

  describe "from_file/2" do
    test "return {:ok, mime_type} from file" do
      # text/plain
      assert Sniffing.from_file("test/support/fixtures/empty_file") == {:ok, "text/plain"}
      assert Sniffing.from_file("test/support/fixtures/text_as_jpg.jpg") == {:ok, "text/plain"}
      assert Sniffing.from_file("test/support/fixtures/text_as_png.png") == {:ok, "text/plain"}
      assert Sniffing.from_file("test/support/fixtures/text_file.txt") == {:ok, "text/plain"}
      assert Sniffing.from_file("test/support/fixtures/utf8_file.txt") == {:ok, "text/plain"}
      assert Sniffing.from_file("test/support/fixtures/utf16_file.txt") == {:ok, "text/plain"}

      assert Sniffing.from_file("test/support/fixtures/text_file_with_only_blank_space") ==
               {:ok, "text/plain"}

      # png
      assert Sniffing.from_file("test/support/fixtures/png_file.png") == {:ok, "image/png"}
      assert Sniffing.from_file("test/support/fixtures/png_file_as_jpg.jpg") == {:ok, "image/png"}

      # jpg
      assert Sniffing.from_file("test/support/fixtures/jpg_file.jpg") == {:ok, "image/jpeg"}

      assert Sniffing.from_file("test/support/fixtures/jpg_file_as_png.png") ==
               {:ok, "image/jpeg"}

      # html
      assert Sniffing.from_file("test/support/fixtures/google.html") == {:ok, "text/html"}

      # pdf
      assert Sniffing.from_file("test/support/fixtures/pdf_file.pdf") == {:ok, "application/pdf"}

      # excel
      assert Sniffing.from_file("test/support/fixtures/excel_file.xlsx") ==
               {:ok, "application/zip"}

      # csv
      assert Sniffing.from_file("test/support/fixtures/csv_file.csv") == {:ok, "text/plain"}

      # application/octet-stream (text file that has binary data byte)
      assert Sniffing.from_file("test/support/fixtures/bd_at_60_file") ==
               {:ok, "application/octet-stream"}
    end
  end

  describe "from_binary/2" do
  end
end
