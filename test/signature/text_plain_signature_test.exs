defmodule MimeSniff.TextPlainSignatureTest do
  use ExUnit.Case
  alias MimeSniff.TextPlainSignature

  describe "match/2" do
    test "return {:ok, text/plain} with valid input" do
      # hello worlds!
      text_data = <<104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 115, 33>>

      assert TextPlainSignature.match(%TextPlainSignature{}, text_data) == {:ok, "text/plain"}
    end

    test "return {:error, :not_match} with binary data input" do
      binary_data = <<37, 80, 68, 70, 45, 0, 49, 46, 53, 10, 37, 208>>

      assert TextPlainSignature.match(%TextPlainSignature{}, binary_data) == {:error, :not_match}
    end
  end
end
