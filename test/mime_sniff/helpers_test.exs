defmodule MimeSniff.HelpersTest do
  use ExUnit.Case
  alias MimeSniff.Helpers

  describe "c_to_b/1" do
    test "return correct byte from string with length = 1" do
      assert Helpers.c_to_b("0") == 48
      assert Helpers.c_to_b("9") == 57
      assert Helpers.c_to_b("A") == 65
      assert Helpers.c_to_b("z") == 122
      assert Helpers.c_to_b(<<0>>) == 0
      assert Helpers.c_to_b(<<20>>) == 20
    end
  end

  describe "b_big_endian_to_uint/1" do
    test "return uint given bytes in big endian" do
      assert Helpers.b_big_endian_to_uint(<<0x00, 0x00, 0x00, 0x1E>>) == 30
      assert Helpers.b_big_endian_to_uint(<<0x00, 0x4A, 0x00, 0x1E>>) == 4_849_694
    end
  end
end
