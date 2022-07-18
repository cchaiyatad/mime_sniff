defmodule MimeSniff.LexiconTest do
  use ExUnit.Case
  alias MimeSniff.Lexicon

  describe "is_ws?/1" do
    test "return true when input is satisfy" do
      assert Lexicon.is_ws?(<<0x09>>)
      assert Lexicon.is_ws?(<<0x0A>>)
      assert Lexicon.is_ws?(<<0x0C>>)
      assert Lexicon.is_ws?(<<0x0D>>)
      assert Lexicon.is_ws?(<<0x20>>)
    end

    test "return false when input is not satisfy" do
      refute Lexicon.is_ws?(<<0x00>>)
      refute Lexicon.is_ws?(<<0x61>>)
      refute Lexicon.is_ws?(<<224, 184, 129>>)
      refute Lexicon.is_ws?(<<0x09, 0x0A>>)
    end
  end

  describe "is_tt?/1" do
    test "return true when input is satisfy" do
      assert Lexicon.is_tt?(<<0x20>>)
      assert Lexicon.is_tt?(<<0x3E>>)
    end

    test "return false when input is not satisfy" do
      refute Lexicon.is_tt?(<<0x00>>)
      refute Lexicon.is_tt?(<<0x61>>)
      refute Lexicon.is_tt?(<<224, 184, 129>>)
      refute Lexicon.is_tt?(<<0x20, 0x0A>>)
    end
  end
end
