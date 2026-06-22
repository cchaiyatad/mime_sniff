defmodule MimeSniff.GuardsTest do
  use ExUnit.Case
  import MimeSniff.Guards

  defp ws?(token) when is_ws(token), do: true
  defp ws?(_token), do: false

  defp tt?(token) when is_tt(token), do: true
  defp tt?(_token), do: false

  defp bd?(token) when is_bd(token), do: true
  defp bd?(_token), do: false

  describe "is_ws/1" do
    test "return true when input is satisfy" do
      assert ws?(<<0x09>>)
      assert ws?(<<0x0A>>)
      assert ws?(<<0x0C>>)
      assert ws?(<<0x0D>>)
      assert ws?(<<0x20>>)
    end

    test "return false when input is not satisfy" do
      refute ws?(<<0x00>>)
      refute ws?(<<0x61>>)
      refute ws?(<<224, 184, 129>>)
      refute ws?(<<0x09, 0x0A>>)
    end
  end

  describe "is_tt/1" do
    test "return true when input is satisfy" do
      assert tt?(<<0x20>>)
      assert tt?(<<0x3E>>)
    end

    test "return false when input is not satisfy" do
      refute tt?(<<0x00>>)
      refute tt?(<<0x61>>)
      refute tt?(<<224, 184, 129>>)
      refute tt?(<<0x20, 0x0A>>)
    end
  end

  describe "is_bd/1" do
    test "return true when input is satisfy" do
      valid_tokens =
        Enum.to_list(0x00..0x08) ++ [0x0B] ++ Enum.to_list(0x0E..0x1A) ++ Enum.to_list(0x1C..0x1F)

      assert Enum.all?(valid_tokens, &bd?(<<&1>>))
    end

    test "return false when input is not satisfy" do
      refute bd?(<<0x61>>)
      refute bd?(<<224, 184, 129>>)
      refute bd?(<<0x1A, 0x0A>>)
    end
  end
end
