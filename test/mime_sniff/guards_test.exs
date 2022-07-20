defmodule MimeSniff.GuardsTest do
  use ExUnit.Case
  import MimeSniff.Guards

  defp is_ws?(token) when is_ws(token), do: true
  defp is_ws?(_token), do: false

  defp is_tt?(token) when is_tt(token), do: true
  defp is_tt?(_token), do: false

  defp is_bd?(token) when is_bd(token), do: true
  defp is_bd?(_token), do: false

  describe "is_ws/1" do
    test "return true when input is satisfy" do
      assert is_ws?(<<0x09>>)
      assert is_ws?(<<0x0A>>)
      assert is_ws?(<<0x0C>>)
      assert is_ws?(<<0x0D>>)
      assert is_ws?(<<0x20>>)
    end

    test "return false when input is not satisfy" do
      refute is_ws?(<<0x00>>)
      refute is_ws?(<<0x61>>)
      refute is_ws?(<<224, 184, 129>>)
      refute is_ws?(<<0x09, 0x0A>>)
    end
  end

  describe "is_tt/1" do
    test "return true when input is satisfy" do
      assert is_tt?(<<0x20>>)
      assert is_tt?(<<0x3E>>)
    end

    test "return false when input is not satisfy" do
      refute is_tt?(<<0x00>>)
      refute is_tt?(<<0x61>>)
      refute is_tt?(<<224, 184, 129>>)
      refute is_tt?(<<0x20, 0x0A>>)
    end
  end

  describe "is_bd/1" do
    test "return true when input is satisfy" do
      valid_tokens =
        Enum.to_list(0x00..0x08) ++ [0x0B] ++ Enum.to_list(0x0E..0x1A) ++ Enum.to_list(0x1C..0x1F)

      assert Enum.all?(valid_tokens, &is_bd?(<<&1>>))
    end

    test "return false when input is not satisfy" do
      refute is_bd?(<<0x61>>)
      refute is_bd?(<<224, 184, 129>>)
      refute is_bd?(<<0x1A, 0x0A>>)
    end
  end
end
