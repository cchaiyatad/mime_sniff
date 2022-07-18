defmodule MimeSniff.Lexicon do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#terminology
  """

  @doc """
  A whitespace byte (abbreviated 0xWS) is any one of the following bytes:
  0x09 (HT), 0x0A (LF), 0x0C (FF), 0x0D (CR), 0x20 (SP).
  """
  @spec is_ws?(binary()) :: boolean
  def is_ws?(token) when token in [<<0x09>>, <<0x0A>>, <<0x0C>>, <<0x0D>>, <<0x20>>], do: true
  def is_ws?(_token), do: false

  @doc """
  A tag-terminating byte (abbreviated 0xTT) is any one of the following bytes:
  0x20 (SP), 0x3E (">").
  """
  @spec is_tt?(binary()) :: boolean
  def is_tt?(token) when token in [<<0x20>>, <<0x3E>>], do: true
  def is_tt?(_token), do: false
end
