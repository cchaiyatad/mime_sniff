defmodule MimeSniff.Guard do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#terminology
  """

  @whitespace_byte [<<0x09>>, <<0x0A>>, <<0x0C>>, <<0x0D>>, <<0x20>>]
  @tag_terminating_byte [<<0x20>>, <<0x3E>>]

  @doc """
  A whitespace byte (abbreviated 0xWS) is any one of the following bytes:
  0x09 (HT), 0x0A (LF), 0x0C (FF), 0x0D (CR), 0x20 (SP).
  """
  defguard is_ws(token) when token in @whitespace_byte

  @doc """
  A tag-terminating byte (abbreviated 0xTT) is any one of the following bytes:
  0x20 (SP), 0x3E (">").
  """
  defguard is_tt(token) when token in @tag_terminating_byte
end
