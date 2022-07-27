defmodule MimeSniff.Guards do
  @moduledoc """
  Functions in this module were implemented as defined
  in [terminlogy](https://mimesniff.spec.whatwg.org/#terminology)
  """

  @whitespace_byte [<<0x09>>, <<0x0A>>, <<0x0C>>, <<0x0D>>, <<0x20>>]
  @tag_terminating_byte [<<0x20>>, <<0x3E>>]
  @binary_data_byte [
    <<0x00>>,
    <<0x01>>,
    <<0x02>>,
    <<0x03>>,
    <<0x04>>,
    <<0x05>>,
    <<0x06>>,
    <<0x07>>,
    <<0x08>>,
    <<0x0B>>,
    <<0x0E>>,
    <<0x0F>>,
    <<0x10>>,
    <<0x11>>,
    <<0x12>>,
    <<0x13>>,
    <<0x14>>,
    <<0x15>>,
    <<0x16>>,
    <<0x17>>,
    <<0x18>>,
    <<0x19>>,
    <<0x1A>>,
    <<0x1C>>,
    <<0x1D>>,
    <<0x1E>>,
    <<0x1F>>
  ]

  @doc """
  A gaurd that returns true if term is a whitespace byte;
  otherwise returns false.

  A whitespace byte is any one of the following bytes:
  0x09 (HT), 0x0A (LF), 0x0C (FF), 0x0D (CR), 0x20 (SP).
  """
  defguard is_ws(token) when token in @whitespace_byte

  @doc """
  A gaurd that returns true if term is a tag-terminating byte;
  otherwise returns false.

  A tag-terminating byte is any one of the following bytes:
  0x20 (SP), 0x3E (">").
  """
  defguard is_tt(token) when token in @tag_terminating_byte

  @doc """
  A gaurd that returns true if term is a binary data byte;
  otherwise returns false.

  A binary data byte is a byte in the range 0x00 to 0x08 (NUL to BS),
  the byte 0x0B (VT), a byte in the range 0x0E to 0x1A (SO to SUB),
  or a byte in the range 0x1C to 0x1F (FS to US).
  """
  defguard is_bd(token) when token in @binary_data_byte
end
