defmodule MimeSniff.Signatures.MP3SignatureTest do
  use ExUnit.Case

  alias MimeSniff.Signatures.MP3Signature
  alias MimeSniff.Signatures.Signature
  alias MimeSniff.Sniffing

  # MPEG1 Layer III, 128 kbit/s, 44.1 kHz, no padding -> 417-byte frames
  @mpeg1_header <<0xFF, 0xFB, 0x90, 0x00>>
  @mpeg1_frame_size 417

  # MPEG2.5 Layer III, 80 kbit/s, 11.025 kHz, no padding -> 522-byte frames
  @mpeg25_header <<0xFF, 0xE3, 0x90, 0x00>>
  @mpeg25_frame_size 522

  # MPEG1 Layer III, 128 kbit/s, 44.1 kHz, with padding -> 418-byte frames
  @mpeg1_padded_header <<0xFF, 0xFB, 0x92, 0x00>>
  @mpeg1_padded_frame_size 418

  describe "Signature.match/2 for MP3Signature" do
    test "return {:ok, mime_type} for two consecutive valid frames" do
      assert Signature.match(%MP3Signature{}, frames(@mpeg1_header, @mpeg1_frame_size)) ==
               {:ok, "audio/mpeg"}

      assert Signature.match(%MP3Signature{}, frames(@mpeg25_header, @mpeg25_frame_size)) ==
               {:ok, "audio/mpeg"}

      assert Signature.match(
               %MP3Signature{},
               frames(@mpeg1_padded_header, @mpeg1_padded_frame_size)
             ) ==
               {:ok, "audio/mpeg"}
    end

    test "return {:error, :not_match} when the second frame header is invalid" do
      data = pad_to(@mpeg1_header, @mpeg1_frame_size) <> <<0x00, 0x00, 0x00, 0x00>>

      assert Signature.match(%MP3Signature{}, data) == {:error, :not_match}
    end

    test "return {:error, :not_match} when data ends before the second frame" do
      data = pad_to(@mpeg1_header, @mpeg1_frame_size)

      assert Signature.match(%MP3Signature{}, data) == {:error, :not_match}
    end

    test "return {:error, :not_match} for invalid first headers" do
      # bitrate-index 15
      assert Signature.match(%MP3Signature{}, <<0xFF, 0xFB, 0xF0, 0x00>>) == {:error, :not_match}
      # samplerate-index 3
      assert Signature.match(%MP3Signature{}, <<0xFF, 0xFB, 0x9C, 0x00>>) == {:error, :not_match}
      # layer 0
      assert Signature.match(%MP3Signature{}, <<0xFF, 0xF9, 0x90, 0x00>>) == {:error, :not_match}
      # not a sync word
      assert Signature.match(%MP3Signature{}, <<0xFF, 0x1B, 0x90, 0x00>>) == {:error, :not_match}
      # free-format bitrate (frame size would be 0)
      assert Signature.match(%MP3Signature{}, frames(<<0xFF, 0xFB, 0x00, 0x00>>, 4)) ==
               {:error, :not_match}

      # too short
      assert Signature.match(%MP3Signature{}, <<0xFF, 0xFB, 0x90>>) == {:error, :not_match}
    end
  end

  describe "from_binary/2" do
    test "identifies a raw MP3 stream without an ID3 tag" do
      assert Sniffing.from_binary(frames(@mpeg1_header, @mpeg1_frame_size)) == {:ok, "audio/mpeg"}
    end

    test "an ID3-tagged MP3 is still identified by its ID3 signature" do
      assert Sniffing.from_binary("ID3" <> <<0x04, 0x00, 0x00>>) == {:ok, "audio/mpeg"}
    end

    test "a lone frame header followed by garbage is not identified as audio" do
      data = pad_to(@mpeg1_header, @mpeg1_frame_size) <> "garbage!"

      assert Sniffing.from_binary(data) == {:ok, "application/octet-stream"}
    end
  end

  defp frames(header, frame_size) do
    pad_to(header, frame_size) <> pad_to(header, frame_size)
  end

  defp pad_to(header, frame_size) do
    header <> :binary.copy(<<0x00>>, frame_size - byte_size(header))
  end
end
