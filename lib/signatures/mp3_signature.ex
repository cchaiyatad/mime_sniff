defmodule MimeSniff.Signatures.MP3Signature do
  @moduledoc false
  @type t :: %__MODULE__{}

  defstruct []
end

defimpl MimeSniff.Signatures.Signature, for: MimeSniff.Signatures.MP3Signature do
  import Bitwise

  alias MimeSniff.Signatures.MP3Signature

  @mime_type "audio/mpeg"

  # Layer III bitrate tables in bits/s, indexed by the frame header's
  # bitrate-index. mp3_rates is used for MPEG1, mp25_rates for MPEG2/2.5.
  @mp3_rates {0, 32_000, 40_000, 48_000, 56_000, 64_000, 80_000, 96_000, 112_000, 128_000,
              160_000, 192_000, 224_000, 256_000, 320_000}
  @mp25_rates {0, 8_000, 16_000, 24_000, 32_000, 40_000, 48_000, 56_000, 64_000, 80_000, 96_000,
               112_000, 128_000, 144_000, 160_000}

  # sample-rate table, indexed by the frame header's samplerate-index.
  # MPEG2 divides these by 2 and MPEG2.5 by 4 during frame parsing.
  @sample_rates {44_100, 48_000, 32_000}

  @doc """
  Function is implemented as defined in
  [matching signature for mp3 without id3](https://mimesniff.spec.whatwg.org/#signature-for-mp3-without-id3):
  match an mp3 frame header, skip over that frame, and require a second valid
  header immediately after it.
  """
  @spec match(MP3Signature.t(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def match(%MP3Signature{}, data) when is_binary(data) do
    with :ok <- match_mp3_header(data, 0),
         frame_size = compute_frame_size(data),
         :ok <- validate_frame_size(data, frame_size),
         :ok <- match_mp3_header(data, frame_size) do
      {:ok, @mime_type}
    end
  end

  # (6.2.7) https://mimesniff.spec.whatwg.org/#match-an-mp3-header
  defp match_mp3_header(data, offset) do
    case data do
      <<_::binary-size(offset), 0xFF, b1, b2, _b3, _::binary>> ->
        layer = b1 |> band(0x06) |> bsr(1)
        bitrate_index = b2 |> band(0xF0) |> bsr(4)
        samplerate_index = b2 |> band(0x0C) |> bsr(2)

        valid_header? =
          band(b1, 0xE0) == 0xE0 and layer != 0 and 4 - layer == 3 and
            bitrate_index != 15 and samplerate_index != 3

        if valid_header?, do: :ok, else: {:error, :not_match}

      _ ->
        {:error, :not_match}
    end
  end

  # (6.2.8) parse an mp3 frame and (6.2.9) compute an mp3 frame size.
  # Deviation from the spec text: its literal scale selection ("if version is
  # 1, let scale be 72, else, let scale be 144") makes MPEG2/2.5 frame sizes
  # twice their real length, so the second-header check could never succeed
  # for those files. Real Layer III framing uses 144 for MPEG1 (version 3)
  # and 72 for MPEG2/2.5.
  defp compute_frame_size(<<_b0, b1, b2, _::binary>>) do
    version = b1 |> band(0x18) |> bsr(3)
    bitrate_index = b2 |> band(0xF0) |> bsr(4)
    samplerate_index = b2 |> band(0x0C) |> bsr(2)
    pad = b2 |> band(0x02) |> bsr(1)

    bitrate =
      case band(version, 0x01) do
        0 -> elem(@mp25_rates, bitrate_index)
        _ -> elem(@mp3_rates, bitrate_index)
      end

    samplerate =
      case version do
        2 -> div(elem(@sample_rates, samplerate_index), 2)
        0 -> div(elem(@sample_rates, samplerate_index), 4)
        _ -> elem(@sample_rates, samplerate_index)
      end

    scale = if version == 3, do: 144, else: 72

    div(bitrate * scale, samplerate) + pad
  end

  defp validate_frame_size(data, frame_size) do
    case frame_size < 4 or frame_size + 4 > byte_size(data) do
      true -> {:error, :not_match}
      false -> :ok
    end
  end
end
