defmodule MimeSniff.Signatures.MP4Signature do
  @moduledoc false

  defstruct []
end

defimpl MimeSniff.Signatures.Signature, for: MimeSniff.Signatures.MP4Signature do
  @moduledoc """
  Functions in this module were implemented
  as defined in https://mimesniff.spec.whatwg.org/#signature-for-mp4
  """

  alias MimeSniff.Helpers
  alias MimeSniff.Signatures.MP4Signature

  @mime_type "video/mp4"

  def match(%MP4Signature{}, data) when is_binary(data) do
    with :ok <- validate_length(data),
         box_size <- get_box_size(data),
         :ok <- validate_box_size_length(data, box_size) do
      do_match(data, box_size)
    end
  end

  # (6.2.1.3)
  defp validate_length(data) do
    case byte_size(data) < 12 do
      true -> {:error, :not_match}
      false -> :ok
    end
  end

  # (6.2.1.4)
  defp get_box_size(<<h::bytes-size(4), _::binary()>>), do: Helpers.b_big_endian_to_uint(h)

  # (6.2.1.5)
  defp validate_box_size_length(data, box_size) do
    case byte_size(data) < box_size or rem(box_size, 4) != 0 do
      true -> {:error, :not_match}
      false -> :ok
    end
  end

  defp do_match(
         <<_raw_box_size::bytes-size(4), maybe_ftyp::bytes-size(4), maybe_mp4::bytes-size(3),
           _::binary()>> = data,
         box_size
       ) do
    cond do
      # if sequence[4:8] != "ftyp" return false (6.2.1.6)
      maybe_ftyp != "ftyp" ->
        {:error, :not_match}

      # if sequence[8:11] != "mp4" return true (6.2.1.7)
      maybe_mp4 == "mp4" ->
        {:ok, @mime_type}

      true ->
        # skip first 16 bytes (6.2.1.8)
        remain = box_size - 16
        <<_::bytes-size(16), rest::bytes-size(remain), _rest::binary()>> = data
        # begin the loop (6.2.1.9)
        iterating_check_size_box(rest)
    end
  end

  defp iterating_check_size_box(<<>>), do: {:error, :not_match}

  # (6.2.1.9.1)
  defp iterating_check_size_box(<<d::bytes-size(3), _::binary()>>) when d == "mp4",
    do: {:ok, @mime_type}

  # (6.2.1.9.2)
  defp iterating_check_size_box(<<_::bytes-size(4), rest::binary()>>),
    do: iterating_check_size_box(rest)
end
