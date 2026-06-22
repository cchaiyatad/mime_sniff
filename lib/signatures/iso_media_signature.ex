defmodule MimeSniff.Signatures.ISOMediaSignature do
  @moduledoc false
  @type t :: %__MODULE__{
          :ftyp_value => String.t(),
          :mime_type => String.t(),
          :ftyp_size => nonempty_binary()
        }

  defstruct ftyp_value: "", mime_type: "", ftyp_size: 4
end

defimpl MimeSniff.Signatures.Signature, for: MimeSniff.Signatures.ISOMediaSignature do
  alias MimeSniff.Helpers
  alias MimeSniff.Signatures.ISOMediaSignature

  @doc """
  Function is implemented as defined in
  [matching signature for mp4](https://mimesniff.spec.whatwg.org/#signature-for-mp4)
  """
  @spec match(ISOMediaSignature.t(), binary()) :: {:ok, String.t()} | {:error, atom()}
  def match(%ISOMediaSignature{} = signature, data) when is_binary(data) do
    with :ok <- validate_length(data),
         box_size <- get_box_size(data),
         :ok <- validate_box_size_length(data, box_size) do
      do_match(signature, data, box_size)
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
  defp get_box_size(<<h::bytes-size(4), _::binary>>), do: Helpers.b_big_endian_to_uint(h)

  # (6.2.1.5)
  defp validate_box_size_length(data, box_size) do
    case byte_size(data) < box_size or rem(box_size, 4) != 0 do
      true -> {:error, :not_match}
      false -> :ok
    end
  end

  defp do_match(
         %ISOMediaSignature{ftyp_size: ftyp_size} = signature,
         data,
         box_size
       ) do
    <<_raw_box_size::bytes-size(4), maybe_ftyp::bytes-size(4), maybe_value::bytes-size(ftyp_size),
      _::binary>> = data

    cond do
      # if sequence[4:8] != "ftyp" return false (6.2.1.6)
      maybe_ftyp != "ftyp" ->
        {:error, :not_match}

      # if sequence[8:11] != ftyp_value return true (6.2.1.7)
      maybe_value == signature.ftyp_value ->
        {:ok, signature.mime_type}

      true ->
        # skip first 16 bytes (6.2.1.8)
        remain = box_size - 16
        <<_::bytes-size(16), rest::bytes-size(remain), _rest::binary>> = data
        # begin the loop (6.2.1.9)
        iterating_check_size_box(signature, rest)
    end
  end

  defp iterating_check_size_box(_signature, <<>>), do: {:error, :not_match}

  # (6.2.1.9.1)
  defp iterating_check_size_box(
         %ISOMediaSignature{ftyp_size: ftyp_size, ftyp_value: ftyp_value, mime_type: mime_type} =
           signature,
         <<type::bytes-size(4), rest::binary>>
       ) do
    <<compare_type::bytes-size(ftyp_size), _rest::binary>> = type

    if compare_type == ftyp_value do
      {:ok, mime_type}
    else
      iterating_check_size_box(signature, rest)
    end
  end
end
