defmodule MimeSniff.MimeSniff.SignaturesTest do
  use ExUnit.Case

  alias MimeSniff.MimeSniff.Signatures

  alias MimeSniff.Signatures.{
    ExactSignature,
    HTMLSignature,
    MaskedSignature,
    MP4Signature,
    TextPlainSignature
  }

  describe "get_default_signatures/1" do
    test "return list of signature from default_signatures file" do
      default_signatures = Signatures.get_default_signatures()

      assert length(default_signatures) == 49

      assert default_signatures == [
               %HTMLSignature{
                 byte_pattern: "<!DOCTYPE HTML",
                 pattern_mask:
                   <<255, 255, 223, 223, 223, 223, 223, 223, 223, 255, 223, 223, 223, 223>>
               },
               %HTMLSignature{
                 byte_pattern: "<HTML",
                 pattern_mask: <<255, 223, 223, 223, 223>>
               },
               %HTMLSignature{
                 byte_pattern: "<HEAD",
                 pattern_mask: <<255, 223, 223, 223, 223>>
               },
               %HTMLSignature{
                 byte_pattern: "<SCRIPT",
                 pattern_mask: <<255, 223, 223, 223, 223, 223, 223>>
               },
               %HTMLSignature{
                 byte_pattern: "<IFRAME",
                 pattern_mask: <<255, 223, 223, 223, 223, 223, 223>>
               },
               %HTMLSignature{byte_pattern: "<H1", pattern_mask: <<255, 223, 255>>},
               %HTMLSignature{
                 byte_pattern: "<DIV",
                 pattern_mask: <<255, 223, 223, 223>>
               },
               %HTMLSignature{
                 byte_pattern: "<FONT",
                 pattern_mask: <<255, 223, 223, 223, 223>>
               },
               %HTMLSignature{
                 byte_pattern: "<TABLE",
                 pattern_mask: <<255, 223, 223, 223, 223, 223>>
               },
               %HTMLSignature{byte_pattern: "<A", pattern_mask: <<255, 223>>},
               %HTMLSignature{
                 byte_pattern: "<STYLE",
                 pattern_mask: <<255, 223, 223, 223, 223, 223>>
               },
               %HTMLSignature{
                 byte_pattern: "<TITLE",
                 pattern_mask: <<255, 223, 223, 223, 223, 223>>
               },
               %HTMLSignature{byte_pattern: "<B", pattern_mask: <<255, 223>>},
               %HTMLSignature{
                 byte_pattern: "<BODY",
                 pattern_mask: <<255, 223, 223, 223, 223>>
               },
               %HTMLSignature{byte_pattern: "<BR", pattern_mask: <<255, 223, 223>>},
               %HTMLSignature{byte_pattern: "<P", pattern_mask: <<255, 223>>},
               %HTMLSignature{
                 byte_pattern: "<!--",
                 pattern_mask: <<255, 255, 255, 255>>
               },
               %ExactSignature{
                 byte_pattern: "<?xml",
                 ignored_ws_leading_bytes: true,
                 mime_type: "text/xml"
               },
               %ExactSignature{
                 byte_pattern: "%PDF-",
                 mime_type: "application/pdf"
               },
               %ExactSignature{
                 byte_pattern: "%!PS-Adobe-",
                 mime_type: "application/postscript"
               },
               %MaskedSignature{
                 byte_pattern: <<254, 255, 0, 0>>,
                 mime_type: "text/plain",
                 pattern_mask: <<255, 255, 0, 0>>
               },
               %MaskedSignature{
                 byte_pattern: <<255, 254, 0, 0>>,
                 mime_type: "text/plain",
                 pattern_mask: <<255, 255, 0, 0>>
               },
               %MaskedSignature{
                 byte_pattern: <<239, 187, 191, 0>>,
                 mime_type: "text/plain",
                 pattern_mask: <<255, 255, 255, 0>>
               },
               %ExactSignature{
                 byte_pattern: <<0, 0, 1, 0>>,
                 mime_type: "image/x-icon"
               },
               %ExactSignature{
                 byte_pattern: <<0, 0, 2, 0>>,
                 mime_type: "image/x-icon"
               },
               %ExactSignature{
                 byte_pattern: "BM",
                 mime_type: "image/bmp"
               },
               %ExactSignature{
                 byte_pattern: "GIF87a",
                 mime_type: "image/gif"
               },
               %ExactSignature{
                 byte_pattern: "GIF89a",
                 mime_type: "image/gif"
               },
               %MaskedSignature{
                 byte_pattern: <<82, 73, 70, 70, 0, 0, 0, 0, 87, 69, 66, 80, 86, 80>>,
                 mime_type: "image/webp",
                 pattern_mask: <<255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255>>
               },
               %ExactSignature{
                 byte_pattern: <<137, 80, 78, 71, 13, 10, 26, 10>>,
                 mime_type: "image/png"
               },
               %ExactSignature{
                 byte_pattern: <<255, 216, 255>>,
                 mime_type: "image/jpeg"
               },
               %MaskedSignature{
                 byte_pattern: <<70, 79, 82, 77, 0, 0, 0, 0, 65, 73, 70, 70>>,
                 mime_type: "audio/aiff",
                 pattern_mask: <<255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255>>
               },
               %ExactSignature{
                 byte_pattern: "ID3",
                 mime_type: "audio/mpeg"
               },
               %ExactSignature{
                 byte_pattern: <<79, 103, 103, 83, 0>>,
                 mime_type: "application/ogg"
               },
               %ExactSignature{
                 byte_pattern: <<77, 84, 104, 100, 0, 0, 0, 6>>,
                 mime_type: "audio/midi"
               },
               %MaskedSignature{
                 byte_pattern: <<82, 73, 70, 70, 0, 0, 0, 0, 65, 86, 73, 32>>,
                 mime_type: "video/avi",
                 pattern_mask: <<255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255>>
               },
               %MaskedSignature{
                 byte_pattern: <<82, 73, 70, 70, 0, 0, 0, 0, 87, 65, 86, 69>>,
                 mime_type: "audio/wave",
                 pattern_mask: <<255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255>>
               },
               %MP4Signature{},
               %ExactSignature{
                 byte_pattern: <<26, 69, 223, 163>>,
                 mime_type: "video/webm"
               },
               %MaskedSignature{
                 byte_pattern:
                   <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 76, 80>>,
                 mime_type: "application/vnd.ms-fontobject",
                 pattern_mask:
                   <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 255, 255>>
               },
               %ExactSignature{
                 byte_pattern: <<0, 1, 0, 0>>,
                 mime_type: "font/ttf"
               },
               %ExactSignature{
                 byte_pattern: "OTTO",
                 mime_type: "font/otf"
               },
               %ExactSignature{
                 byte_pattern: "ttcf",
                 mime_type: "font/collection"
               },
               %ExactSignature{
                 byte_pattern: "wOFF",
                 mime_type: "font/woff"
               },
               %ExactSignature{
                 byte_pattern: "wOF2",
                 mime_type: "font/woff2"
               },
               %ExactSignature{
                 byte_pattern: <<31, 139, 8>>,
                 mime_type: "application/x-gzip"
               },
               %ExactSignature{
                 byte_pattern: <<80, 75, 3, 4>>,
                 mime_type: "application/zip"
               },
               %ExactSignature{
                 byte_pattern: <<82, 97, 114, 32, 26, 7, 0>>,
                 mime_type: "application/x-rar-compressed"
               },
               %TextPlainSignature{}
             ]
    end
  end
end
