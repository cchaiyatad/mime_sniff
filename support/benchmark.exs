test_file_paths =
  [
    "support/fixtures/empty_file",
    "support/fixtures/text_as_jpg.jpg",
    "support/fixtures/text_as_png.png",
    "support/fixtures/text_file.txt",
    "support/fixtures/utf8_file.txt",
    "support/fixtures/utf16_file.txt",
    "support/fixtures/text_file_with_only_blank_space",
    "support/fixtures/png_file.png",
    "support/fixtures/png_file_as_jpg.jpg",
    "support/fixtures/jpg_file.jpg",
    "support/fixtures/jpg_file_as_png.png",
    "support/fixtures/google.html",
    "support/fixtures/pdf_file.pdf",
    "support/fixtures/mp4_file.mp4",
    "support/fixtures/excel_file.xlsx",
    "support/fixtures/csv_file.csv",
    "support/fixtures/bd_at_60_file",
    "support/fixtures/utf8_file.txt",
    "support/fixtures/utf8_file.txt",
    "support/fixtures/bd_at_60_file"
  ]
  |> Stream.cycle()

inputs = %{
  "1 file (empty_file)" => ["support/fixtures/empty_file"],
  "1 file (jpg)" => ["support/fixtures/jpg_file.jpg"],
  "1 file (png)" => ["support/fixtures/png_file.png"],
  "1 file (pdf)" => ["support/fixtures/pdf_file.pdf"],
  "100 files" => Enum.take(test_file_paths, 100),
  "10,000 files" => Enum.take(test_file_paths, 10_000)
}

Benchee.run(
  %{
    "file --mime-type" => fn input ->
      Enum.map(input, &System.cmd("file", ["--mime-type", &1]))
    end,
    "MimeSniff.from_file (512 bytes)" => fn input ->
      Enum.map(input, &MimeSniff.from_file(&1))
    end,
    "MimeSniff.from_file (64 bytes)" => fn input ->
      Enum.map(input, &MimeSniff.from_file(&1, sniff_len: 64))
    end
  },
  inputs: inputs,
  memory_time: 2
)
