# MimeSniff

A MIME Type detection by magic number for Elixir.

MimeSniff implements the [MIME Sniffing Standard](https://mimesniff.spec.whatwg.org) which detect MIME Type from few bytes sequence at the beginning of a file or binary input. This work is faster than calling `System.cmd("file", ["--mime-type", file_path]` by about 50 times (see [benchmark](#benchmark)).

## Installation

The package can be installed by adding `mime_sniff` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:mime_sniff, "~> 0.1.0"}
  ]
end
```

## Example

``` elixir
iex> MimeSniff.from_file("path/to/png_file.png")
{:ok, "image/png"}

iex> MimeSniff.from_binary(" <h1>Hello, World!<h1/>   ")
{:ok, "text/html"}

# only read 32 bytes, if not provided default is 512 bytes
iex> MimeSniff.from_file("path/to/jpg_file.jpg", sniff_len: 32)
{:ok, "image/jpeg"}
```

## Support types

This library support most of the MIME Type defined in [MIME Sniffing Standard](https://mimesniff.spec.whatwg.org). See [Support types](/docs/support_types.md) for the full list.

## Benchmark

The benchmark result shows that MimeSniff, compared to `System.cmd("file", ["--mime-type", file_path])`, is about 50 times faster with one file and more than 100 times faster with 10,000 files.

Full result can be found in [bench_result](/docs/bench_result).

or you can run it yourself by executing `mix bench`. This command will execute [benchmark.exs](support/benchmark.exs) file.

## License

MimeSniff is released under the MIT License - see the [LICENSE](LICENSE.md) file.

This work is an implemented from mimesniff[https://mimesniff.spec.whatwg.org] that was licensed under [Creative Commons Attribution 4.0 International Public License](https://creativecommons.org/licenses/by/4.0/)
