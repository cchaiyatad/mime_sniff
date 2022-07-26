# Support types

The tables below show the support MIME Type and minimum number of bytes need to perform. If the length of data that is provided to the function is less than the minimum, the program will return unmatch immediately.

## A html, xml, pdf, postscript or UTF text type [(more info)](https://mimesniff.spec.whatwg.org/#identifying-a-resource-with-an-unknown-mime-type)

| MIME Type | Minimum number of bytes need to perform | Note |
| --------- | ---- | --- |
| text/html | 15 |   |
| text/xml | 5 |   |
| application/pdf | 5 |   |
| application/postscript | 11 |   |
| text/plain | 4 | UTF-16BE BOM, UTF-16LE BOM, and UTF-8 BOM text file. |

## An image type [(more info)](https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern)

| MIME Type | Minimum number of bytes need to perform | Note |
| --------- | ---- | --- |
| x-icon | 4 |   |
| x-icon | 4 |   |
| image/bmp | 2 |   |
| image/gif | 6 |   |
| image/gif | 6 |   |
| image/webp | 14 |   |
| image/png | 8 |   |
| image/jpeg | 3 |   |

## An audio or video type [(more info)](https://mimesniff.spec.whatwg.org/#matching-an-audio-or-video-type-pattern)

Currently, this application does not support sniffing [A MP3 without id3 type](https://mimesniff.spec.whatwg.org/#signature-for-mp3-without-id3)

| MIME Type | Minimum number of bytes need to perform | Note |
| --------- | ---- | --- |
| audio/aiff | 12 |   |
| audio/mpeg | 3 |   |
| application/ogg | 5 |   |
| audio/midi | 8 |   |
| video/avi | 12 |   |
| audio/wave | 12 |   |
| video/mp4 | >12 | [how the algorithm work for mp4](https://mimesniff.spec.whatwg.org/#signature-for-mp4) |
| *video/webm | *4  |only check first four bytes see [Matching a WebM type](https://mimesniff.spec.whatwg.org/#signature-for-webm).|

## A font type [(more info)](https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern)

| MIME Type | Minimum number of bytes need to perform | Note |
| --------- | ---- | --- |
| application/vnd.ms-fontobject | 36 |   |
| font/ttf | 4 |   |
| font/otf | 4 |   |
| font/collection | 4 |   |
| font/woff | 4 |   |
| font/woff2 | 4 |   |

## An archive type [(more info)](https://mimesniff.spec.whatwg.org/#matching-an-archive-type-pattern)

| MIME Type | Minimum number of bytes need to perform | Note |
| --------- | ---- | --- |
| application/x-gzip | 3 |   |
| application/zip | 4 |   |
| application/x-rar-compressed | 7 |   |

## Other

| MIME Type | Minimum number of bytes need to perform | Note |
| --------- | ---- | --- |
|text/plain|0|if content contains no binary data bytes|
|application/octet-stream|1|if not match anything else|
