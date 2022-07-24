# Support types

## A html, xml, pdf, postscript or UTF text type type [(more info)](https://mimesniff.spec.whatwg.org/#identifying-a-resource-with-an-unknown-mime-type)

| MIME Type | Note |
| --------- | ---- |
| text/html ||
| text/xml ||
| application/pdf ||
| application/postscript ||
| text/plain |UTF-16BE BOM<br/>UTF-16LE BOM<br/>UTF-8 BOM text file.|

## An image type [(more info)](https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern)

| MIME Type | Note |
| --------- | ---- |
| x-icon ||
| x-icon ||
| image/bmp ||
| image/gif ||
| image/gif ||
| image/webp ||
| image/png ||
| image/jpeg ||

## An audio or video type [(more info)](https://mimesniff.spec.whatwg.org/#matching-an-audio-or-video-type-pattern)

Currently, this application does not support sniffing [A MP3 without id3 type](https://mimesniff.spec.whatwg.org/#signature-for-mp3-without-id3)

| MIME Type | Note |
| --------- | ---- |
|audio/aiff||
|audio/mpeg||
|application/ogg||
|audio/midi||
|video/avi||
|audio/wave||
|video/mp4||
|*video/webm|only check first four bytes<br/>see [Matching a WebM type](https://mimesniff.spec.whatwg.org/#signature-for-webm).|

## A font type [(more info)](https://mimesniff.spec.whatwg.org/#matching-a-font-type-pattern)

| MIME Type | Note |
| --------- | ---- |
|application/vnd.ms-fontobject||
|font/ttf||
|font/otf||
|font/collection||
|font/woff||
|font/woff2||

## An archive type [(more info)](https://mimesniff.spec.whatwg.org/#matching-an-archive-type-pattern)

| MIME Type | Note |
| --------- | ---- |
|application/x-gzip||
|application/zip||
|application/x-rar-compressed||

## Other

| MIME Type | Note |
| --------- | ---- |
|text/plain|if content contains no binary data bytes|
|application/octet-stream|if not match anything else|
