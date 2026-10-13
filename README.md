# Parsec Dev toolbox

A [Parsec](https://github.com/abidibo/parsec) plugin for the small jobs you'd
otherwise open a sketchy website for. Fully offline, no dependencies.

```
dev                        a fresh UUID v4 and v7, the Unix time now
dev 1739000000             the date: 2025-02-08 08:33:20 CET, and in UTC
dev 2026-10-13 14:00       the Unix time, in seconds and milliseconds
dev eyJhbGciOiJIUzI1NiJ9…  the JWT: algorithm, subject, expiry; Enter lists the claims
dev #ff8800                the colour as hex, rgb() and hsl(), with a swatch
dev aGVsbG8=               the decoded base64
dev caf%C3%A9              the decoded URL
dev any text               its base64, URL encoding, SHA-256, SHA-1, MD5 and SHA-512
```

Type `dev` and the input: every tool that recognises it answers with a row,
best guess first. Enter pastes the result into the window you came from
(copies it, without the Parsec Shell extension); Tab copies it or offers
variants: uppercase UUIDs, base64url, ISO 8601, `+` for spaces.

## Install

```sh
parsec plugin install https://github.com/abidibo/parsec-devtools
```

or Settings › Plugins › install from the git URL, a `.zip` or a folder.
Needs Python 3.8+ and nothing else.

## What it recognises

- **Unix time**: 9 to 20 digits. The length picks the unit: up to 11 digits
  are seconds, then milliseconds, microseconds and nanoseconds. Shorter
  numbers need `dev time 12345`.
- **Dates**: `2026-10-13`, `2026-10-13 14:00`, `2026-10-13T14:00:00.5Z`,
  `2026-10-13 14:00 +02:00`. Without a zone the date is local time.
  `dev now` gives the current time in every form.
- **JWTs**: `header.payload.signature`, with or without `Bearer `. The
  signature is **not verified**: this reads a token, it doesn't trust it.
  Enter opens the claims; `exp`, `iat`, `nbf` show as dates.
- **Colours**: `#f80`, `#ff8800`, `#ff880080`, `rgb(255, 136, 0)`,
  `rgb(255 136 0 / 50%)`, `hsl(32, 100%, 50%)`, `hsla(…)`. Bare hex counts with
  6 or 8 digits; the format you typed is listed last.
- **base64 and URL encoding**: decoded when the result is readable text.
- **Anything else**: encoded and hashed. Parsec trims spaces before the text
  but not after it, so a hash of text ending in a space says so.

## Picking one tool

A tool word followed by a space skips the guessing:

| Type | Gets |
|---|---|
| `dev uuid` | UUIDs |
| `dev time …` (`date`, `epoch`) | Unix time or date; empty or `now` for now |
| `dev jwt …` | the JWT, or why it isn't one |
| `dev color …` (`colour`) | the colour; bare `f80` works here |
| `dev b64 …` (`base64`) | encode and decode |
| `dev url …` | encode and decode |
| `dev hash …` | all four hashes |
| `dev sha256 …` (`sha1`, `md5`, `sha512`) | just that hash |

So `dev sha256 1739000000` hashes the number instead of reading it as a date.
Without the space, `dev url` is just the text "url".

## Privacy

Nothing leaves the machine. The plugin keeps nothing either: every row has
a fixed id (`hash:sha256`, `jwt`), so what Parsec remembers to rank your
favourite tools first never includes a token, a hash or the text you typed.
JWTs are decoded in memory and the token is not sent back to Parsec for
the claims list.

Colour swatches are small SVG files in `~/.cache/parsec-devtools`, at most
256 of them.

## Development

```sh
python3 -m unittest          # offline tests
parsec plugin install .      # try it in Parsec
```

## License

MIT
