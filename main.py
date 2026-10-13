#!/usr/bin/env python3
"""Parsec plugin: the small developer jobs you'd otherwise open a website for.

  dev                      fresh UUIDs (v4, v7) and the Unix time now
  dev 1739000000           the date; seconds, ms, µs or ns by length
  dev 2026-10-13 14:00     the Unix time (local unless a zone is given)
  dev eyJhbGciOi…          a decoded JWT; Enter lists its claims
  dev #ff8800              the colour as hex, rgb() and hsl()
  dev any text             base64, URL encoding and hashes of the text

The input is recognised and every tool that fits answers with a row, best
guess first. A tool word followed by a space forces one tool:
dev b64 …, dev url …, dev hash …, dev sha256 …, dev jwt …, dev time …,
dev color …, dev uuid.

Enter pastes into the window you came from (copies without the Parsec
Shell extension), Tab copies. Nothing leaves the machine.

Every item has a fixed id: Parsec remembers picked ids to rank them, and
an item without one would be remembered by its title, which here is a
decoded token or a hash.
"""
import base64
import colorsys
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import uuid

CACHE_DIR = os.path.join(
    os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "parsec-devtools")
MAX_SWATCHES = 256
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

HELP = "dev 1739000000 · dev 2026-10-13 14:00 · dev #ff8800 · dev eyJ… · dev any text"

# Digits in a Unix time → its unit. Ten digits is seconds until 2286.
UNITS = [(11, "seconds", 1), (14, "milliseconds", 10 ** 3),
         (17, "microseconds", 10 ** 6), (20, "nanoseconds", 10 ** 9)]
TIME_CLAIMS = ("exp", "iat", "nbf", "auth_time", "updated_at")
HASHES = [("sha256", "SHA-256"), ("sha1", "SHA-1"), ("md5", "MD5"), ("sha512", "SHA-512")]

DATE = re.compile(
    r"^(\d{4})-(\d{1,2})-(\d{1,2})"
    r"(?:[T ]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?)?"
    r"\s*(Z|UTC|[+-]\d{2}(?::?\d{2})?)?$", re.I)
JWT = re.compile(r"^(?:Bearer\s+)?([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$", re.I)
B64 = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
PCT = re.compile(r"%[0-9A-Fa-f]{2}")
HEX = re.compile(r"^(#?)([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$", re.I)
FUNC = re.compile(r"^(rgba?|hsla?)\(\s*(.*?)\s*\)$", re.I)


# --- items -------------------------------------------------------------------

def one_line(text, limit=120):
    """Text fit for a title. The actions keep the original."""
    flat = text.replace("\r\n", "\n").replace("\n", " ⏎ ").replace("\t", " ")
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def quoted(text, limit=40):
    return f"“{one_line(text, limit)}”"


def row(key, title, subtitle, value, score, extra=()):
    """A result whose Enter pastes `value` and Tab copies it."""
    actions = [{"label": "Paste", "paste": value}, {"label": "Copy", "copy": value}]
    actions.extend(extra)
    return {"id": key, "title": one_line(title), "subtitle": subtitle,
            "score": score, "actions": actions}


def note(key, title, subtitle="", score=100):
    """An informational row: Enter just closes."""
    return {"id": key, "title": title, "subtitle": subtitle, "score": score,
            "icon": "dialog-information-symbolic", "actions": []}


# --- UUIDs -------------------------------------------------------------------

def uuid7(ms=None):
    """RFC 9562 version 7: 48 bits of Unix milliseconds, then random bits."""
    ms = int(time.time() * 1000) if ms is None else ms
    rand = int.from_bytes(os.urandom(10), "big")
    value = ((ms & ((1 << 48) - 1)) << 80) | (0x7 << 76) | ((rand >> 68) << 64) \
        | (0b10 << 62) | (rand & ((1 << 62) - 1))
    return uuid.UUID(int=value)


def uuid_items():
    v4, v7 = str(uuid.uuid4()), str(uuid7())
    return [
        row("uuid:v4", v4, "UUID v4 · random", v4, 900,
            [{"label": "Paste uppercase", "paste": v4.upper()}]),
        row("uuid:v7", v7, "UUID v7 · time-ordered, sorts by creation", v7, 890,
            [{"label": "Paste uppercase", "paste": v7.upper()}]),
    ]


# --- time --------------------------------------------------------------------

def relative(seconds):
    """'in 2 hours' or '3 days ago' for a difference from now."""
    span = abs(seconds)
    if span < 45:
        return "just now"
    for size, unit in ((31557600, "year"), (2629800, "month"), (86400, "day"),
                       (3600, "hour"), (60, "minute"), (1, "second")):
        if span >= size:
            n = int(span // size)
            break
    text = f"{n} {unit}{'' if n == 1 else 's'}"
    return f"in {text}" if seconds > 0 else f"{text} ago"


def human(moment):
    return moment.strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def iso(moment):
    spec = "seconds" if moment.microsecond == 0 else \
        "milliseconds" if moment.microsecond % 1000 == 0 else "microseconds"
    return moment.isoformat(timespec=spec).replace("+00:00", "Z")


def unix(moment):
    """Exact (seconds, milliseconds) since the epoch, without float rounding."""
    delta = moment - EPOCH
    seconds = delta.days * 86400 + delta.seconds
    return seconds, seconds * 1000 + delta.microseconds // 1000


def from_epoch(text):
    """An integer Unix time as (local datetime, unit name), or None."""
    if not text.isdigit() or len(text) > 20:
        return None
    for limit, unit, per_second in UNITS:
        if len(text) <= limit:
            break
    seconds, rest = divmod(int(text), per_second)
    try:
        moment = EPOCH + dt.timedelta(seconds=seconds, microseconds=rest * 10 ** 6 // per_second)
        return moment.astimezone(), unit
    except (OverflowError, OSError, ValueError):
        return None


def parse_date(text):
    """YYYY-MM-DD[ HH:MM[:SS[.frac]]][ Z|UTC|±HH[:MM]] as an aware datetime.
    Without a zone it is local time."""
    m = DATE.match(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, zone = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    try:
        moment = dt.datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(s or 0), micro)
        if zone is None:
            return moment.astimezone()
        if zone.upper() in ("Z", "UTC"):
            return moment.replace(tzinfo=dt.timezone.utc)
        sign = 1 if zone[0] == "+" else -1
        minutes = int(zone[-2:]) if len(zone) > 3 else 0
        offset = dt.timedelta(hours=int(zone[1:3]), minutes=minutes)
        return moment.replace(tzinfo=dt.timezone(sign * offset))
    except (OverflowError, OSError, ValueError):
        return None


def epoch_items(moment, unit, now):
    label = f"Unix {unit}"
    when = relative(moment.timestamp() - now)
    utc = iso(moment.astimezone(dt.timezone.utc))
    return [
        row("time:local", human(moment), f"{label} → local time · {when}", human(moment), 900,
            [{"label": "Copy ISO 8601", "copy": iso(moment)}]),
        row("time:utc", utc, f"{label} → ISO 8601, UTC", utc, 890),
    ]


def date_items(moment, now):
    seconds, millis = unix(moment)
    about = f"{human(moment)} · {relative(moment.timestamp() - now)}"
    return [
        row("date:seconds", str(seconds), f"Unix seconds for {about}", str(seconds), 900),
        row("date:millis", str(millis), "Unix milliseconds", str(millis), 890),
    ]


def now_items(now):
    moment = (EPOCH + dt.timedelta(seconds=now)).astimezone()
    seconds, millis = unix(moment)
    utc = iso(moment.astimezone(dt.timezone.utc).replace(microsecond=0))
    return [
        row("now:seconds", str(seconds), "Unix time now, in seconds", str(seconds), 880),
        row("now:millis", str(millis), "Unix time now, in milliseconds", str(millis), 870),
        row("now:local", human(moment), "Now, local time", human(moment), 860),
        row("now:utc", utc, "Now, ISO 8601, UTC", utc, 850),
    ]


# --- JWT ---------------------------------------------------------------------

def b64url_json(part):
    raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    return json.loads(raw.decode("utf-8"))


def parse_jwt(text):
    """(header, payload) of a JWT, or None. The signature is not checked."""
    m = JWT.match(text.strip())
    if not m:
        return None
    try:
        header, payload = b64url_json(m.group(1)), b64url_json(m.group(2))
    except ValueError:
        return None
    if not isinstance(header, dict) or "alg" not in header or not isinstance(payload, dict):
        return None
    return header, payload


def pretty(value):
    return json.dumps(value, indent=2, ensure_ascii=False)


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def is_time(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def jwt_items(header, payload, now):
    title = f"JWT · {header.get('alg')}"
    if "sub" in payload:
        title += f" · sub {payload['sub']}"
    exp = payload.get("exp")
    if is_time(exp):
        state = ("expires " if exp > now else "expired ") + relative(exp - now)
    else:
        state = "no expiry"
    return [{
        "id": "jwt",
        "title": one_line(title),
        "subtitle": f"{state} · signature not verified",
        "score": 950,
        "actions": [
            {"label": "Claims", "browse": {"header": header, "payload": payload}},
            {"label": "Copy payload", "copy": pretty(payload)},
            {"label": "Copy header", "copy": pretty(header)},
        ],
    }]


def claim_items(header, payload, now):
    """The browse list of a JWT: both parts as JSON, then field by field."""
    items = [
        row("jwt:payload", compact(payload), "payload as JSON", pretty(payload), 1000),
        row("jwt:header", compact(header), "header as JSON", pretty(header), 999),
    ]
    score = 990
    for part, fields in (("payload", payload), ("header", header)):
        for name, value in fields.items():
            key = f"jwt:{part}:{name}"
            text = value if isinstance(value, str) else compact(value)
            where = name if part == "payload" else f"header · {name}"
            if name in TIME_CLAIMS and is_time(value):
                found = from_epoch(str(int(value)))
                if found:
                    shown = human(found[0])
                    items.append(row(key, shown, f"{where} · {text} · {relative(value - now)}",
                                     shown, score, [{"label": f"Copy {text}", "copy": text}]))
                    score -= 1
                    continue
            items.append(row(key, text, where, text, score))
            score -= 1
    return items


# --- colours -----------------------------------------------------------------

def channel(word, top):
    """A number or a percentage of `top`."""
    if word.endswith("%"):
        return float(word[:-1]) * top / 100
    return float(word)


def parse_colour(text, forced=False):
    """(r, g, b, alpha, format) with 0-255 ints and alpha 0-1, or None.
    Bare hex needs 6 or 8 digits unless the colour tool was asked for."""
    text = text.strip()
    m = HEX.match(text)
    if m:
        hashed, digits = m.groups()
        if not hashed and not forced and len(digits) not in (6, 8):
            return None
        if len(digits) <= 4:
            digits = "".join(c * 2 for c in digits)
        r, g, b = (int(digits[i:i + 2], 16) for i in (0, 2, 4))
        alpha = int(digits[6:8], 16) / 255 if len(digits) == 8 else 1.0
        return r, g, b, alpha, "hex"
    m = FUNC.match(text)
    if not m:
        return None
    kind = m.group(1).lower()[:3]
    words = [w for w in re.split(r"[\s,/]+", m.group(2)) if w]
    if len(words) not in (3, 4):
        return None
    try:
        alpha = channel(words[3], 1) if len(words) == 4 else 1.0
        if kind == "rgb":
            r, g, b = (round(channel(w, 255)) for w in words[:3])
        else:
            h = float(words[0].lower().replace("deg", "")) % 360 / 360
            s, l = (float(w.rstrip("%")) / 100 for w in words[1:3])
            if not (0 <= s <= 1 and 0 <= l <= 1):
                return None
            r, g, b = (round(c * 255) for c in colorsys.hls_to_rgb(h, l, s))
    except ValueError:
        return None
    if not all(0 <= c <= 255 for c in (r, g, b)) or not 0 <= alpha <= 1:
        return None
    return r, g, b, alpha, kind


def number(value):
    return f"{value:.3f}".rstrip("0").rstrip(".")


def as_hex(r, g, b, a):
    return f"#{r:02x}{g:02x}{b:02x}" + ("" if a >= 1 else f"{round(a * 255):02x}")


def as_rgb(r, g, b, a):
    return f"rgb({r}, {g}, {b})" if a >= 1 else f"rgba({r}, {g}, {b}, {number(a)})"


def as_hsl(r, g, b, a):
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    parts = f"{round(h * 360) % 360}, {round(s * 100)}%, {round(l * 100)}%"
    return f"hsl({parts})" if a >= 1 else f"hsla({parts}, {number(a)})"


SWATCH = """<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">
<defs><pattern id="c" width="8" height="8" patternUnits="userSpaceOnUse">
<rect width="8" height="8" fill="#fff"/><rect width="4" height="4" fill="#bbb"/>
<rect x="4" y="4" width="4" height="4" fill="#bbb"/></pattern></defs>
{under}<rect x="2" y="2" width="28" height="28" rx="7" fill="{fill}" fill-opacity="{alpha}"
 stroke="#808080" stroke-opacity="0.5"/>
</svg>
"""


def swatch(r, g, b, a):
    """Path to an SVG square of the colour, written once to the cache, or
    None when the cache can't be written."""
    path = os.path.join(CACHE_DIR, f"swatch-{r:02x}{g:02x}{b:02x}{round(a * 255):02x}.svg")
    if os.path.isfile(path):
        return path
    under = "" if a >= 1 else '<rect x="2" y="2" width="28" height="28" rx="7" fill="url(#c)"/>\n'
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        prune()
        with open(path + ".tmp", "w") as f:
            f.write(SWATCH.format(under=under, fill=f"#{r:02x}{g:02x}{b:02x}", alpha=number(a)))
        os.replace(path + ".tmp", path)
    except OSError as e:
        print(f"devtools: cannot write a swatch: {e}", file=sys.stderr)
        return None
    return path


def prune():
    """Keep the swatch cache small: drop the oldest beyond the limit."""
    names = [n for n in os.listdir(CACHE_DIR) if n.startswith("swatch-")]
    if len(names) < MAX_SWATCHES:
        return
    paths = sorted((os.path.join(CACHE_DIR, n) for n in names), key=os.path.getmtime)
    for p in paths[: len(paths) - MAX_SWATCHES + 1]:
        try:
            os.remove(p)
        except OSError:
            pass


def colour_items(colour, score=900):
    r, g, b, a, source = colour
    icon = swatch(r, g, b, a)
    items = []
    for i, (kind, label, show) in enumerate((("hex", "Hex", as_hex), ("rgb", "RGB", as_rgb),
                                             ("hsl", "HSL", as_hsl))):
        value = show(r, g, b, a)
        # The format typed in sinks below the conversions.
        item = row(f"colour:{kind}", value, label, value, score - (40 if kind == source else i))
        if icon:
            item["icon"] = icon
        items.append(item)
    return items


# --- base64, URL encoding, hashes ---------------------------------------------

def b64_decode(text):
    """(decoded text, url-safe?) when `text` is base64 of printable UTF-8."""
    core = text.strip().rstrip("=")
    if len(core) < 4 or not B64.match(text.strip()) or len(core) % 4 == 1:
        return None
    urlsafe = "-" in core or "_" in core
    if urlsafe and ("+" in core or "/" in core):
        return None
    std = core.replace("-", "+").replace("_", "/")
    try:
        out = base64.b64decode(std + "=" * (-len(std) % 4), validate=True).decode("utf-8")
    except ValueError:
        return None
    if not out.strip() or not all(c.isprintable() or c in "\n\r\t" for c in out):
        return None
    return out, urlsafe


def url_decode(text):
    if not PCT.search(text):
        return None
    form = "+" in text and "=" in text and " " not in text.strip()
    out = urllib.parse.unquote_plus(text) if form else urllib.parse.unquote(text)
    return out if out != text else None


def of(text):
    """'of “text”', warning about trailing spaces: Parsec trims only the start."""
    tail = " · ends with a space" if text != text.rstrip() else ""
    return f"of {quoted(text)}{tail}"


def b64_items(text, score=400):
    std = base64.b64encode(text.encode("utf-8")).decode("ascii")
    url = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
    extra = [{"label": "Paste base64url", "paste": url}] if url != std else []
    return [row("b64:encode", std, f"Base64 {of(text)}", std, score, extra)]


def b64_decoded_items(decoded, score=880):
    out, urlsafe = decoded
    return [row("b64:decode", out, f"Decoded {'base64url' if urlsafe else 'base64'}", out, score)]


def url_items(text, score=390, always=False):
    out = urllib.parse.quote(text, safe="")
    if out == text and not always:
        return []
    return [row("url:encode", out, f"URL encoding {of(text)}", out, score,
                [{"label": "Paste with + for spaces", "paste": urllib.parse.quote_plus(text, safe="")}])]


def url_decoded_items(out, score=870):
    return [row("url:decode", out, "URL-decoded", out, score)]


def hash_items(text, only=None, score=360):
    items = []
    for i, (algo, label) in enumerate(HASHES):
        if only and algo != only:
            continue
        digest = hashlib.new(algo, text.encode("utf-8")).hexdigest()
        items.append(row(f"hash:{algo}", digest, f"{label} {of(text)}", digest, score - i * 10))
    return items


# --- dispatch ----------------------------------------------------------------

# A tool word followed by a space forces that tool.
TOOLS = {"uuid": "uuid", "b64": "b64", "base64": "b64", "url": "url", "jwt": "jwt",
         "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash", "sha512": "hash",
         "time": "time", "date": "time", "epoch": "time", "color": "colour", "colour": "colour"}
PROMPTS = {"b64": "text to encode or decode", "url": "text to encode or decode",
           "jwt": "token", "hash": "text to hash", "colour": "colour"}


def split_tool(text):
    """(tool, word, rest) when `text` starts with a tool word and a space."""
    m = re.match(r"^(\S+)\s(.*)$", text, re.S)
    if not m or m.group(1).lower() not in TOOLS:
        return None
    return TOOLS[m.group(1).lower()], m.group(1).lower(), m.group(2).lstrip()


def forced(tool, word, rest, now):
    s = rest.strip()
    if tool == "uuid":
        return uuid_items()
    if tool == "time":
        if not s or s.lower() == "now":
            return now_items(now)
        found = from_epoch(s)
        if found:
            return epoch_items(found[0], found[1], now)
        moment = parse_date(s)
        if moment:
            return date_items(moment, now)
        return [note("time:error", "Not a Unix time or a date",
                     "1739000000 · 2026-10-13 · 2026-10-13 14:00 · 2026-10-13T14:00:00Z")]
    if not rest:
        return [note(f"{tool}:prompt", f"Type the {PROMPTS[tool]} after “{word}”", HELP)]
    if tool == "b64":
        decoded = b64_decode(rest)
        return (b64_decoded_items(decoded) if decoded else []) + b64_items(rest, 870)
    if tool == "url":
        out = url_decode(rest)
        return (url_decoded_items(out) if out else []) + url_items(rest, 860, always=True)
    if tool == "hash":
        return hash_items(rest, None if word == "hash" else word, 900)
    if tool == "jwt":
        parts = parse_jwt(rest)
        if parts:
            return jwt_items(parts[0], parts[1], now)
        return [note("jwt:error", "Not a JWT", "Expected header.payload.signature, base64url-encoded")]
    colour = parse_colour(rest, forced=True)
    if colour:
        return colour_items(colour)
    return [note("colour:error", "Not a colour", "#f80 · #ff8800 · rgb(255 136 0) · hsl(32 100% 50%)")]


def detect(text, now):
    """Every tool that fits, ranked by how sure the guess is, then the
    encodings and hashes that fit anything."""
    s = text.strip()
    if not s:
        return uuid_items() + now_items(now)[:1] + [
            note("help", HELP, "Dates, colours, JWTs, base64, URL encoding and hashes")]
    items = []
    low = s.lower()
    if low == "uuid":
        items += uuid_items()
    if low == "now":
        items += now_items(now)
    parts = parse_jwt(s)
    if parts:
        items += jwt_items(parts[0], parts[1], now)
    if 9 <= len(s) <= 20:
        found = from_epoch(s)
        if found:
            items += epoch_items(found[0], found[1], now)
    moment = parse_date(s)
    if moment:
        items += date_items(moment, now)
    colour = parse_colour(s)
    if colour:
        # Bare hex is a weaker guess than one with a "#".
        items += colour_items(colour, 600 if HEX.match(s) and not s.startswith("#") else 900)
    decoded = None if parts else b64_decode(s)
    if decoded:
        items += b64_decoded_items(decoded)
    out = url_decode(s)
    if out:
        items += url_decoded_items(out)
    return items + b64_items(text) + url_items(text) + hash_items(text)


class DevTools:
    def query(self, text, now=None):
        now = time.time() if now is None else now
        tool = split_tool(text)
        if tool:
            return forced(tool[0], tool[1], tool[2], now)
        return detect(text, now)

    def browse(self, data, now=None):
        now = time.time() if now is None else now
        if not isinstance(data, dict):
            return []
        header, payload = data.get("header"), data.get("payload")
        if isinstance(header, dict) and isinstance(payload, dict):
            return claim_items(header, payload, now)
        return []


def main():
    plugin = DevTools()
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = msg.get("type")
        try:
            if kind == "init":
                reply = {"type": "ready"}
            elif kind == "query":
                reply = {"type": "results", "id": msg.get("id"),
                         "items": plugin.query(msg.get("text", ""))}
            elif kind == "browse":
                reply = {"type": "results", "items": plugin.browse(msg.get("data"))}
            else:
                reply = {"type": "ok"}
        except Exception as e:  # never leave Parsec without its one reply line
            print(f"devtools: {kind} failed: {e!r}", file=sys.stderr)
            if kind == "init":
                reply = {"type": "ready"}
            elif kind == "query":
                reply = {"type": "results", "id": msg.get("id"), "items": []}
            elif kind == "browse":
                reply = {"type": "results", "items": []}
            else:
                reply = {"type": "ok"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
