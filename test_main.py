"""Offline tests. Run with `python3 -m unittest`."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

import main

NOW = 1760356800  # 2025-10-13T12:00:00Z
HERE = os.path.dirname(os.path.abspath(__file__))


def setUpModule():
    global _tz
    _tz = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()


def tearDownModule():
    if _tz is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = _tz
    time.tzset()


def jwt(header, payload, signature="c2ln"):
    part = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{part(header)}.{part(payload)}.{signature}"


class Base(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.TemporaryDirectory()
        patcher = mock.patch.object(main, "CACHE_DIR", self.cache.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.cache.cleanup)

    def query(self, text):
        return main.DevTools().query(text, NOW)

    def ids(self, text):
        return [i["id"] for i in self.query(text)]

    def item(self, text, key):
        return next(i for i in self.query(text) if i["id"] == key)


class Uuids(Base):
    def test_empty_query_offers_uuids_and_now(self):
        self.assertEqual(self.ids("")[:3], ["uuid:v4", "uuid:v7", "now:seconds"])

    def test_v7_layout(self):
        u = main.uuid7(1739000000123)
        self.assertEqual((u.version, u.variant), (7, uuid.RFC_4122))
        self.assertEqual(u.int >> 80, 1739000000123)

    def test_v7_sorts_by_time(self):
        self.assertLess(str(main.uuid7(1000)), str(main.uuid7(2000)))

    def test_enter_pastes_tab_copies(self):
        actions = self.item("", "uuid:v4")["actions"]
        self.assertEqual([a["label"] for a in actions[:2]], ["Paste", "Copy"])


class Time(Base):
    def test_seconds(self):
        self.assertEqual(self.item("1739000000", "time:utc")["title"], "2025-02-08T07:33:20Z")

    def test_milliseconds_by_length(self):
        item = self.item("1739000000123", "time:utc")
        self.assertEqual(item["title"], "2025-02-08T07:33:20.123Z")
        self.assertIn("milliseconds", item["subtitle"])

    def test_nanoseconds_by_length(self):
        self.assertIn("nanoseconds", self.item("1739000000123456789", "time:local")["subtitle"])

    def test_local_time_and_relative(self):
        item = self.item("1739000000", "time:local")
        self.assertEqual(item["title"], "2025-02-08 07:33:20 UTC")
        self.assertIn("8 months ago", item["subtitle"])

    def test_short_numbers_are_not_times_unless_asked(self):
        self.assertNotIn("time:local", self.ids("12345"))
        self.assertIn("time:local", self.ids("time 12345"))

    def test_date_to_epoch(self):
        self.assertEqual(self.item("2025-02-08 07:33:20", "date:seconds")["title"], "1739000000")
        self.assertEqual(self.item("2025-02-08T07:33:20.5Z", "date:millis")["title"], "1739000000500")

    def test_zones(self):
        self.assertEqual(main.unix(main.parse_date("2025-02-08T09:33:20+02:00"))[0], 1739000000)
        self.assertEqual(main.unix(main.parse_date("2025-02-08 02:03:20 -0530"))[0], 1739000000)

    def test_invalid_dates(self):
        for text in ("2025-02-30", "2025-13-01", "2025-02-08 25:00"):
            self.assertIsNone(main.parse_date(text), text)

    def test_now(self):
        self.assertEqual(self.item("now", "now:seconds")["title"], str(NOW))
        self.assertEqual(self.item("time ", "now:utc")["title"], "2025-10-13T12:00:00Z")

    def test_relative(self):
        self.assertEqual(main.relative(7200), "in 2 hours")
        self.assertEqual(main.relative(-86400 * 3), "3 days ago")
        self.assertEqual(main.relative(10), "just now")


class Jwt(Base):
    token = jwt({"alg": "HS256", "typ": "JWT"},
                {"sub": "alice", "exp": NOW + 7200, "iat": NOW - 60, "roles": ["a", "b"]})

    def test_detected(self):
        item = self.item(self.token, "jwt")
        self.assertEqual(item["title"], "JWT · HS256 · sub alice")
        self.assertEqual(item["subtitle"], "expires in 2 hours · signature not verified")
        self.assertEqual(item["actions"][0]["label"], "Claims")

    def test_bearer_prefix_and_expired(self):
        old = jwt({"alg": "RS256"}, {"exp": NOW - 3600})
        self.assertTrue(self.item("Bearer " + old, "jwt")["subtitle"].startswith("expired 1 hour ago"))

    def test_claims_list(self):
        data = self.item(self.token, "jwt")["actions"][0]["browse"]
        claims = {i["id"]: i for i in main.DevTools().browse(data, NOW)}
        self.assertEqual(claims["jwt:payload:sub"]["title"], "alice")
        self.assertEqual(claims["jwt:payload:roles"]["title"], '["a","b"]')
        exp = claims["jwt:payload:exp"]
        self.assertEqual(exp["title"], "2025-10-13 14:00:00 UTC")
        self.assertIn("in 2 hours", exp["subtitle"])
        self.assertEqual(claims["jwt:header:alg"]["title"], "HS256")

    def test_token_is_not_sent_back(self):
        data = self.item(self.token, "jwt")["actions"][0]["browse"]
        self.assertNotIn(self.token, json.dumps(data))

    def test_not_a_jwt(self):
        self.assertIsNone(main.parse_jwt("a.b.c"))
        self.assertEqual(self.ids("jwt a.b.c"), ["jwt:error"])


class Colours(Base):
    def titles(self, text):
        return {i["id"]: i["title"] for i in self.query(text) if i["id"].startswith("colour:")}

    def test_hex(self):
        self.assertEqual(self.titles("#ff8800"), {
            "colour:hex": "#ff8800", "colour:rgb": "rgb(255, 136, 0)", "colour:hsl": "hsl(32, 100%, 50%)"})

    def test_short_hex_and_alpha(self):
        self.assertEqual(self.titles("#f808")["colour:rgb"], "rgba(255, 136, 0, 0.533)")

    def test_rgb_and_hsl_syntaxes(self):
        for text in ("rgb(255, 136, 0)", "rgb(255 136 0)", "RGB(100%, 53.3%, 0%)",
                     "hsl(32, 100%, 50%)", "hsl(32deg 100% 50%)"):
            self.assertEqual(self.titles(text)["colour:hex"], "#ff8800", text)

    def test_css4_alpha(self):
        self.assertEqual(self.titles("rgb(255 136 0 / 50%)")["colour:hex"], "#ff880080")

    def test_typed_format_sinks(self):
        items = sorted(self.query("rgb(255, 136, 0)"), key=lambda i: -i["score"])
        ids = [i["id"] for i in items if i["id"].startswith("colour:")]
        self.assertEqual(ids, ["colour:hex", "colour:hsl", "colour:rgb"])

    def test_bare_hex(self):
        self.assertIn("colour:hex", self.ids("ff8800"))
        self.assertNotIn("colour:hex", self.ids("bad"))
        self.assertIn("colour:hex", self.ids("color bad"))

    def test_out_of_range(self):
        for text in ("rgb(300, 0, 0)", "hsl(0, 150%, 50%)", "rgb(1, 2)"):
            self.assertIsNone(main.parse_colour(text), text)

    def test_swatch_icon(self):
        icon = self.item("#ff8800", "colour:rgb")["icon"]
        self.assertTrue(os.path.isabs(icon) and os.path.isfile(icon))
        with open(icon) as f:
            self.assertIn('fill="#ff8800"', f.read())

    def test_swatch_cache_is_pruned(self):
        with mock.patch.object(main, "MAX_SWATCHES", 5):
            for i in range(12):
                main.swatch(i, 0, 0, 1)
            self.assertLessEqual(len(os.listdir(self.cache.name)), 5)

    def test_unwritable_cache_drops_the_icon(self):
        with mock.patch.object(main, "CACHE_DIR", "/proc/nope"), mock.patch("sys.stderr"):
            self.assertNotIn("icon", self.item("#123456", "colour:hex"))


class Encodings(Base):
    def test_hashes(self):
        titles = {i["id"]: i["title"] for i in self.query("hello")}
        self.assertEqual(titles["hash:md5"], "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(titles["hash:sha1"], "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        self.assertEqual(titles["hash:sha256"],
                         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

    def test_one_hash(self):
        self.assertEqual(self.ids("sha1 hello"), ["hash:sha1"])

    def test_trailing_space_is_hashed_and_flagged(self):
        item = self.item("hello ", "hash:md5")
        self.assertNotEqual(item["title"], "5d41402abc4b2a76b9719d911017c592")
        self.assertIn("ends with a space", item["subtitle"])

    def test_base64_round_trip(self):
        self.assertEqual(self.item("hello world", "b64:encode")["title"], "aGVsbG8gd29ybGQ=")
        self.assertEqual(self.item("aGVsbG8gd29ybGQ=", "b64:decode")["title"], "hello world")

    def test_base64url(self):
        self.assertEqual(main.b64_decode("Pz8_"), ("???", True))
        paste = self.item("???", "b64:encode")["actions"][2]
        self.assertEqual(paste["paste"], "Pz8_")

    def test_words_are_not_base64(self):
        for text in ("test", "hello", "abcd", "password", "1739000000", "ff8800", "uuid", "now"):
            self.assertIsNone(main.b64_decode(text), text)

    def test_url(self):
        self.assertEqual(self.item("a b&c", "url:encode")["title"], "a%20b%26c")
        self.assertEqual(self.item("caf%C3%A9%20bar", "url:decode")["title"], "café bar")
        self.assertEqual(self.item("q=a+b%21", "url:decode")["title"], "q=a b!")

    def test_nothing_to_url_encode(self):
        self.assertNotIn("url:encode", self.ids("hello"))
        self.assertIn("url:encode", self.ids("url hello"))

    def test_multiline_title_is_one_line(self):
        item = self.item(base64.b64encode(b"a\nb").decode(), "b64:decode")
        self.assertEqual((item["title"], item["actions"][0]["paste"]), ("a ⏎ b", "a\nb"))


class Dispatch(Base):
    def test_tool_word_needs_a_space(self):
        self.assertEqual(self.ids("b64 "), ["b64:prompt"])
        self.assertIn("hash:sha256", self.ids("b64"))

    def test_uuid_word(self):
        self.assertEqual(self.ids("uuid")[:2], ["uuid:v4", "uuid:v7"])

    def test_ids_never_carry_content(self):
        texts = ["", "hello", "1739000000", "#ff8800", Jwt.token, "aGVsbG8=", "a%20b",
                 "2025-02-08", "sha256 x", "jwt nope", "color nope", "time nope"]
        for text in texts:
            for item in self.query(text):
                self.assertNotEqual(item["id"], item["title"], text)
                self.assertRegex(item["id"], r"^[a-z0-9]+:[a-z0-9:]+$|^jwt$|^help$", text)

    def test_best_guess_first(self):
        for text, first in (("1739000000", "time:local"), ("#ff8800", "colour:rgb"),
                            (Jwt.token, "jwt"), ("aGVsbG8gd29ybGQ=", "b64:decode")):
            items = sorted(self.query(text), key=lambda i: -i["score"])
            self.assertEqual(items[0]["id"], first, text)


class Protocol(unittest.TestCase):
    def test_one_reply_per_line(self):
        lines = [{"type": "init", "version": "1", "config": {}},
                 {"type": "query", "id": 7, "text": "hello", "keyword": "dev"},
                 "not json",
                 {"type": "browse", "item": "jwt", "data": None, "text": ""},
                 {"type": "activate", "item": "x", "data": None, "text": ""}]
        stdin = "\n".join(l if isinstance(l, str) else json.dumps(l) for l in lines) + "\n"
        out = subprocess.run([sys.executable, os.path.join(HERE, "main.py")], input=stdin,
                             capture_output=True, text=True, timeout=10, check=True).stdout
        replies = [json.loads(l) for l in out.splitlines()]
        self.assertEqual([r["type"] for r in replies], ["ready", "results", "results", "ok"])
        self.assertEqual(replies[1]["id"], 7)
        self.assertTrue(replies[1]["items"])


if __name__ == "__main__":
    unittest.main()
