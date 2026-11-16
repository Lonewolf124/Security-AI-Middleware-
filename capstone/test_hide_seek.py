"""
Tests for the local Hide-and-Seek layer.

Run from this directory:

    python -m unittest test_hide_seek -v

Everything except RealModelTest uses a small regex detector, so those
tests do not load the ONNX model. All values are synthetic.
"""

import json
import os
import re
import shutil
import tempfile
import unittest

from mitmproxy import http
from mitmproxy.test import tflow, tutils

from hide_seek import surrogates
from hide_seek.hide import Hider, luhn_ok, verhoeff_ok
from hide_seek.proxy import HideSeekAddon
from hide_seek.seek import SSERestorer, StreamRestorer, restore
from hide_seek.vault import Vault


ORG = "11111111-1111-1111-1111-111111111111"
CONV_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
CONV_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

FAKE_RULES = [
    ("EMAIL", re.compile(r"[\w.]+@[\w.]+\.\w+")),
    ("PERSON_NAME", re.compile(r"Rahul Sharma|Priya Mehta")),
    ("PASSWORD", re.compile(r"hunter2!X")),
    ("AADHAAR", re.compile(r"\b\d{4} ?\d{4} ?\d{4}\b")),
    ("PHONE", re.compile(r"\+91[ -]?\d{5}[ -]?\d{5}")),
    ("ADDRESS", re.compile(r"12, MG Road, Pune")),
]

SECRET_PATTERNS = [
    ("AWS_TEST_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
]

PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAtestTESTtest0123456789+/abcd\n"
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
    "-----END RSA PRIVATE KEY-----"
)


def fake_detect(text):

    return [
        {"start": m.start(), "end": m.end(), "type": entity_type}
        for entity_type, pattern in FAKE_RULES
        for m in pattern.finditer(text)
    ]


class VaultCase(unittest.TestCase):

    def setUp(self):

        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "vault.sqlite3")
        self.key_path = os.path.join(self.tmp, "vault.key")
        self.vault = self.open_vault()
        self.hider = Hider(fake_detect, None, SECRET_PATTERNS)

    def open_vault(self):
        return Vault(self.db_path, self.key_path)

    def tearDown(self):

        self.vault.close()
        shutil.rmtree(self.tmp)

    def session(self, conversation=CONV_A):
        return self.vault.session("claude.ai", "", conversation)

    def hide(self, text, conversation=CONV_A):
        return self.hider.hide(text, self.session(conversation))[0]

    def seek(self, text, conversation=CONV_A):
        return restore(text, self.session(conversation))[0]

    def fake_of(self, value):
        """The surrogate the session issued for one value."""

        return self.session().lookup(value)


class VaultTest(VaultCase):

    def test_same_value_same_surrogate(self):

        session = self.session()

        self.assertEqual(
            session.assign("PERSON_NAME", "Rahul Sharma", lambda: "Arjun Nair"),
            "Arjun Nair",
        )
        self.assertEqual(
            session.assign("PERSON_NAME", "rahul  SHARMA", lambda: "Other One"),
            "Arjun Nair",
        )

    def test_colliding_surrogates_are_rejected(self):

        session = self.session()

        session.assign("PERSON_NAME", "Rahul Sharma", lambda: "Arjun Nair")

        proposals = iter(
            ["Arjun Nair", "Rahul Sharma", "Priya Mehta", "Neha Rao"]
        )

        self.assertEqual(
            session.assign(
                "PERSON_NAME",
                "Priya Mehta",
                lambda: next(proposals),
            ),
            "Neha Rao",
        )

    def test_no_generator_falls_back_to_placeholder(self):

        session = self.session()

        self.assertEqual(
            session.assign("ADDRESS", "12, MG Road, Pune", lambda: None),
            "[ADDRESS_1]",
        )
        self.assertEqual(
            session.assign("ADDRESS", "4 Park Street", lambda: None),
            "[ADDRESS_2]",
        )

    def test_mapping_survives_restart(self):

        masked = self.hide("Call Rahul Sharma.")

        self.vault.close()
        self.vault = self.open_vault()

        self.assertEqual(self.hide("Call Rahul Sharma."), masked)
        self.assertEqual(self.seek(masked), "Call Rahul Sharma.")

    def test_sessions_are_isolated(self):

        masked = self.hide("Call Rahul Sharma.", CONV_A)

        self.assertEqual(self.seek(masked, CONV_B), masked)
        self.assertEqual(len(self.session(CONV_B)), 0)

    def test_nothing_stored_in_plaintext(self):

        self.hide("Rahul Sharma, rahul@corp.example.in")

        fake_name = self.fake_of("Rahul Sharma")

        self.vault.close()

        with open(self.db_path, "rb") as handle:
            raw = handle.read()

        self.vault = self.open_vault()

        for value in (b"Rahul", b"rahul", b"corp.example", fake_name.encode()):
            self.assertNotIn(value, raw)

    def test_purge_removes_idle_sessions_and_their_mappings(self):

        self.hide("Call Rahul Sharma.")

        self.assertEqual(self.vault.purge_expired(ttl_days=1), 0)
        self.assertEqual(self.vault.purge_expired(ttl_days=-1), 1)
        self.assertEqual(
            self.vault.stats(),
            {"sessions": 0, "mappings": 0},
        )


class AuditTest(VaultCase):

    def test_report_hides_values_unless_asked(self):

        from hide_seek.audit import report

        self.hide("Rahul Sharma, rahul@example.com")

        summary = report(self.vault)
        detail = report(self.vault, CONV_A[:8])
        revealed = report(self.vault, CONV_A[:8], reveal=True)

        self.assertIn("2 values masked", summary[1])
        self.assertTrue(any("PERSON_NAME" in line for line in detail))
        self.assertFalse(any("Rahul" in line for line in summary + detail))
        self.assertTrue(any("'Rahul Sharma' ->" in line for line in revealed))


class SurrogateTest(VaultCase):

    def check_shape(self, original, fake):

        self.assertNotEqual(original, fake)
        self.assertEqual(len(original), len(fake))

        for a, b in zip(original, fake):

            self.assertEqual(
                (a.isdigit(), a.isupper(), a.islower()),
                (b.isdigit(), b.isupper(), b.islower()),
            )

            if not a.isalnum():
                self.assertEqual(a, b)

    def test_id_like_values_keep_their_shape(self):

        session = self.session()

        for entity_type, value in [
            ("AADHAAR", "2234 5678 9101"),
            ("PAN_CARD", "ABCDE1234F"),
            ("PASSPORT", "K1234567"),
            ("SSN", "123-45-6789"),
            ("PASSWORD", "hunter2!X"),
            ("CREDIT_CARD", "4111-1111-1111-1111"),
            ("VEHICLE_REG", "MH 12 AB 1234"),
        ]:

            fake = session.assign(
                entity_type,
                value,
                lambda: surrogates.generate(entity_type, value, session),
            )

            self.check_shape(value, fake)

    def test_keys_keep_their_prefix(self):

        session = self.session()

        for value, prefix in [
            ("AKIA1234567890ABCDEF", "AKIA"),
            ("ghp_" + "a1B2" * 9, "ghp_"),
            ("sk-ant-abc123XYZ", "sk-ant-"),
        ]:

            fake = session.assign(
                "API_KEY",
                value,
                lambda: surrogates.generate("API_KEY", value, session),
            )

            self.check_shape(value, fake)
            self.assertTrue(fake.startswith(prefix))

    def test_phone_keeps_country_code_and_grouping(self):

        fake = surrogates.generate("PHONE", "+91 98765 43210", self.session())

        self.assertRegex(fake, r"^\+91 [6-9]\d{4} \d{5}$")

    def test_ip_stays_in_its_private_range(self):

        session = self.session()

        self.assertRegex(
            surrogates.generate("IP_ADDRESS", "192.168.1.50", session),
            r"^192\.168\.\d+\.\d+$",
        )
        self.assertRegex(
            surrogates.generate("IP_ADDRESS", "10.0.0.5", session),
            r"^10\.\d+\.\d+\.\d+$",
        )

    def test_date_is_shifted_and_keeps_its_format(self):

        session = self.session()

        fake = surrogates.generate("DATE_OF_BIRTH", "15/08/1990", session)

        self.assertRegex(fake, r"^\d{2}/\d{2}/(1989|1990|1991)$")
        self.assertNotEqual(fake, "15/08/1990")
        self.assertEqual(
            surrogates.generate("DATE_OF_BIRTH", "15/08/1990", session),
            fake,
        )
        self.assertIsNone(
            surrogates.generate("DATE_OF_BIRTH", "sometime in 1990", session)
        )

    def test_name_keeps_structure(self):

        fake = surrogates.generate(
            "PERSON_NAME",
            "Dr. RAHUL K. Sharma",
            self.session(),
        )

        parts = fake.split()

        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "Dr.")
        self.assertTrue(parts[1].isupper())
        self.assertRegex(parts[2], r"^[A-Z]\.$")

    def test_email_follows_the_fake_name(self):

        self.hide("Rahul Sharma <rahul.sharma42@gmail.com>")

        first, last = self.fake_of("Rahul Sharma").lower().split()

        self.assertRegex(
            self.fake_of("rahul.sharma42@gmail.com"),
            rf"^{first}\.{last}\d\d@gmail\.com$",
        )

    def test_one_organisation_keeps_one_fake_domain(self):

        masked = self.hide("a.b@corp.example.in and c.d@corp.example.in")

        first, second = re.findall(r"@(\S+)", masked)

        self.assertEqual(first, second)
        self.assertNotIn("corp", first)
        self.assertTrue(first.endswith(".in"))

    def test_checksums(self):

        self.assertTrue(verhoeff_ok("234123412346"))
        self.assertFalse(verhoeff_ok("123456789101"))
        self.assertTrue(luhn_ok("4111111111111111"))
        self.assertFalse(luhn_ok("4111111111111112"))


class HideSeekTest(VaultCase):

    def test_round_trip_every_kind(self):

        original = (
            "Rahul Sharma (rahul@corp.example.in, +91 98765 43210) lives at "
            "12, MG Road, Pune. Aadhaar 1234 5678 9101, password hunter2!X, "
            "key AKIA1234567890ABCDEF. Rahul Sharma asked Priya Mehta."
        )

        masked = self.hide(original)

        for value in (
            "Rahul", "Sharma", "Priya", "Mehta", "corp.example", "98765",
            "MG Road", "1234 5678 9101", "hunter2!X", "AKIA1234567890ABCDEF",
        ):
            self.assertNotIn(value, masked)

        self.assertIn("[ADDRESS_1]", masked)
        self.assertEqual(self.seek(masked), original)

    def test_aadhaar_with_a_failing_checksum_is_still_masked(self):

        self.assertNotIn("123456789101", self.hide("Aadhaar 123456789101"))

    def test_checksum_catches_what_the_detector_misses(self):

        hider = Hider(lambda text: [], None, ())

        masked, findings = hider.hide(
            "ids 2341 2341 2346 and 4111 1111 1111 1111, order 987654321013",
            self.session(),
        )

        self.assertEqual(
            [finding["type"] for finding in findings],
            ["AADHAAR", "CREDIT_CARD"],
        )
        self.assertIn("order 987654321013", masked)
        self.assertNotIn("2341 2341 2346", masked)
        self.assertNotIn("4111 1111 1111 1111", masked)

    def test_later_turns_reuse_surrogates(self):

        self.hide("Priya Mehta wrote to Rahul Sharma.")

        fake = self.fake_of("Rahul Sharma")

        self.assertEqual(
            self.hide("Draft a reply from Rahul Sharma."),
            f"Draft a reply from {fake}.",
        )

    def test_known_value_is_masked_when_the_detector_misses_it(self):

        self.hide("Contact Rahul Sharma.")

        fake = self.fake_of("Rahul Sharma")

        # Lower-cased, then first name only: the fake detector matches neither.
        self.assertEqual(
            self.hide("what did rahul sharma say? ask Rahul again"),
            f"what did {fake} say? ask {fake.split()[0]} again",
        )

    def test_part_of_a_fake_name_is_restored(self):

        self.hide("Contact Rahul Sharma.")

        fake = self.fake_of("Rahul Sharma")
        first, last = fake.split()

        self.assertEqual(
            self.seek(f"Hi {first}, or Mr. {last}? {fake.upper()}!"),
            "Hi Rahul, or Mr. Sharma? Rahul Sharma!",
        )

    def test_reformatted_numbers_are_restored(self):

        self.hide("Aadhaar 1234 5678 9101 phone +91 98765 43210")

        aadhaar = self.fake_of("1234 5678 9101")
        phone = self.fake_of("+91 98765 43210")

        compact = aadhaar.replace(" ", "")
        dashed = aadhaar.replace(" ", "-")

        self.assertEqual(
            self.seek(f"{compact} / {dashed} / {phone.replace(' ', '')}"),
            "1234 5678 9101 / 1234 5678 9101 / +91 98765 43210",
        )

    def test_plural_and_possessive_names(self):

        self.hide("Contact Rahul Sharma.")

        first = self.fake_of("Rahul Sharma").split()[0]

        masked = self.hide("What is Rahuls phone no.? And Rahul's email?")

        self.assertEqual(masked, f"What is {first}s phone no.? And {first}'s email?")
        self.assertEqual(
            self.seek(masked),
            "What is Rahuls phone no.? And Rahul's email?",
        )

    def test_a_real_value_equal_to_a_surrogate_stays_distinct(self):

        self.hide("Contact Rahul Sharma.")

        fake = self.fake_of("Rahul Sharma")
        first = fake.split()[0]

        # The user now mentions a real person who has the fake's name.
        masked = self.hide(f"Who is {first} now? And Rahul?")

        other = self.fake_of(first)

        self.assertNotIn(other, (first, "Rahul"))
        self.assertEqual(masked, f"Who is {other} now? And {first}?")

        # The provider's two people come back as the user's two people.
        self.assertEqual(
            self.seek(f"{other} is new to me; {first} is {fake}."),
            f"{first} is new to me; Rahul is Rahul Sharma.",
        )

        # And it stays stable on later turns.
        self.assertEqual(self.hide(f"Call {first} and Rahul"), f"Call {other} and {first}")

    def test_unrelated_text_is_untouched(self):

        self.hide("Rahul Sharma, 1234 5678 9101")

        text = "Use arr[0], see [ADDRESS_1] and call 555-0100."

        self.assertEqual(self.seek(text), text)

    def test_private_key_block_is_swapped_and_restored(self):

        original = f"Fix this key:\n{PRIVATE_KEY}\nthanks"

        masked, findings = self.hider.hide(original, self.session())

        self.assertEqual(findings, [{"type": "PRIVATE_KEY", "action": "MASK"}])
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", masked)
        self.assertNotIn("MIIEowIBAAKCAQEAtest", masked)
        self.assertNotIn("QUJDREVGR0hJ", masked)
        self.assertEqual(len(masked), len(original))
        self.assertEqual(self.seek(masked), original)

    def test_truncated_private_key_blocks(self):

        _masked, findings = self.hider.hide(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA Rahul Sharma",
            self.session(),
        )

        self.assertEqual(findings, [{"type": "PRIVATE_KEY", "action": "BLOCK"}])

    def test_long_text_is_scanned_past_the_first_window(self):

        class WordTokenizer:

            def __call__(self, text, **_kwargs):
                return {
                    "offset_mapping": [
                        m.span() for m in re.finditer(r"\S+", text)
                    ]
                }

        seen = []

        def detect(text):
            seen.append(len(text.split()))
            return fake_detect(text)

        hider = Hider(detect, WordTokenizer(), ())

        text = "filler " * 2000 + "ask Rahul Sharma " + "filler " * 300

        masked, findings = hider.hide(text, self.session())

        self.assertGreater(len(seen), 1)
        self.assertLessEqual(max(seen), 384)
        self.assertNotIn("Rahul", masked)
        self.assertEqual(len(findings), 1)


class StreamTest(VaultCase):

    def setUp(self):

        super().setUp()

        session = self.session()

        session.assign("PERSON_NAME", "Rahul Sharma", lambda: "Arjun Nair")
        session.assign("AADHAAR", "1234 5678 9101", lambda: "8765 4321 0987")
        session.assign("EMAIL", 'a"b@example.com', lambda: 'k"z@example.com')

    def test_surrogate_split_across_pieces(self):

        text = (
            "Dear Arjun Nair, Arjun and Arjuna met Mr Nair; id 8765-4321-0987 "
            "or 876543210987, not 8765 4321 09876. Bye Arjun"
        )

        expected = (
            "Dear Rahul Sharma, Rahul and Arjuna met Mr Sharma; "
            "id 1234 5678 9101 or 1234 5678 9101, not 8765 4321 09876. "
            "Bye Rahul"
        )

        for size in range(1, len(text) + 1):

            restorer = StreamRestorer(self.session())

            out = "".join(
                restorer.feed(text[i:i + size])
                for i in range(0, len(text), size)
            ) + restorer.flush()

            self.assertEqual(out, expected, f"chunk size {size}")

    def test_stream_is_held_only_while_undecided(self):

        restorer = StreamRestorer(self.session())

        self.assertEqual(restorer.feed("Hello there. Ar"), "Hello there. ")
        self.assertEqual(restorer.feed("e you"), "Are you")
        self.assertEqual(restorer.feed(" Arjun"), " ")
        self.assertEqual(restorer.feed(" went"), "Rahul went")

    @staticmethod
    def sse(pieces, field="text", delta_type="text_delta", newline="\n"):

        events = [
            ("message_start", {"type": "message_start", "message": {}}),
            (
                "content_block_start",
                {"type": "content_block_start", "index": 0},
            ),
        ]

        for piece in pieces:
            events.append((
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": delta_type, field: piece},
                },
            ))

        events.append((
            "content_block_stop",
            {"type": "content_block_stop", "index": 0},
        ))
        events.append(("message_stop", {"type": "message_stop"}))

        return "".join(
            f"event: {name}{newline}data: {json.dumps(data)}{newline * 2}"
            for name, data in events
        ).encode("utf-8")

    @staticmethod
    def collect(stream, field="text"):

        text = ""

        for block in re.split(r"\r?\n\r?\n", stream.decode("utf-8")):

            for line in block.splitlines():

                if line.startswith("data:"):

                    event = json.loads(line[5:])

                    if event.get("type") == "content_block_delta":
                        text += event["delta"][field]

        return text

    def test_sse_stream_any_network_chunking(self):

        stream = self.sse(
            ["Hi Arj", "un N", "air", ", id 8765 43", "21 0987 bye Arjun"]
        )

        for size in (1, 7, 64, len(stream)):

            for newline in ("\n", "\r\n"):

                body = stream.replace(b"\n", newline.encode())
                restorer = SSERestorer(self.session())

                out = b"".join(
                    restorer(body[i:i + size])
                    for i in range(0, len(body), size)
                ) + restorer(b"")

                self.assertEqual(
                    self.collect(out),
                    "Hi Rahul Sharma, id 1234 5678 9101 bye Rahul",
                    f"chunk size {size}",
                )
                self.assertIn(b"message_start", out)
                self.assertTrue(out.rstrip().endswith(b'"message_stop"}'))

    def test_sse_stream_without_surrogates_is_byte_identical(self):

        stream = self.sse(["plain ", "text"])
        restorer = SSERestorer(self.session())

        self.assertEqual(restorer(stream) + restorer(b""), stream)

    def test_tool_json_delta_is_restored_with_json_escaping(self):

        stream = self.sse(
            ['{"to": "k\\"z@exa', 'mple.com"}'],
            field="partial_json",
            delta_type="input_json_delta",
        )

        restorer = SSERestorer(self.session())
        out = restorer(stream) + restorer(b"")

        self.assertEqual(
            json.loads(self.collect(out, "partial_json")),
            {"to": 'a"b@example.com'},
        )


class ProxyTest(VaultCase):

    def setUp(self):

        super().setUp()
        self.addon = HideSeekAddon(self.vault, self.hider)

    def flow(self, action, body=None, method="POST", conversation=CONV_A):

        path = f"/api/organizations/{ORG}/chat_conversations/{conversation}"

        if action:
            path += f"/{action}"

        return tflow.tflow(
            req=tutils.treq(
                host="claude.ai",
                port=443,
                scheme=b"https",
                method=method.encode(),
                path=path.encode(),
                headers=http.Headers(
                    host="claude.ai",
                    content_type="application/json",
                ),
                content=json.dumps(body).encode() if body else b"",
            )
        )

    def test_completion_is_masked_and_stream_is_restored(self):

        flow = self.flow(
            "completion",
            {
                "prompt": "Write to Rahul Sharma at rahul@example.com",
                "attachments": [
                    {"extracted_content": "CV of Priya Mehta"},
                ],
                "timezone": "Asia/Kolkata",
            },
        )

        self.assertTrue(self.addon.request(flow))
        self.assertIsNone(flow.response)

        wire = flow.request.get_text()
        sent = json.loads(wire)

        for value in ("Rahul", "Sharma", "rahul@", "Priya", "Mehta"):
            self.assertNotIn(value, wire)

        fake_name = self.fake_of("Rahul Sharma")
        fake_email = self.fake_of("rahul@example.com")

        self.assertEqual(sent["prompt"], f"Write to {fake_name} at {fake_email}")
        self.assertEqual(sent["timezone"], "Asia/Kolkata")
        self.assertEqual(flow.request.headers["accept-encoding"], "identity")

        flow.response = tutils.tresp(
            headers=http.Headers(content_type="text/event-stream"),
            content=b"",
        )

        self.addon.responseheaders(flow)

        self.assertTrue(callable(flow.response.stream))

        half = len(fake_email) // 2

        stream = StreamTest.sse(
            [f"Dear {fake_name} <{fake_email[:half]}", f"{fake_email[half:]}>"]
        )

        out = flow.response.stream(stream) + flow.response.stream(b"")

        self.assertEqual(
            StreamTest.collect(out),
            "Dear Rahul Sharma <rahul@example.com>",
        )

    def test_title_request_and_history_response(self):

        self.addon.request(
            self.flow("completion", {"prompt": "Email Rahul Sharma"})
        )

        fake = self.fake_of("Rahul Sharma")

        title = self.flow("title", {"message_content": "Email Rahul Sharma"})
        self.addon.request(title)

        self.assertEqual(
            json.loads(title.request.get_text())["message_content"],
            f"Email {fake}",
        )

        history = self.flow(None, method="GET")
        self.addon.request(history)

        history.response = tutils.tresp(
            headers=http.Headers(content_type="application/json"),
            content=json.dumps({
                "name": f"Email to {fake}",
                "chat_messages": [{"text": f"Email {fake}"}],
            }).encode(),
        )

        self.addon.responseheaders(history)
        self.addon.response(history)

        self.assertEqual(
            json.loads(history.response.get_text()),
            {
                "name": "Email to Rahul Sharma",
                "chat_messages": [{"text": "Email Rahul Sharma"}],
            },
        )

    def test_other_conversation_cannot_read_the_mapping(self):

        self.addon.request(
            self.flow("completion", {"prompt": "Email Rahul Sharma"})
        )

        other = self.flow(None, method="GET", conversation=CONV_B)
        self.addon.request(other)

        body = json.dumps({"text": self.fake_of("Rahul Sharma")}).encode()

        other.response = tutils.tresp(
            headers=http.Headers(content_type="application/json"),
            content=body,
        )

        self.addon.response(other)

        self.assertEqual(other.response.content, body)

    def test_truncated_private_key_blocks(self):

        flow = self.flow(
            "completion",
            {"prompt": "-----BEGIN PRIVATE KEY-----\nMIIabc"},
        )

        self.addon.request(flow)

        self.assertEqual(flow.response.status_code, 403)

    def test_whole_private_key_is_forwarded_as_a_fake(self):

        flow = self.flow("completion", {"prompt": PRIVATE_KEY})

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertNotIn("MIIEowIBAAKCAQEAtest", flow.request.get_text())

    def test_fails_closed(self):

        garbled = self.flow("completion")
        garbled.request.content = b"{not json"
        self.addon.request(garbled)

        self.assertEqual(garbled.response.status_code, 400)

        def broken(_text):
            raise RuntimeError("detector crashed")

        self.addon.hider = Hider(broken, None, ())

        crashed = self.flow("completion", {"prompt": "Email Rahul Sharma"})
        self.addon.request(crashed)

        self.assertEqual(crashed.response.status_code, 502)

    def test_clean_prompt_is_untouched(self):

        flow = self.flow("completion", {"prompt": "Explain TLS termination."})
        before = flow.request.content

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.content, before)

    def test_unrelated_hosts_are_ignored(self):

        flow = tflow.tflow(req=tutils.treq(host="example.com"))

        self.assertFalse(self.addon.request(flow))


MODEL_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "onnx_quantized_all17",
    "model_quantized.onnx",
)


@unittest.skipUnless(os.path.exists(MODEL_FILE), "ONNX model not present")
class RealModelTest(VaultCase):

    def setUp(self):

        super().setUp()
        self.hider = Hider.default()

    def test_round_trip_with_the_real_detectors(self):

        original = (
            "My name is Rahul Sharma. My email is rahul@example.com. "
            "My IP is 192.168.1.50. My AWS test key is AKIA1234567890ABCDEF."
        )

        masked, findings = self.hider.hide(original, self.session())

        print("\n[real model] masked :", masked)
        print("[real model] types  :", sorted({f["type"] for f in findings}))

        for value in (
            "Rahul", "rahul@example.com", "192.168.1.50", "AKIA1234567890ABCDEF",
        ):
            self.assertNotIn(value, masked)

        self.assertEqual(self.seek(masked), original)
        self.assertEqual(self.hide(original), masked)

    def test_long_prompt_tail_is_masked(self):

        text = (
            "The quarterly report covers many topics in detail. " * 150
            + "Please send the summary to Priya Mehta at priya@example.com."
        )

        masked = self.hide(text)

        self.assertNotIn("priya@example.com", masked)
        self.assertNotIn("Priya Mehta", masked)
        self.assertEqual(self.seek(masked), text)


if __name__ == "__main__":
    unittest.main()
