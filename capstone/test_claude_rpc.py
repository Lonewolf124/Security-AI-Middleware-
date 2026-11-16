"""
Tests for Hide-and-Seek on the claude.ai RPC interface (protobuf bodies).

Run from this directory:

    python -m unittest test_claude_rpc -v

The messages are built to the field layout captured from the live app on
2026-11-15 (see hide_seek/providers/claude_rpc.py). All values are synthetic.
"""

import gzip
import json

from mitmproxy import http
from mitmproxy.test import tflow, tutils

from hide_seek import proto
from hide_seek.hide import Hider
from hide_seek.providers import claude_rpc
from hide_seek.proxy import HideSeekAddon
from test_hide_seek import VaultCase


CONV = "0b6f1f6e-1c2d-4e3f-8a9b-0c1d2e3f4a5b"
MESSAGE = "11111111-2222-4333-8444-555555555555"
PARENT = "66666666-7777-4888-8999-aaaaaaaaaaaa"
BLOCK = b"cblk_01KoqYSUJMnhcydSp5xq64e7"

SERVICE = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/"


def ln(number, payload):

    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    return proto.encode_len(number, payload)


def vi(number, value):
    return proto.encode_varint(number << 3) + proto.encode_varint(value)


def context():
    return ln(1, ln(1, ln(1, "sess_810ba174c0ea8d43") + vi(2, 1)) + ln(2, CONV) + vi(3, 3) + ln(14, "en-US"))


TOOL = (
    "6a7cc3fa-6962-427e-9202-fa7f06a8721c:"
    "fireflies_get_transcript-e57c908e96c8125be9364d953f2c51b4"
)


def send_action(prompt):

    return context() + ln(
        2,
        ln(1, MESSAGE) + ln(2, PARENT) + ln(3, prompt)
        + ln(7, ln(2, "claude-opus-5-5"))
        + ln(8, ln(1, vi(1, 1) + ln(8, ln(1, ln(1, TOOL) + vi(2, 1)))))
        + ln(9, "a note with spaces in it")
        + ln(12, "Asia/Calcutta") + ln(13, "en-GB") + vi(18, 1),
    )


def prompt_of(body):

    action = proto.parse(proto.first(proto.parse(body), 2))

    return proto.first(action, 3).decode("utf-8")


def event(inner, compress=False):

    payload = ln(1, ln(10, ln(1, "cursor-00000001")) + vi(11, 3) + inner)

    if compress:
        return proto.frame(1, gzip.compress(payload))

    return proto.frame(0, payload)


def delta(text):
    return event(ln(2, ln(1, BLOCK) + ln(2, text)))


def snapshot(text, title="Chat title", compress=True):

    return event(
        ln(
            1,
            ln(2, ln(1, CONV) + ln(2, title) + ln(6, ln(2, "claude-opus-5-5")))
            + ln(3, ln(1, MESSAGE) + ln(2, CONV) + vi(3, 2))
            + ln(5, ln(1, BLOCK) + ln(2, "dgrp_01UoVdzN6xz9vSgoJxaSSxn9") + vi(4, 1) + ln(9, text)),
        ),
        compress,
    )


HEARTBEAT = proto.frame(0, ln(1, ln(6, vi(1, 4))))
END = proto.frame(2, json.dumps({"metadata": {}}).encode())


def read_stream(data):
    """Return (delta_text, snapshot_texts, titles) of a response stream."""

    deltas, snapshots, titles = "", [], []

    frames, rest = proto.frames(data)

    assert rest == b""

    for flags, payload, _raw in frames:

        if flags & 2:
            continue

        if flags & 1:
            payload = gzip.decompress(payload)

        for number, _type, value, _r in proto.parse(proto.first(proto.parse(payload), 1)):

            if number == 2:
                deltas += proto.first(proto.parse(value), 2).decode("utf-8")

            if number == 1:

                for n, _t, item, _r2 in proto.parse(value):

                    if n == 5:
                        snapshots.append(proto.first(proto.parse(item), 9).decode("utf-8"))

                    if n == 2:
                        titles.append(proto.first(proto.parse(item), 2).decode("utf-8"))

    return deltas, snapshots, titles


class ProtoTest(VaultCase):

    def test_rewrite_keeps_untouched_messages_identical(self):

        body = send_action("Hello there, how are you?")

        self.assertIs(proto.rewrite(body, lambda path, text: None), body)

    def test_rewrite_replaces_one_value_and_fixes_lengths(self):

        body = send_action("short")
        longer = "a much longer replacement text " * 20

        new = proto.rewrite(
            body,
            lambda path, text: longer if path == (2, 3) else None,
        )

        self.assertEqual(prompt_of(new), longer)
        self.assertEqual(claude_rpc.action_conversation(new), CONV)
        self.assertEqual(
            proto.first(proto.parse(proto.first(proto.parse(new), 2)), 12),
            b"Asia/Calcutta",
        )

    def test_conversation_ids(self):

        self.assertEqual(claude_rpc.action_conversation(send_action("x")), CONV)
        self.assertEqual(
            claude_rpc.timeline_conversation(proto.frame(0, ln(1, CONV) + vi(3, 1))),
            CONV,
        )
        self.assertIsNone(claude_rpc.action_conversation(b"\xff\xff"))


class RpcTest(VaultCase):

    def setUp(self):

        super().setUp()
        self.addon = HideSeekAddon(self.vault, self.hider)

    def session(self, conversation=CONV):
        return super().session(conversation)

    def flow(self, method, body, content_type="application/proto"):

        return tflow.tflow(
            req=tutils.treq(
                host="claude.ai",
                port=443,
                scheme=b"https",
                method=b"POST",
                path=(SERVICE + method).encode(),
                headers=http.Headers(host="claude.ai", content_type=content_type),
                content=body,
            )
        )

    def send(self, prompt):

        flow = self.flow("PerformAction", send_action(prompt))

        self.assertTrue(self.addon.request(flow))

        return flow

    def open_stream(self):

        flow = self.flow(
            "StreamTimeline",
            proto.frame(0, ln(1, CONV) + vi(3, 1)),
            "application/connect+proto",
        )

        self.addon.request(flow)

        flow.response = tutils.tresp(
            headers=http.Headers(
                content_type="application/connect+proto",
                connect_content_encoding="gzip",
            ),
            content=b"",
        )

        self.addon.responseheaders(flow)

        return flow.response.stream

    def test_prompt_is_masked_and_everything_else_is_kept(self):

        flow = self.send("Email Rahul Sharma at rahul@example.com please")

        self.assertIsNone(flow.response)

        sent = flow.request.content

        self.assertEqual(
            prompt_of(sent),
            f"Email {self.fake_of('Rahul Sharma')} at "
            f"{self.fake_of('rahul@example.com')} please",
        )
        self.assertNotIn(b"Rahul", sent)
        self.assertEqual(claude_rpc.action_conversation(sent), CONV)

        action = proto.parse(proto.first(proto.parse(sent), 2))

        self.assertEqual(proto.first(action, 1), MESSAGE.encode())
        self.assertEqual(proto.first(action, 2), PARENT.encode())
        self.assertEqual(proto.first(action, 12), b"Asia/Calcutta")
        self.assertEqual(proto.first(proto.parse(sent), 1), proto.first(proto.parse(send_action("x")), 1))

    def test_settings_in_a_send_action_are_never_changed(self):

        def detect_everything(text):
            return [{"start": 0, "end": len(text), "type": "API_KEY"}]

        self.addon.hider = Hider(detect_everything, None, ())

        original = proto.parse(proto.first(proto.parse(send_action("the prompt")), 2))

        flow = self.send("the prompt")

        sent = proto.parse(proto.first(proto.parse(flow.request.content), 2))

        # Only the prompt and the one other field holding written text.
        self.assertEqual(len(self.session()), 2)

        for before, after in zip(original, sent):

            if before[0] in (3, 9):
                self.assertNotEqual(before[2], after[2])
            else:
                self.assertEqual(before[3], after[3])

    def test_single_word_secret_prompt_is_masked(self):

        flow = self.send("AKIA1234567890ABCDEF")

        self.assertNotEqual(prompt_of(flow.request.content), "AKIA1234567890ABCDEF")

    def test_clean_prompt_is_byte_identical(self):

        body = send_action("Explain TLS termination.")
        flow = self.flow("PerformAction", body)

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.content, body)

    def test_actions_without_text_pass_untouched(self):

        body = context() + ln(27, ln(1, ln(2, "claude-haiku-5-5")))
        flow = self.flow("PerformAction", body)

        self.addon.request(flow)

        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.content, body)

    def test_text_in_an_unknown_action_is_masked(self):

        body = context() + ln(9, ln(1, MESSAGE) + ln(4, "Edit: call Rahul Sharma now"))
        flow = self.flow("PerformAction", body)

        self.addon.request(flow)

        self.assertNotIn(b"Rahul", flow.request.content)

    def test_fails_closed(self):

        garbled = self.flow("PerformAction", b"\xff\xff\xff")
        self.addon.request(garbled)

        self.assertEqual(garbled.response.status_code, 502)

        no_conversation = self.flow("PerformAction", ln(2, ln(3, "Email Rahul Sharma")))
        self.addon.request(no_conversation)

        self.assertEqual(no_conversation.response.status_code, 502)

        truncated_key = self.send("-----BEGIN PRIVATE KEY-----\nMIIabc")

        self.assertEqual(truncated_key.response.status_code, 403)

    def test_reply_stream_is_restored(self):

        # The app opens the stream before the first message is sent.
        stream = self.open_stream()

        self.assertTrue(callable(stream))
        self.assertEqual(stream(HEARTBEAT), HEARTBEAT)

        self.send("Repeat: Rahul Sharma, rahul@example.com")

        name = self.fake_of("Rahul Sharma")
        email = self.fake_of("rahul@example.com")

        reply = f"Sure: {name}, {email}. Bye {name.split()[0]}"
        expected = "Sure: Rahul Sharma, rahul@example.com. Bye Rahul"

        # Force the session cache to refresh, as a second would in real use.
        stream._session_at = 0.0

        for size in (1, 3, 7, len(reply)):

            self.addon._timeline_blocks.clear()

            body = b"".join(
                delta(reply[i:i + size]) for i in range(0, len(reply), size)
            )

            wire = body + HEARTBEAT + snapshot(reply, f"Mail to {name}") + END

            out = b"".join(
                stream(wire[i:i + 11]) for i in range(0, len(wire), 11)
            ) + stream(b"")

            deltas, snapshots, titles = read_stream(out)

            self.assertEqual(snapshots, [expected], f"delta size {size}")
            self.assertEqual(titles, ["Mail to Rahul Sharma"])
            self.assertTrue(expected.startswith(deltas), f"delta size {size}: {deltas!r}")
            self.assertNotIn(name.split()[0], deltas)
            self.assertIn(END, out)

    def test_held_delta_tail_survives_a_reconnect(self):

        self.send("Repeat: Rahul Sharma")

        name = self.fake_of("Rahul Sharma")
        first, last = name.split()

        one = self.open_stream()
        out_one = one(delta(f"Hello {first} ")) + one(END)

        two = self.open_stream()
        out_two = two(delta(f"{last}!")) + two(END)

        self.assertEqual(
            read_stream(out_one)[0] + read_stream(out_two)[0],
            "Hello Rahul Sharma!",
        )

    def test_stream_of_an_unmasked_conversation_is_untouched(self):

        stream = self.open_stream()

        wire = delta("Hello Arjun Nair") + snapshot("Hello Arjun Nair") + END

        self.assertEqual(stream(wire) + stream(b""), wire)

    def test_broken_frames_pass_through(self):

        self.send("Repeat: Rahul Sharma")

        stream = self.open_stream()

        junk = proto.frame(1, b"this is not gzip data at all")
        text = proto.frame(0, b"\xff\xfe not a protobuf message \xff")

        self.assertEqual(stream(junk + text), junk + text)

    def test_conversation_list_titles_are_restored(self):

        self.send("Repeat: Rahul Sharma")

        name = self.fake_of("Rahul Sharma")

        flow = tflow.tflow(
            req=tutils.treq(
                host="claude.ai",
                method=b"GET",
                path=b"/api/organizations/11111111-1111-1111-1111-111111111111/chat_conversations_v2",
                headers=http.Headers(host="claude.ai"),
            )
        )

        self.addon.request(flow)

        flow.response = tutils.tresp(
            headers=http.Headers(content_type="application/json"),
            content=json.dumps({
                "data": [
                    {"uuid": CONV, "name": f"Mail to {name}"},
                    {"uuid": PARENT, "name": f"Other chat about {name}"},
                ],
            }).encode(),
        )

        self.addon.responseheaders(flow)
        self.addon.response(flow)

        self.assertEqual(
            [item["name"] for item in json.loads(flow.response.get_text())["data"]],
            ["Mail to Rahul Sharma", f"Other chat about {name}"],
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
