"""
The claude.ai web app's RPC interface (Connect protocol, protobuf bodies).

The schema is not published. The field numbers below were read from
captured traffic on 2026-11-15 and will need updating if the app changes.

PerformAction (unary request)
    1      context           1.2  conversation id
    2      send message      2.3  the user's text
    other  further actions (typing state, model change, ...)

StreamTimeline (streamed response), each frame holds one event in field 1
    1.1    state snapshot    1.1.2 conversation, 1.1.3 message,
                             1.1.5 content block: .1 block id, .9 full text
    1.2    text delta        1.2.1 block id, 1.2.2 text to append
    1.6    heartbeat
"""

import re
import time

from .. import proto
from ..seek import StreamRestorer, restore


PROVIDER = "claude.ai"
HOST = "claude.ai"

SERVICE = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/"

UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

CONTEXT = 1
PROMPT_PATH = (2, 3)

EVENT = 1
EVENT_STATE = 1
EVENT_DELTA = 2
STATE_BLOCK = 5

SESSION_REFRESH_SECONDS = 1.0


def method(host, path):
    """Return the RPC method name for a ConversationService call."""

    if host.lower() != HOST:
        return None

    path = path.split("?")[0]

    if not path.startswith(SERVICE):
        return None

    return path[len(SERVICE):]


def _uuid(data):

    if data is None:
        return None

    try:
        text = data.decode("ascii")

    except UnicodeDecodeError:
        return None

    return text.lower() if UUID.fullmatch(text) else None


def action_conversation(body):
    """The conversation id of a PerformAction request body."""

    context = proto.parse(proto.first(proto.parse(body), CONTEXT) or b"")

    return _uuid(proto.first(context, 2))


def timeline_conversation(body):
    """The conversation id of a StreamTimeline request body."""

    frames, _rest = proto.frames(body)

    if not frames:
        return None

    return _uuid(proto.first(proto.parse(frames[0][1]), 1))


def is_free_text(text):
    """
    True for text a person could have written, false for protocol values.

    Protocol values (ids, locales, model and tool names) are single tokens,
    some of them long. Running the detector over them corrupts them, so
    only text containing whitespace is treated as written by a person.
    """

    return any(char.isspace() for char in text.strip())


def hide_action(body, hider, session):
    """
    Mask the user's text in a PerformAction request body.

    Returns (new_body, findings). Raises ValueError if the body cannot be
    read, so the caller can refuse to forward it.
    """

    if proto.parse(body) is None:
        raise ValueError("PerformAction body is not a protobuf message")

    findings = []

    def mask(path, text):

        if path[0] == CONTEXT:
            return None

        # The prompt field is always inspected. Elsewhere, including in
        # actions whose layout is not known, only written text is inspected:
        # settings such as the enabled-tool list must reach the server intact.
        if path != PROMPT_PATH and not is_free_text(text):
            return None

        masked, text_findings = hider.hide(text, session)

        findings.extend(text_findings)

        return masked

    return proto.rewrite(body, mask), findings


class TimelineRestorer:
    """
    Seek over a StreamTimeline response, as a mitmproxy stream callable.

    Text deltas are restored with a per-block StreamRestorer, so a
    surrogate split across deltas is still caught. blocks holds those
    restorers and is shared between the successive streams of one
    conversation, because the app reconnects every few seconds.

    get_session() returns the conversation's session, or None while nothing
    has been masked in it yet.
    """

    def __init__(self, get_session, blocks, encoding=""):

        self._get_session = get_session
        self._blocks = blocks
        self._encoding = encoding
        self._pending = b""

        self._session = None
        self._session_at = 0.0

        self.restored = 0

    def __call__(self, chunk):

        frames, rest = proto.frames(self._pending + chunk)

        self._pending = rest

        out = []

        for flags, payload, raw in frames:

            try:
                out.append(self._frame(flags, payload, raw))

            except Exception:
                # Seek must never break the stream; at worst the user sees
                # a surrogate instead of the restored value.
                out.append(raw)

        if chunk == b"" and self._pending:
            out.append(self._pending)
            self._pending = b""

        return b"".join(out)

    def _current_session(self):

        now = time.monotonic()

        if now - self._session_at >= SESSION_REFRESH_SECONDS:

            self._session = self._get_session()
            self._session_at = now

        return self._session

    def _frame(self, flags, payload, raw):

        # End-of-stream trailers and heartbeats carry no text.
        if flags & 2 or len(payload) < 12:
            return raw

        session = self._current_session()

        if session is None or not len(session):
            return raw

        body = payload

        if flags & 1:

            body = proto.decompress(payload, self._encoding)

            if body is None:
                return raw

        fields = proto.parse(body)

        if fields is None:
            return raw

        out = []
        changed = False

        for number, wire_type, value, field_raw in fields:

            if number == EVENT and wire_type == proto.LEN:

                new = self._event(value, session)

                if new is not value:
                    out.append(proto.encode_len(number, new))
                    changed = True
                    continue

            out.append(field_raw)

        if not changed:
            return raw

        return proto.frame(flags & ~1, b"".join(out))

    def _event(self, event, session):

        fields = proto.parse(event)

        if fields is None:
            return event

        out = []
        changed = False

        for number, wire_type, value, field_raw in fields:

            new = value

            if wire_type == proto.LEN and number == EVENT_DELTA:
                new = self._delta(value, session)

            elif wire_type == proto.LEN:

                if number == EVENT_STATE:
                    self._forget_snapshotted_blocks(value)

                new = proto.rewrite(
                    value,
                    lambda _path, text: self._restore(text, session),
                    path=(number,),
                )

            if new is not value:
                out.append(proto.encode_len(number, new))
                changed = True
            else:
                out.append(field_raw)

        return b"".join(out) if changed else event

    def _restore(self, text, session):

        restored, count = restore(text, session)

        self.restored += count

        return restored

    def _forget_snapshotted_blocks(self, state):
        """A snapshot carries a block's whole text and supersedes deltas."""

        for number, wire_type, value, _raw in proto.parse(state) or ():

            if number == STATE_BLOCK and wire_type == proto.LEN:

                block_id = proto.first(proto.parse(value), 1)

                if block_id is not None:
                    self._blocks.pop(block_id, None)

    def _delta(self, delta, session):

        fields = proto.parse(delta)
        block_id = proto.first(fields, 1)

        if fields is None or block_id is None:
            return delta

        restorer = self._blocks.get(block_id)

        if restorer is None:
            restorer = self._blocks[block_id] = StreamRestorer(session)

        out = []
        changed = False

        for number, wire_type, value, field_raw in fields:

            if number == 2 and wire_type == proto.LEN:

                try:
                    text = value.decode("utf-8")

                except UnicodeDecodeError:
                    out.append(field_raw)
                    continue

                before = restorer.restored
                new_text = restorer.feed(text)

                self.restored += restorer.restored - before

                if new_text != text:
                    out.append(proto.encode_len(number, new_text.encode("utf-8")))
                    changed = True
                    continue

            out.append(field_raw)

        return b"".join(out) if changed else delta
