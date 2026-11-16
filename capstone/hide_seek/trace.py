"""
Structure-only trace of provider traffic, for diagnosing why a request was
or was not handled.

It records addresses, content types, field names or numbers, value types
and lengths. Free text is recorded as its length only. Two kinds of value
are recorded as they are, because they describe the protocol and not the
conversation: integers, and short single-word labels such as "human" or a
model name. Identifiers (UUIDs) are recorded as a short hash, so the same
identifier can be recognised across requests without being stored.
Headers and cookies are never recorded.

Enabled by default; set HAS_TRACE=0 to turn it off.

HAS_TRACE_CONTENT=1 additionally records the start of each text value. It
is for test sessions with synthetic data only and is off by default.
"""

import datetime
import hashlib
import json
import os
import re
import threading

from . import config
from . import proto


ENABLED = os.environ.get("HAS_TRACE", "1") != "0"
CONTENT = os.environ.get("HAS_TRACE_CONTENT", "0") == "1"
CONTENT_CHARS = 300
TRACE_PATH = config.DATA_DIR / "trace.log"

WATCHED = ("claude", "anthropic")

MAX_FIELDS = 60
MAX_DEPTH = 8
MAX_FRAMES = 400

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_.\-/:]{0,47}")

_lock = threading.Lock()


def watched(host):
    return ENABLED and any(word in host.lower() for word in WATCHED)


def _describe(text):

    if UUID.fullmatch(text):
        return "uuid#" + hashlib.sha256(text.lower().encode()).hexdigest()[:6]

    if LABEL.fullmatch(text):
        return "label:" + text

    if CONTENT:
        return f"text[{len(text)}]:" + text[:CONTENT_CHARS]

    return f"text[{len(text)}]"


def _json_shape(value, depth=0):

    if isinstance(value, dict):

        if depth >= MAX_DEPTH:
            return "{...}"

        return {
            key: _json_shape(item, depth + 1)
            for key, item in list(value.items())[:MAX_FIELDS]
        }

    if isinstance(value, list):

        if not value:
            return []

        return [_json_shape(value[0], depth + 1), f"x{len(value)}"]

    if isinstance(value, str):
        return _describe(value)

    if isinstance(value, bool) or value is None:
        return value

    return type(value).__name__


def json_shape(text):

    try:
        return _json_shape(json.loads(text))

    except (TypeError, ValueError):
        return None


def proto_shape(data, depth=0):
    """Field numbers, types and lengths of a protobuf message."""

    kind, value = proto.classify(data)

    if kind == "text":
        return _describe(value)

    if kind == "bytes":
        return f"bytes[{len(data)}]"

    if depth >= MAX_DEPTH:
        return "{...}"

    shape = []

    for number, wire_type, field, _raw in value[:MAX_FIELDS]:

        if wire_type == proto.VARINT:
            shape.append([number, field])

        elif wire_type == proto.LEN:
            shape.append([number, proto_shape(field, depth + 1)])

        else:
            shape.append([number, f"fixed{len(field) * 8}"])

    if len(value) > MAX_FIELDS:
        shape.append(f"+{len(value) - MAX_FIELDS} more")

    return shape


def frame_shape(flags, payload, encoding):

    if flags & 1:

        payload = proto.decompress(payload, encoding)

        if payload is None:
            return f"compressed({encoding})"

    if flags & 2:
        return {"end_stream": json_shape(payload.decode("utf-8", "replace"))}

    return proto_shape(payload)


def body_shape(content, content_type, encoding=""):
    """Shape of a whole request or response body."""

    content = content or b""
    content_type = content_type.lower()

    if "json" in content_type:
        return json_shape(content.decode("utf-8", "replace"))

    if "connect+proto" in content_type:

        frames, rest = proto.frames(content)

        return {
            "frames": [
                [flags, frame_shape(flags, payload, encoding)]
                for flags, payload, _raw in frames[:MAX_FRAMES]
            ],
            "leftover_bytes": len(rest),
        }

    if "proto" in content_type:
        return proto_shape(content)

    return f"{len(content)} bytes"


class StreamTap:
    """
    A pass-through mitmproxy stream callable that traces the frames of a
    Connect streaming response. It never changes the bytes.
    """

    def __init__(self, label, encoding):

        self._label = label
        self._encoding = encoding
        self._pending = b""
        self._count = 0

    def __call__(self, chunk):

        try:
            self._trace(chunk)

        except Exception as error:
            write("stream-error", **self._label, error=repr(error))

        return chunk

    def _trace(self, chunk):

        if self._count >= MAX_FRAMES:
            return

        frames, self._pending = proto.frames(self._pending + chunk)

        for flags, payload, _raw in frames:

            self._count += 1

            write(
                "frame",
                **self._label,
                n=self._count,
                flags=flags,
                size=len(payload),
                shape=frame_shape(flags, payload, self._encoding),
            )

            if self._count >= MAX_FRAMES:
                write("frame-limit", **self._label)
                break


def write(kind, **fields):

    if not ENABLED:
        return

    line = json.dumps(
        {
            "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "kind": kind,
            **fields,
        },
        ensure_ascii=False,
    )

    with _lock:

        TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)

        with open(TRACE_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
