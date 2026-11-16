import json
import re

from . import config
from .matching import surrogates_matcher


def json_escape(value):
    return json.dumps(value, ensure_ascii=False)[1:-1]


def restore(text, session, escape=None):
    """
    The Seek step: replace every surrogate the session issued with its
    original value. Text that matches no surrogate is returned unchanged.

    escape, if given, is applied to both sides, for text that is itself
    inside an encoded string (a JSON fragment).

    Returns (restored_text, restored_count).
    """

    restorer = StreamRestorer(session, escape)

    return restorer.feed(text) + restorer.flush(), restorer.restored


def restore_json(value, session):
    """Restore surrogates in every string of a decoded JSON value."""

    if isinstance(value, dict):
        return {
            key: restore_json(item, session)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [restore_json(item, session) for item in value]

    if isinstance(value, str):
        return restore(value, session)[0]

    return value


class StreamRestorer:
    """
    Seek over text that arrives in pieces.

    A surrogate can be split across two pieces ("Arjun N" + "air"), so any
    tail that is, or could still grow into, a surrogate is held back until
    the next piece settles it.
    """

    def __init__(self, session, escape=None):

        self._matcher = surrogates_matcher(session, escape)
        self._escape = escape
        self._held = ""

        self.restored = 0

    def feed(self, text):
        return self._scan(self._held + text, final=False)

    def flush(self):
        return self._scan(self._held, final=True)

    def _scan(self, buffer, final):

        self._held = ""

        if not self._matcher or not buffer:
            return buffer

        out = []
        pos = 0

        while True:

            found = self._matcher.search(buffer, pos, partial=not final)

            if found is None:
                out.append(buffer[pos:])
                break

            start, end, original, is_partial = found

            undecided = not final and (
                is_partial or self._matcher.could_continue(buffer, start)
            )

            if undecided and len(buffer) - start <= config.MAX_STREAM_HOLD:

                out.append(buffer[pos:start])
                self._held = buffer[start:]

                break

            if is_partial:
                out.append(buffer[pos:])
                break

            out.append(buffer[pos:start])
            out.append(self._escape(original) if self._escape else original)

            self.restored += 1
            pos = end

        return "".join(out)


EVENT_BOUNDARY = re.compile(rb"\r?\n\r?\n")

# delta field -> (delta type used for a synthetic flush event, escaper)
DELTA_FIELDS = {
    "text": ("text_delta", None),
    "thinking": ("thinking_delta", None),
    "partial_json": ("input_json_delta", json_escape),
}


class SSERestorer:
    """
    Seek over a server-sent-event stream of the Anthropic message format
    (content_block_delta events), as bytes in and bytes out.

    Usable directly as a mitmproxy stream callable: it is called once per
    body chunk and once with b"" at end of stream. Events it does not
    recognise pass through byte-for-byte.
    """

    def __init__(self, session):

        self._session = session
        self._pending = b""
        self._restorers = {}

    @property
    def restored(self):
        return sum(r.restored for r in self._restorers.values())

    def __call__(self, chunk):

        try:
            return self._process(chunk)

        except Exception:
            # Seek must never break the response; the worst case is that
            # the user sees surrogates instead of the restored values.
            pending, self._pending = self._pending, b""
            return pending + chunk

    def _process(self, chunk):

        self._pending += chunk

        out = []
        last_end = 0

        for boundary in EVENT_BOUNDARY.finditer(self._pending):

            block = self._pending[last_end:boundary.start()]

            out.append(self._transform_block(block))
            out.append(boundary.group(0))

            last_end = boundary.end()

        self._pending = self._pending[last_end:]

        if chunk == b"":

            if self._pending:
                out.append(self._transform_block(self._pending))
                self._pending = b""

            for key in list(self._restorers):
                out.append(self._flush_event(key, True, "\n") or b"")

        return b"".join(out)

    def _restorer(self, key):

        if key not in self._restorers:

            self._restorers[key] = StreamRestorer(
                self._session,
                DELTA_FIELDS.get(key[1], (None, None))[1],
            )

        return self._restorers[key]

    def _transform_block(self, block):

        try:
            text = block.decode("utf-8")

        except UnicodeDecodeError:
            return block

        newline = "\r\n" if "\r\n" in text else "\n"
        lines = text.split(newline)

        data_lines = [
            index
            for index, line in enumerate(lines)
            if line.startswith("data:")
        ]

        if not data_lines:
            return block

        payload = "\n".join(
            lines[index][5:].lstrip(" ") for index in data_lines
        )

        try:
            event = json.loads(payload)

        except json.JSONDecodeError:
            return block

        if not isinstance(event, dict):
            return block

        has_event_line = any(line.startswith("event:") for line in lines)

        prefix = self._transform_event(event, has_event_line, newline)

        if prefix is None:
            return block

        lines[data_lines[0]] = "data: " + json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        for index in reversed(data_lines[1:]):
            del lines[index]

        return prefix + newline.join(lines).encode("utf-8")

    def _transform_event(self, event, has_event_line, newline):
        """
        Restore surrogates inside one decoded event, in place.

        Returns bytes to emit before the event (possibly empty), or None if
        the event is not one this class rewrites.
        """

        event_type = event.get("type")
        delta = event.get("delta")

        if event_type == "content_block_delta" and isinstance(delta, dict):

            changed = False

            for field in DELTA_FIELDS:

                if isinstance(delta.get(field), str):

                    restored = self._restorer(
                        (event.get("index"), field)
                    ).feed(delta[field])

                    changed = changed or restored != delta[field]

                    delta[field] = restored

            return b"" if changed else None

        if event_type == "content_block_stop":

            prefix = b""

            for key in list(self._restorers):

                if key[0] == event.get("index"):

                    prefix += self._flush_event(
                        key,
                        has_event_line,
                        newline,
                    ) or b""

            return prefix or None

        # Older claude.ai stream shape: {"type":"completion","completion":".."}
        if isinstance(event.get("completion"), str):

            restorer = self._restorer((None, "completion"))

            event["completion"] = restorer.feed(event["completion"])

            if event.get("stop_reason"):
                event["completion"] += restorer.flush()

            return b""

        return None

    def _flush_event(self, key, has_event_line, newline):
        """Emit whatever a block's restorer is still holding as one delta."""

        index, field = key

        leftover = self._restorers.pop(key).flush()

        if not leftover:
            return None

        if field == "completion":
            event = {"type": "completion", "completion": leftover}

        else:
            event = {
                "type": "content_block_delta",
                "index": index,
                "delta": {
                    "type": DELTA_FIELDS[field][0],
                    field: leftover,
                },
            }

        lines = []

        if has_event_line:
            lines.append(f"event: {event['type']}")

        lines.append(
            "data: "
            + json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        )

        return (newline.join(lines) + newline * 2).encode("utf-8")
