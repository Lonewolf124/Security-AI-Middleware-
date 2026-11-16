import re

from . import config
from . import surrogates
from .matching import issued_matcher, originals_matcher
from .spans import Span, tidy_model_spans


PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----"
    r".*?"
    r"-----END \1PRIVATE KEY-----",
    re.DOTALL,
)

PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")

# A number counts only when it stands alone, not as part of a longer token.
AADHAAR_LIKE = re.compile(
    r"(?<![\w.])[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\w)(?!\.\d)"
)
CARD_LIKE = re.compile(r"(?<![\w.])\d(?:[ -]?\d){12,18}(?!\w)(?!\.\d)")

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(digits):

    check = 0

    for index, char in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][int(char)]]

    return check == 0


def luhn_ok(digits):

    total = 0

    for index, char in enumerate(reversed(digits)):

        digit = int(char)

        if index % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2

        total += digit

    return total % 10 == 0


def resolve_overlaps(spans):
    """Keep non-overlapping spans, preferring priority, then length."""

    kept = []

    for span in sorted(spans, key=lambda s: (-s.priority, -len(s), s.start)):

        if all(span.end <= k.start or span.start >= k.end for k in kept):
            kept.append(span)

    return sorted(kept, key=lambda s: s.start)


class Hider:
    """
    The Hide step: replace every private value in a text with a surrogate
    and record the pair in the session.

    detect(text) returns entities as dicts with "start", "end" and "type"
    (the shape PIIModel.detect produces). tokenizer is optional and only
    used to window long text. secret_patterns is a list of
    (entity_type, compiled regex) for credentials with a fixed format.
    """

    def __init__(self, detect, tokenizer=None, secret_patterns=()):

        self._detect = detect
        self._tokenizer = tokenizer
        self._secret_patterns = list(secret_patterns)

    @classmethod
    def default(cls):
        """Build a Hider on the project's existing regex + ONNX detectors."""

        from dlp_engine.detectors import PATTERNS
        from dlp_engine.engine import pii_model

        return cls(
            pii_model.detect,
            pii_model.tokenizer,
            [
                (rule["type"], rule["pattern"])
                for rule in PATTERNS
                if rule["type"] != "PRIVATE_KEY"
            ],
        )

    def hide(self, text, session):
        """
        Return (masked_text, findings).

        A finding with action "BLOCK" means the text must not be forwarded.
        """

        if not text.strip():
            return text, []

        spans = self._format_spans(text)

        blocks = [span for span in spans if span.type == "PRIVATE_KEY"]

        for match in PRIVATE_KEY_HEADER.finditer(text):

            # A key with no END line cannot be bounded, so it cannot be
            # replaced reliably.
            if not any(b.start <= match.start() < b.end for b in blocks):
                return text, [{"type": "PRIVATE_KEY", "action": "BLOCK"}]

        spans += self._detect_spans(text)

        spans += [
            Span(start, end, entity_type, 0, surrogate)
            for start, end, (entity_type, surrogate)
            in originals_matcher(session).finditer(text)
        ]

        # Text the user sends never legitimately contains a surrogate, since
        # everything shown to them was restored first. So a value that
        # equals one is a real value that happens to collide (the user
        # means an actual "Nikhil", not the fake standing in for "Rahul").
        # It gets a surrogate of its own, which keeps the two apart.
        spans += [
            Span(start, end, entity_type)
            for start, end, entity_type
            in issued_matcher(session).finditer(text)
        ]

        spans = resolve_overlaps(spans)

        # Names first: an email or username that contains a name follows
        # the fake name chosen for it.
        replacements = {}

        for span in sorted(spans, key=lambda s: s.type not in config.NAME_TYPES):

            value = text[span.start:span.end]

            replacements[span] = session.assign(
                span.type,
                value,
                lambda: surrogates.generate(span.type, value, session),
            )

        findings = []

        for span in reversed(spans):

            text = text[:span.start] + replacements[span] + text[span.end:]

            findings.append({"type": span.type, "action": "MASK"})

        findings.reverse()

        return text, findings

    def _format_spans(self, text):
        """Values recognised by their format alone."""

        spans = [
            Span(match.start(), match.end(), "PRIVATE_KEY", 2)
            for match in PRIVATE_KEY_BLOCK.finditer(text)
        ]

        for entity_type, pattern in self._secret_patterns:

            spans += [
                Span(match.start(), match.end(), entity_type, 1)
                for match in pattern.finditer(text)
            ]

        # Checksums only ever add a detection. A number the model labels
        # is masked whether or not its checksum holds.
        for match in AADHAAR_LIKE.finditer(text):

            if verhoeff_ok(re.sub(r"\D", "", match.group(0))):
                spans.append(Span(match.start(), match.end(), "AADHAAR", 1))

        for match in CARD_LIKE.finditer(text):

            if luhn_ok(re.sub(r"\D", "", match.group(0))):
                spans.append(Span(match.start(), match.end(), "CREDIT_CARD", 1))

        return spans

    def _detect_spans(self, text):

        spans = []

        for window_start, window_end in self._windows(text):

            window = text[window_start:window_end]

            for entity in self._detect(window):

                start = window_start + entity["start"]
                end = window_start + entity["end"]

                while start < end and text[start].isspace():
                    start += 1

                while end > start and text[end - 1].isspace():
                    end -= 1

                if end > start:
                    spans.append(Span(start, end, entity["type"]))

        return tidy_model_spans(text, spans)

    def _windows(self, text):

        if self._tokenizer is None:
            return [(0, len(text))]

        offsets = self._tokenizer(
            text,
            add_special_tokens=False,
            return_offsets_mapping=True,
            verbose=False,
        )["offset_mapping"]

        if len(offsets) <= config.WINDOW_TOKENS:
            return [(0, len(text))]

        windows = []
        step = config.WINDOW_TOKENS - config.OVERLAP_TOKENS

        for first in range(0, len(offsets), step):

            chunk = offsets[first:first + config.WINDOW_TOKENS]

            windows.append((chunk[0][0], chunk[-1][1]))

            if first + config.WINDOW_TOKENS >= len(offsets):
                break

        return windows
