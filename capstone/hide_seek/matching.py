import regex

from . import config


SEPARATOR = r"[\s\-.]{0,2}"


def _literal(text):

    parts = []

    for word in text.split():

        chars = []

        for char in word:

            # Markdown output may escape these.
            if char in "_*":
                chars.append(r"\\?")

            chars.append(regex.escape(char))

        parts.append("".join(chars))

    return r"\s+".join(parts)


def _pattern(entity_type, needle, escape):

    body = None

    if entity_type in config.SEPARABLE_TYPES:

        chars = [char for char in needle if char.isalnum()]

        if len(chars) >= 6:

            body = SEPARATOR.join(regex.escape(char) for char in chars)

            if needle.lstrip().startswith("+"):
                body = r"\+?" + body

            first, last = chars[0], chars[-1]

    if body is None:

        text = escape(needle) if escape else needle
        stripped = text.strip()

        if not stripped:
            return None

        body = _literal(stripped)
        first, last = stripped[0], stripped[-1]

    if first.isalnum():
        body = r"(?<!\w)" + body

    if last.isalnum():

        if entity_type in config.NAME_TYPES:
            # A name is still that name with a plural or possessive "s"
            # attached: "Rahuls phone", "Rahul's phone".
            body = body + r"(?=s?(?!\w))"
        else:
            body = body + r"(?!\w)"

    return body


class Matcher:
    """
    Finds any of a set of strings in text, tolerant to case, whitespace
    and, for ID-like types, separators.

    items: (entity_type, needle, payload). Longer needles win.
    """

    def __init__(self, items, escape=None):

        self._payloads = []
        patterns = []

        for entity_type, needle, payload in sorted(
            items,
            key=lambda item: -len(item[1]),
        ):

            if len(needle.strip()) < config.MIN_KNOWN_VALUE_LEN:
                continue

            pattern = _pattern(entity_type, needle, escape)

            if pattern is None:
                continue

            patterns.append(f"({pattern})")
            self._payloads.append(payload)

        self._regex = (
            regex.compile("|".join(patterns), regex.IGNORECASE)
            if patterns
            else None
        )

    def __bool__(self):
        return self._regex is not None

    def finditer(self, text):
        """Yield (start, end, payload) for each non-overlapping match."""

        if self._regex is None:
            return

        for match in self._regex.finditer(text):
            yield match.start(), match.end(), self._payloads[match.lastindex - 1]

    def search(self, text, pos, partial):
        """Return (start, end, payload, is_partial) or None."""

        if self._regex is None:
            return None

        match = self._regex.search(text, pos, partial=partial)

        if match is None:
            return None

        if match.partial:
            return match.start(), match.end(), None, True

        return (
            match.start(),
            match.end(),
            self._payloads[match.lastindex - 1],
            False,
        )

    def could_continue(self, text, pos):
        """True if text[pos:] is, or may grow into, one complete needle."""

        return self._regex.fullmatch(text, pos, partial=True) is not None


def originals_matcher(session):
    """Matches original values; payload is (entity_type, surrogate)."""

    return _cached(
        session,
        "originals",
        lambda: Matcher(
            (entity_type, original, (entity_type, surrogate))
            for entity_type, original, surrogate in session.pairs()
        ),
    )


def issued_matcher(session):
    """Matches surrogates; payload is the entity type of each."""

    return _cached(
        session,
        "issued",
        lambda: Matcher(
            (entity_type, surrogate, entity_type)
            for entity_type, _original, surrogate in session.pairs()
        ),
    )


def surrogates_matcher(session, escape=None):
    """Matches surrogates; payload is the original value."""

    return _cached(
        session,
        ("surrogates", escape),
        lambda: Matcher(
            (
                (entity_type, surrogate, original)
                for entity_type, original, surrogate in session.pairs()
            ),
            escape,
        ),
    )


def _cached(session, key, build):

    key = (key, len(session))

    if key not in session.matcher_cache:
        session.matcher_cache[key] = build()

    return session.matcher_cache[key]
