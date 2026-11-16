import re
import unicodedata
from dataclasses import dataclass

from . import config


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    type: str
    # Higher wins an overlap; equal priority goes to the longer span.
    priority: int = 0
    surrogate: str = None

    def __len__(self):
        return self.end - self.start


# A model detection separated from the next one by a single one of these is
# one value that the model split in two ("Str0ngPass" + "!" + "99").
MERGE_GAP = frozenset("-_.@:/+!#$%&*=")

# Widening a detection to the whole value crosses these, but not ":" or "=",
# so the key of "password=hunter2" is never swallowed with its value.
WITHIN_VALUE = frozenset(".@-_+")

MIN_VALUE_LEN = 3
MIN_TOKEN_COVERAGE = 0.5

# Words the model drags into a span when it labels two values as one
# ("10.0.0.1 and 10.0.0.2").
CONNECTING_WORDS = frozenset({
    "and", "or", "to", "the", "from", "with", "for", "via", "at", "on", "in",
})

SENTENCE_MARKS = ".,;:"


def _wordish(char):
    return (
        char.isalnum()
        or char == "_"
        or unicodedata.category(char)[0] == "M"
    )


def _inside(char):
    return _wordish(char) or char in MERGE_GAP


def _stops(char):
    return char.isspace() or char in "=:\"'`()[]{}<>,;"


def _trim(text, start, end, entity_type):
    """Cut what the model attached to the edges of a value."""

    while start < end and text[start].isspace():
        start += 1

    while end > start and text[end - 1].isspace():
        end -= 1

    if entity_type in config.SYMBOL_TYPES:

        # Symbols can be part of a password or key; a closing sentence
        # mark is not.
        if end - start > 1 and text[end - 1] in SENTENCE_MARKS:
            end -= 1

        return start, end

    while start < end and not _wordish(text[start]):

        # "+" opens a phone number.
        if text[start] == "+" and (
            end - start == 1 or text[start + 1].isdigit()
        ):
            break

        start += 1

    while end > start + 1 and not _wordish(text[end - 1]):
        end -= 1

    return start, end


def _values(text, span):
    """Yield (start, end) of each separate value inside one detection."""

    if span.type in config.MULTI_WORD_TYPES:
        candidates = [(span.start, span.end)]

    else:
        candidates = [
            (span.start + match.start(), span.start + match.end())
            for match in re.finditer(r"\S+", text[span.start:span.end])
        ]

    for start, end in candidates:

        start, end = _trim(text, start, end, span.type)
        value = text[start:end]

        if value != "+" and not any(_wordish(char) for char in value):
            continue

        if len(candidates) > 1 and value.lower() in CONNECTING_WORDS:
            continue

        yield start, end


def tidy_model_spans(text, spans):
    """
    Turn raw model detections into spans that can be restored reliably.

    The model labels sub-word pieces and is loose about edges: a detection
    may be one letter of a word, half of an ID, two values joined by "and",
    or a value plus the punctuation after it, and one value may arrive as
    two pieces with different labels. Each detection is trimmed, split
    into its values, widened to whole tokens and joined with the pieces it
    touches. What is then too short, or was guessed from a small part of a
    larger word, is dropped.
    """

    found = []

    for span in spans:

        for start, end in _values(text, span):

            covered = end - start

            if span.type in config.SYMBOL_TYPES:

                # A password or key runs to the next space, whatever
                # symbols it contains, but not past "key=" or a quote.
                while start > 0 and not _stops(text[start - 1]):
                    start -= 1

                while end < len(text) and not _stops(text[end]):
                    end += 1

                if end - start > 1 and text[end - 1] in SENTENCE_MARKS:
                    end -= 1

            while start > 0 and (
                (_wordish(text[start - 1]) and _inside(text[start]))
                or (
                    start > 1
                    and text[start - 1] in WITHIN_VALUE
                    and _wordish(text[start - 2])
                    and _wordish(text[start])
                )
            ):
                start -= 1

            while end < len(text) and (
                (_wordish(text[end]) and _inside(text[end - 1]))
                or (
                    end + 1 < len(text)
                    and text[end] in WITHIN_VALUE
                    and _wordish(text[end + 1])
                    and _wordish(text[end - 1])
                )
            ):
                end += 1

            found.append((start, end, span.type, covered))

    pieces = []

    for start, end, entity_type, covered in sorted(found):

        if pieces:

            last = pieces[-1]
            gap = text[last[1]:start]

            # A piece too short to stand alone belongs to its neighbour
            # ("DL" + "3C AB 4567").
            fragment = min(end - start, last[1] - last[0]) < MIN_VALUE_LEN

            same_spaced_value = (
                entity_type == last[3]
                and entity_type in config.MULTI_WORD_TYPES
            )

            joins = start <= last[1] or (
                len(gap) == 1
                and (
                    gap in MERGE_GAP
                    or (gap == " " and (fragment or same_spaced_value))
                )
            )

            if joins:

                last[1] = max(last[1], end)
                last[2][entity_type] = last[2].get(entity_type, 0) + covered
                last[3] = max(last[2], key=last[2].get)

                continue

        pieces.append([start, end, {entity_type: covered}, entity_type])

    result = []

    for start, end, covered, entity_type in pieces:

        if end - start < MIN_VALUE_LEN:
            continue

        # A small piece of an ordinary word ("L" in "LDAP") is a false alarm.
        # A small piece of an identifier ("_mk" in "contractor_mk") is not.
        if (
            text[start:end].isalpha()
            and sum(covered.values()) / (end - start) < MIN_TOKEN_COVERAGE
        ):
            continue

        result.append(Span(start, end, entity_type))

    return result
