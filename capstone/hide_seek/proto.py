"""
Schema-less protobuf wire-format reader, for traffic whose .proto files
are not available (the claude.ai web app's RPC interface).

A length-delimited field can be a nested message, a string or raw bytes;
the wire format does not say which, so classify() decides from content.
"""

import gzip
import struct
import zlib


VARINT, FIXED64, LEN, FIXED32 = 0, 1, 2, 5

MAX_FIELD_NUMBER = 100000


def read_varint(data, pos):

    value = 0
    shift = 0

    while True:

        if pos >= len(data) or shift > 63:
            raise ValueError("bad varint")

        byte = data[pos]
        pos += 1

        value |= (byte & 0x7F) << shift

        if not byte & 0x80:
            return value, pos

        shift += 7


def parse(data):
    """
    Return [(field_number, wire_type, value, raw)] or None if data is not
    a well-formed message. value is an int for VARINT and bytes otherwise;
    raw is the field exactly as it was encoded, tag included.
    """

    fields = []
    pos = 0

    try:

        while pos < len(data):

            start = pos

            tag, pos = read_varint(data, pos)

            number, wire_type = tag >> 3, tag & 7

            if not 1 <= number <= MAX_FIELD_NUMBER:
                return None

            if wire_type == VARINT:
                value, pos = read_varint(data, pos)

            elif wire_type == LEN:

                size, pos = read_varint(data, pos)

                if pos + size > len(data):
                    return None

                value = data[pos:pos + size]
                pos += size

            elif wire_type in (FIXED64, FIXED32):

                size = 8 if wire_type == FIXED64 else 4

                if pos + size > len(data):
                    return None

                value = data[pos:pos + size]
                pos += size

            else:
                return None

            fields.append((number, wire_type, value, data[start:pos]))

    except ValueError:
        return None

    return fields


def _as_text(data):

    try:
        text = data.decode("utf-8")

    except UnicodeDecodeError:
        return None

    if any(ord(char) < 32 and char not in "\t\n\r" for char in text):
        return None

    return text


def classify(data):
    """Return ("message", fields), ("text", str) or ("bytes", data)."""

    text = _as_text(data)
    fields = parse(data) if data else None

    if fields is not None and text is None:
        return "message", fields

    if text is not None and fields is None:
        return "text", text

    if text is not None and fields is not None:

        # Both readings are possible. A message nearly always opens with
        # a low-numbered field, whose tag byte is a control character and
        # so not something text starts with, apart from a newline.
        if data[:1] == b"\n":
            return "message", fields

        return "text", text

    return "bytes", data


def encode_varint(value):

    out = bytearray()

    while True:

        byte = value & 0x7F
        value >>= 7

        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def encode_len(number, payload):
    """Encode one length-delimited field."""

    return encode_varint(number << 3 | LEN) + encode_varint(len(payload)) + payload


def first(fields, number, wire_type=LEN):
    """The value of the first field with this number, or None."""

    for field_number, field_type, value, _raw in fields or ():

        if field_number == number and field_type == wire_type:
            return value

    return None


def rewrite(data, text_fn, path=()):
    """
    Rebuild a message with its text values passed through text_fn.

    text_fn(path, text) returns the replacement text, or None to keep the
    value. path is the tuple of field numbers leading to the value. Fields
    that do not change are copied byte for byte, and the same object is
    returned when nothing changed at all.
    """

    if path:
        kind, value = classify(data)

    else:
        # The outermost value is always a message.
        value = parse(data)
        kind = "message" if value is not None else "bytes"

    if kind == "text":

        replacement = text_fn(path, value)

        if replacement is None or replacement == value:
            return data

        return replacement.encode("utf-8")

    if kind != "message":
        return data

    out = []
    changed = False

    for number, wire_type, field, raw in value:

        if wire_type == LEN:

            new = rewrite(field, text_fn, path + (number,))

            if new is not field:
                out.append(encode_len(number, new))
                changed = True
                continue

        out.append(raw)

    return b"".join(out) if changed else data


def frame(flags, payload):
    return struct.pack(">BI", flags, len(payload)) + payload


def frames(data):
    """
    Split a Connect streaming body into (flags, payload, raw) frames.

    Returns (frames, remainder), where remainder is an incomplete tail.
    """

    result = []
    pos = 0

    while pos + 5 <= len(data):

        flags, size = struct.unpack(">BI", data[pos:pos + 5])

        if pos + 5 + size > len(data):
            break

        result.append(
            (flags, data[pos + 5:pos + 5 + size], data[pos:pos + 5 + size])
        )

        pos += 5 + size

    return result, data[pos:]


def decompress(payload, encoding):
    """Return the decompressed payload, or None if it cannot be decoded."""

    encoding = (encoding or "").lower()

    try:

        if encoding == "gzip":
            return gzip.decompress(payload)

        if encoding == "deflate":
            return zlib.decompress(payload)

        if encoding == "br":
            import brotli
            return brotli.decompress(payload)

        if encoding == "zstd":
            import zstandard
            return zstandard.ZstdDecompressor().decompressobj().decompress(payload)

    except Exception:
        return None

    return None
