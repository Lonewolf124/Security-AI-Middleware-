"""
Show what the proxy has masked. Run from the capstone directory:

    python -m hide_seek.audit                    one line per conversation
    python -m hide_seek.audit 4525e51a           types masked in that conversation
    python -m hide_seek.audit 4525e51a --reveal  also the original and fake values

Without --reveal no masked value is decrypted or printed.
"""

import datetime
import sys
from collections import Counter

from .vault import Vault


def _when(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


def report(vault, prefix=None, reveal=False):
    """Return the report as a list of lines."""

    rows = vault.conversations()

    if prefix is None:

        lines = [f"{len(rows)} conversations in the vault"]

        for provider, conversation_id, _created, last_seen, count in rows:
            lines.append(
                f"{conversation_id[:8]}  {provider:10s} "
                f"last used {_when(last_seen)}  {count} values masked"
            )

        return lines

    matches = [row for row in rows if row[1].startswith(prefix.lower())]

    if len(matches) != 1:
        return [f"{len(matches)} conversations match '{prefix}'"]

    provider, conversation_id, created, last_seen, _count = matches[0]

    session = vault.find_session(provider, "", conversation_id)
    entries = session.entries() if session is not None else []

    lines = [
        f"conversation {conversation_id} ({provider})",
        f"first masked {_when(created)}, last used {_when(last_seen)}",
    ]

    for entity_type, count in sorted(Counter(e[0] for e in entries).items()):
        lines.append(f"  {entity_type:16s} {count}")

    if reveal:

        lines.append("original -> sent to the provider")

        for entity_type, original, surrogate in entries:
            lines.append(f"  {entity_type:16s} {original!r} -> {surrogate!r}")

    return lines


def main(argv):

    args = [arg for arg in argv if not arg.startswith("--")]

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    vault = Vault()

    try:
        print("\n".join(report(vault, args[0] if args else None, "--reveal" in argv)))

    finally:
        vault.close()


if __name__ == "__main__":
    main(sys.argv[1:])
