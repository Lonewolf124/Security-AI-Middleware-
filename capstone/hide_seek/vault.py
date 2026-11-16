import hashlib
import hmac
import sqlite3
import threading
import time
import unicodedata
from pathlib import Path

from cryptography.fernet import Fernet

from . import config


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY,
    provider        TEXT NOT NULL,
    org_id          TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    created_at      REAL NOT NULL,
    last_seen_at    REAL NOT NULL,
    UNIQUE (provider, org_id, conversation_id)
);

CREATE TABLE IF NOT EXISTS mappings (
    id            INTEGER PRIMARY KEY,
    session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    entity_type   TEXT NOT NULL,
    idx           INTEGER NOT NULL,
    value_hmac    TEXT NOT NULL,
    value_enc     BLOB NOT NULL,
    surrogate_enc BLOB NOT NULL,
    created_at    REAL NOT NULL,
    UNIQUE (session_id, entity_type, idx),
    UNIQUE (session_id, value_hmac)
);
"""

SURROGATE_ATTEMPTS = 20

HONORIFICS = frozenset({
    "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "shri", "sri", "smt", "er",
})


def normalise(value):
    return " ".join(
        unicodedata.normalize("NFKC", value).casefold().split()
    )


def placeholder(entity_type, idx):
    return f"[{entity_type}_{idx}]"


class Vault:
    """
    Per-session store of original value <-> surrogate.

    Both sides are encrypted at rest (Fernet). Lookups by original value use
    a keyed hash, so the database never holds a plaintext or unsalted-hash
    copy of anything that was masked.
    """

    def __init__(self, db_path=None, key_path=None):

        db_path = Path(db_path or config.DB_PATH)
        key_path = Path(key_path or config.KEY_PATH)

        db_path.parent.mkdir(parents=True, exist_ok=True)

        key = self._load_key(key_path)

        self._fernet = Fernet(key)
        self._mac_key = hashlib.sha256(b"has-lookup:" + key).digest()

        # Re-entrant: generating one surrogate can assign another (an email
        # address assigns its domain).
        self._lock = threading.RLock()

        self._db = sqlite3.connect(
            db_path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)

    @staticmethod
    def _load_key(key_path):

        if key_path.exists():
            return key_path.read_bytes().strip()

        key_path.parent.mkdir(parents=True, exist_ok=True)

        key = Fernet.generate_key()

        with open(key_path, "xb") as handle:
            handle.write(key)

        return key

    def close(self):
        self._db.close()

    def session(self, provider, org_id, conversation_id):

        now = time.time()

        with self._lock:

            self._db.execute(
                "INSERT INTO sessions "
                "(provider, org_id, conversation_id, created_at, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (provider, org_id, conversation_id) "
                "DO UPDATE SET last_seen_at = excluded.last_seen_at",
                (provider, org_id, conversation_id, now, now),
            )

            session_id = self._db.execute(
                "SELECT id FROM sessions "
                "WHERE provider = ? AND org_id = ? AND conversation_id = ?",
                (provider, org_id, conversation_id),
            ).fetchone()[0]

        return Session(self, session_id)

    def find_session(self, provider, org_id, conversation_id):
        """Return an existing session without creating or touching it."""

        with self._lock:

            row = self._db.execute(
                "SELECT id FROM sessions "
                "WHERE provider = ? AND org_id = ? AND conversation_id = ?",
                (provider, org_id, conversation_id),
            ).fetchone()

        return Session(self, row[0]) if row else None

    def purge_expired(self, ttl_days=None):

        ttl_days = config.SESSION_TTL_DAYS if ttl_days is None else ttl_days
        cutoff = time.time() - ttl_days * 86400

        with self._lock:

            cursor = self._db.execute(
                "DELETE FROM sessions WHERE last_seen_at < ?",
                (cutoff,),
            )

            return cursor.rowcount

    def stats(self):

        with self._lock:

            sessions = self._db.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0]

            mappings = self._db.execute(
                "SELECT COUNT(*) FROM mappings"
            ).fetchone()[0]

        return {"sessions": sessions, "mappings": mappings}

    def conversations(self):
        """(provider, conversation_id, created_at, last_seen_at, values)."""

        with self._lock:

            return self._db.execute(
                "SELECT s.provider, s.conversation_id, s.created_at, "
                "s.last_seen_at, COUNT(m.id) "
                "FROM sessions s LEFT JOIN mappings m ON m.session_id = s.id "
                "GROUP BY s.id ORDER BY s.last_seen_at DESC"
            ).fetchall()

    def _mac(self, value):
        return hmac.new(
            self._mac_key,
            normalise(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


class Session:
    """The mappings of one conversation."""

    def __init__(self, vault, session_id):

        self._vault = vault
        self._id = session_id

        self._entries = []
        self._by_value = {}
        self._taken = set()

        # Compiled matchers, owned by hide_seek.matching.
        self.matcher_cache = {}

        with vault._lock:

            rows = vault._db.execute(
                "SELECT entity_type, value_hmac, value_enc, surrogate_enc "
                "FROM mappings WHERE session_id = ? ORDER BY id",
                (session_id,),
            ).fetchall()

        for row in rows:
            self._remember(*row)

    def _remember(self, entity_type, value_hmac, value_enc, surrogate_enc):

        fernet = self._vault._fernet

        original = fernet.decrypt(value_enc).decode("utf-8")
        surrogate = fernet.decrypt(surrogate_enc).decode("utf-8")

        self._entries.append((entity_type, original, surrogate))
        self._by_value[value_hmac] = surrogate

        self._taken.add(normalise(original))
        self._taken.add(normalise(surrogate))

        return surrogate

    def __len__(self):
        return len(self._entries)

    @property
    def date_offset(self):
        """A fixed day shift for this session, 15 to 300 days either way."""

        digest = hmac.new(
            self._vault._mac_key,
            f"date-offset:{self._id}".encode(),
            hashlib.sha256,
        ).digest()

        days = 15 + int.from_bytes(digest[:4], "big") % 286

        return days if digest[4] % 2 else -days

    def lookup(self, value):
        """Return the surrogate already assigned to this value, or None."""

        surrogate = self._by_value.get(self._vault._mac(value))

        if surrogate is not None:
            return surrogate

        key = normalise(value)

        for _type, original, alias in self.aliases():

            if normalise(original) == key:
                return alias

        return None

    def assign(self, entity_type, value, make):
        """
        Return the surrogate for this value, creating one if it is new.

        make() proposes a surrogate, or returns None when the type has no
        generator. A proposal that collides with anything already in the
        session is rejected; after repeated failures an indexed placeholder
        is used instead.
        """

        existing = self.lookup(value)

        if existing is not None:
            return existing

        vault = self._vault
        value_hmac = vault._mac(value)

        with vault._lock:

            row = vault._db.execute(
                "SELECT entity_type, value_hmac, value_enc, surrogate_enc "
                "FROM mappings WHERE session_id = ? AND value_hmac = ?",
                (self._id, value_hmac),
            ).fetchone()

            if row is not None:
                return self._remember(*row)

            surrogate = None

            for _ in range(SURROGATE_ATTEMPTS):

                candidate = make()

                if candidate is None:
                    break

                if (
                    normalise(candidate)
                    and normalise(candidate) != normalise(value)
                    and normalise(candidate) not in self._taken
                ):
                    surrogate = candidate
                    break

            # make() may itself have assigned (an email assigns its domain),
            # so the index is read only now.
            idx = vault._db.execute(
                "SELECT COALESCE(MAX(idx), 0) + 1 FROM mappings "
                "WHERE session_id = ? AND entity_type = ?",
                (self._id, entity_type),
            ).fetchone()[0]

            if surrogate is None:
                surrogate = placeholder(entity_type, idx)

            row = (
                entity_type,
                value_hmac,
                vault._fernet.encrypt(value.encode("utf-8")),
                vault._fernet.encrypt(surrogate.encode("utf-8")),
            )

            vault._db.execute(
                "INSERT INTO mappings "
                "(session_id, entity_type, idx, value_hmac, value_enc, "
                "surrogate_enc, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._id, entity_type, idx, *row[1:], time.time()),
            )

            return self._remember(*row)

    def aliases(self):
        """
        Part-of-name pairs derived from stored names: "Rahul Sharma" ->
        "Arjun Nair" also gives "Rahul" -> "Arjun" and "Sharma" -> "Nair".
        """

        result = []
        seen = set(self._taken)

        for entity_type, original, surrogate in self._entries:

            if entity_type not in config.NAME_TYPES:
                continue

            original_parts = original.split()
            surrogate_parts = surrogate.split()

            if len(original_parts) != len(surrogate_parts):
                continue

            if len(original_parts) < 2:
                continue

            for part, fake in zip(original_parts, surrogate_parts):

                part = part.strip(".,")
                fake = fake.strip(".,")
                key = normalise(part)

                if (
                    len(part) < 3
                    or key in HONORIFICS
                    or key in seen
                    or key == normalise(fake)
                    or any(char.isdigit() for char in part)
                ):
                    continue

                seen.add(key)
                result.append((entity_type, part, fake))

        return result

    def entries(self):
        """The stored (entity_type, original, surrogate), in masking order."""

        return list(self._entries)

    def pairs(self):
        """Every (entity_type, original, surrogate), including aliases."""

        return self._entries + self.aliases()
