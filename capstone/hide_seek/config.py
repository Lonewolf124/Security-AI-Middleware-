import os
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent

DATA_DIR = Path(os.environ.get("HAS_DATA_DIR", PACKAGE_DIR / "data"))
DB_PATH = Path(os.environ.get("HAS_DB_FILE", DATA_DIR / "vault.sqlite3"))
KEY_PATH = Path(os.environ.get("HAS_KEY_FILE", DATA_DIR / "vault.key"))

# Sessions idle for longer than this are deleted when the proxy starts.
SESSION_TTL_DAYS = int(os.environ.get("HAS_SESSION_TTL_DAYS", "30"))

# The PII model accepts 512 tokens including [CLS]/[SEP]. Longer text is
# scanned in overlapping windows so nothing past token 512 goes unchecked.
WINDOW_TOKENS = 384
OVERLAP_TOKENS = 64

# Values already in a session's vault are re-masked wherever they reappear,
# even if the model misses them. Very short values are skipped to avoid
# masking ordinary words.
MIN_KNOWN_VALUE_LEN = 3

# Entity types whose values are person names. A later mention of one part
# of a masked name ("Rahul" after "Rahul Sharma") maps to the matching part
# of the surrogate name.
NAME_TYPES = frozenset({"PERSON_NAME"})

# Types the provider may re-emit with different spacing or separators
# ("9876 5432 1011"). They are matched on their letters and digits only.
SEPARABLE_TYPES = frozenset({
    "AADHAAR",
    "CREDIT_CARD",
    "PHONE",
    "SSN",
    "PAN_CARD",
    "PASSPORT",
    "DRIVER_LICENSE",
    "VEHICLE_REG",
})

# The reply stream is held back while its tail could still turn into a
# surrogate. Beyond this many characters it is released as it is.
MAX_STREAM_HOLD = 8192
