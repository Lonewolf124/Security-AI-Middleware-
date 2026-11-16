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
    "BANK_ACCOUNT",
    "IFSC",
    "GSTIN",
    "VOTER_ID",
})

# The reply stream is held back while its tail could still turn into a
# surrogate. Beyond this many characters it is released as it is.
MAX_STREAM_HOLD = 8192

# Types whose values can contain spaces. A model detection of any other
# type that covers several words is treated as several values.
MULTI_WORD_TYPES = frozenset({
    "PERSON_NAME",
    "ADDRESS",
    "PHONE",
    "AADHAAR",
    "CREDIT_CARD",
    "VEHICLE_REG",
    "DRIVER_LICENSE",
    "DATE_OF_BIRTH",
    "BANK_ACCOUNT",
    "ORG_NAME",
})

# Types whose values can begin or end with a symbol.
SYMBOL_TYPES = frozenset({"PASSWORD", "API_KEY", "SECRET"})

# How readily the model's doubts count as private data, 0.0 to 1.0.
# 0.5 is the model's own choice; see detector.py.
SENSITIVITY = float(os.environ.get("HAS_SENSITIVITY", "0.5"))

# What to mask. A profile is a set of entity types; "all" masks everything
# that is detected. Chosen with HAS_PROFILE, or a comma-separated list of
# entity types in HAS_MASK_TYPES.
PROFILES = {
    "credentials": frozenset({
        "PASSWORD", "API_KEY", "SECRET", "PRIVATE_KEY", "AWS_TEST_KEY",
        "GITHUB_TEST_TOKEN",
    }),
    "financial": frozenset({
        "CREDIT_CARD", "BANK_ACCOUNT", "IFSC", "UPI_ID", "GSTIN", "PAN_CARD",
    }),
    "government_id": frozenset({
        "AADHAAR", "PAN_CARD", "PASSPORT", "DRIVER_LICENSE", "VOTER_ID",
        "SSN", "VEHICLE_REG",
    }),
    "contact": frozenset({"PHONE", "EMAIL", "ADDRESS", "IP_ADDRESS"}),
    "identity": frozenset({
        "PERSON_NAME", "DATE_OF_BIRTH", "USERNAME", "ORG_NAME",
    }),
}


def mask_types():
    """The entity types to mask, or None for all of them."""

    explicit = os.environ.get("HAS_MASK_TYPES", "").strip()

    if explicit:
        return frozenset(t.strip().upper() for t in explicit.split(",") if t.strip())

    names = [
        n.strip().lower()
        for n in os.environ.get("HAS_PROFILE", "all").split("+")
        if n.strip()
    ]

    if not names or "all" in names:
        return None

    unknown = [n for n in names if n not in PROFILES]

    if unknown:
        raise ValueError(
            f"unknown HAS_PROFILE {unknown}; choose from "
            f"{sorted(PROFILES)} joined with '+', or 'all'"
        )

    return frozenset().union(*(PROFILES[n] for n in names))
