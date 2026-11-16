"""
Surrogate generators: for a detected value, produce a random fake of the
same kind and shape. No generator here needs a model or the network.

generate() returns None when a type has no generator; the vault then
falls back to an indexed placeholder such as [ADDRESS_1].
"""

import datetime
import re
import secrets
import string
import unicodedata


_rng = secrets.SystemRandom()


FIRST_NAMES = [
    "Aarav", "Aditi", "Akash", "Ananya", "Arjun", "Bhavna", "Deepak",
    "Divya", "Gaurav", "Harini", "Ishaan", "Jyoti", "Karthik", "Kavya",
    "Lakshmi", "Manish", "Meera", "Naveen", "Neha", "Nikhil", "Pooja",
    "Pranav", "Rekha", "Rohan", "Sanjay", "Sneha", "Suresh", "Tanvi",
    "Varun", "Vidya", "Daniel", "Emma", "Grace", "Henry", "Laura",
    "Martin", "Nora", "Oliver", "Sarah", "Thomas",
]

LAST_NAMES = [
    "Agarwal", "Bose", "Chatterjee", "Desai", "Fernandes", "Ghosh",
    "Hegde", "Iyer", "Joshi", "Kapoor", "Kulkarni", "Menon", "Mishra",
    "Nair", "Pandey", "Pillai", "Rao", "Reddy", "Saxena", "Shetty",
    "Sinha", "Thakur", "Trivedi", "Varma", "Yadav", "Bennett", "Carter",
    "Foster", "Hughes", "Morgan", "Parker", "Turner",
]

FIRST_NAMES_DEVANAGARI = [
    "अमित", "अनीता", "दीपक", "गीता", "किरण", "मनोज", "नेहा", "पूजा",
    "राजेश", "सीमा", "सुनील", "विकास",
]

LAST_NAMES_DEVANAGARI = [
    "जोशी", "कपूर", "मिश्रा", "पांडे", "राव", "सक्सेना", "सिन्हा",
    "ठाकुर", "त्रिवेदी", "वर्मा", "यादव", "देसाई",
]

DOMAIN_WORDS = [
    "northfield", "bluepeak", "lumenworks", "greyharbor", "sunvale",
    "novaline", "redmaple", "quillstone", "ironbridge", "clearwater",
    "eastgate", "silveroak", "brightpath", "stonemill", "highmeadow",
    "larkspur", "westbrook", "fairhaven", "oakridge", "pinecrest",
]

ORG_WORDS = [
    "Northfield", "Bluepeak", "Lumen", "Greyharbor", "Sunvale", "Novaline",
    "Redmaple", "Quillstone", "Ironbridge", "Clearwater", "Eastgate",
    "Silveroak", "Brightpath", "Stonemill", "Highmeadow", "Larkspur",
    "Westbrook", "Fairhaven", "Oakridge", "Pinecrest", "Meridian", "Altura",
]

# Kept as they are, so the fake still reads as the same kind of organisation.
ORG_SUFFIXES = frozenset({
    "pvt", "private", "ltd", "limited", "llp", "inc", "corp", "corporation",
    "co", "company", "and", "of", "the", "bank", "hospital", "hospitals",
    "school", "college", "university", "industries", "technologies",
    "solutions", "services", "systems", "finserv", "finance", "logistics",
    "textiles", "infra", "enterprises", "group", "associates", "consultants",
    "labs", "clinic", "pharma", "foods", "motors", "traders", "stores",
})

HONORIFICS = frozenset({
    "mr", "mrs", "ms", "miss", "mx", "dr", "prof", "shri", "sri", "smt", "er",
})

PUBLIC_MAIL_DOMAINS = frozenset({
    "gmail.com", "yahoo.com", "yahoo.in", "yahoo.co.in", "outlook.com",
    "hotmail.com", "icloud.com", "live.com", "proton.me", "protonmail.com",
    "rediffmail.com", "aol.com", "example.com", "example.org", "example.net",
})

SECOND_LEVEL_LABELS = frozenset({"co", "com", "org", "net", "gov", "ac", "edu"})

# Kept as they are, so a fake key is still recognisable as that kind of key.
KEY_PREFIXES = (
    "github_pat_", "sk-ant-", "sk-proj-", "sk-", "ghp_", "gho_", "ghs_",
    "glpat-", "xoxb-", "xoxp-", "nvapi-", "hf_", "AKIA", "ASIA", "AIza",
    "Bearer ",
)

DATE_FORMATS = (
    "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%Y-%m-%d", "%Y/%m/%d",
    "%d %B %Y", "%d %b %Y", "%B %d, %Y", "%b %d, %Y", "%d %B, %Y",
    "%d-%b-%Y", "%d/%m/%y", "%d-%m-%y", "%m/%d/%Y",
)


# ---------------------------------------------------------
# Shape-preserving randomisation
# ---------------------------------------------------------

def _random_digit(char):

    if char.isascii():
        return _rng.choice(string.digits)

    # Other numeral systems (Devanagari, Gujarati, ...) stay in their block.
    zero = ord(char) - unicodedata.digit(char)

    return chr(zero + _rng.randrange(10))


def shape(value, keep=0):
    """Replace each ASCII letter and each digit with a random one."""

    letters = [char for char in value[keep:] if char.isascii() and char.isalpha()]

    hexlike = bool(letters) and all(char in "abcdefABCDEF" for char in letters)

    lower = "abcdef" if hexlike else string.ascii_lowercase
    upper = "ABCDEF" if hexlike else string.ascii_uppercase

    out = []

    for index, char in enumerate(value):

        if index < keep:
            out.append(char)

        elif char.isdigit():
            out.append(_random_digit(char))

        elif char.isascii() and char.islower():
            out.append(_rng.choice(lower))

        elif char.isascii() and char.isupper():
            out.append(_rng.choice(upper))

        else:
            out.append(char)

    return "".join(out)


def _match_case(word, like):

    if like.isupper():
        return word.upper()

    if like.islower():
        return word.lower()

    return word


# ---------------------------------------------------------
# Per-type generators
# ---------------------------------------------------------

def _is_devanagari(text):
    return any("ऀ" <= char <= "ॿ" for char in text)


def person_name(value, session):

    out = []
    position = 0

    for token in re.split(r"(\s+)", value):

        core = token.strip(".,")

        if not core or token.isspace():
            out.append(token)
            continue

        if core.lower() in HONORIFICS:
            out.append(token)
            continue

        if len(core) == 1:
            fake = _match_case(_rng.choice(string.ascii_uppercase), core)

        else:

            if _is_devanagari(core):
                pool = (
                    FIRST_NAMES_DEVANAGARI
                    if position == 0
                    else LAST_NAMES_DEVANAGARI
                )
            else:
                pool = FIRST_NAMES if position == 0 else LAST_NAMES

            fake = _match_case(_rng.choice(pool), core)

        position += 1

        out.append(token.replace(core, fake, 1))

    return "".join(out)


def _name_parts(session):
    """Original name part -> surrogate name part, longest first."""

    parts = {}

    for entity_type, original, surrogate in session.pairs():

        if entity_type == "PERSON_NAME" and " " not in original.strip():
            parts.setdefault(original.strip(".,"), surrogate.strip(".,"))

    return sorted(parts.items(), key=lambda item: -len(item[0]))


def handle(value, session):
    """
    A fake login-style identifier: email local part, username, UPI name.

    If it contains a name that is already masked in this session, the fake
    uses the matching fake name, so "rahul.sharma" follows "Rahul Sharma".
    """

    out = value
    linked = False

    for original, fake in _name_parts(session):

        if not original.isascii() or len(original) < 3:
            continue

        pattern = re.compile(re.escape(original), re.IGNORECASE)

        if pattern.search(out):
            out = pattern.sub(lambda m: _match_case(fake.lower(), m.group(0)), out)
            linked = True

    if not linked:

        runs = [0]

        def replace_run(match):

            run = match.group(0)

            if len(run) <= 2:
                return shape(run)

            pool = FIRST_NAMES if runs[0] == 0 else LAST_NAMES
            runs[0] += 1

            return _match_case(_rng.choice(pool).lower(), run)

        out = re.sub(r"[A-Za-z]+", replace_run, out)

    return re.sub(r"\d", lambda m: _random_digit(m.group(0)), out)


def _domain(value):

    labels = value.split(".")
    keep = 1

    if len(labels) > 2 and labels[-2].lower() in SECOND_LEVEL_LABELS:
        keep = 2

    fake = [
        _match_case(_rng.choice(DOMAIN_WORDS), label)
        for label in labels[:-keep]
    ]

    return ".".join(fake + labels[-keep:])


def email(value, session):

    local, at, domain = value.rpartition("@")

    if not at or not local or "." not in domain:
        return shape(value)

    if domain.lower() not in PUBLIC_MAIL_DOMAINS:
        # Stored as its own entry, so every address at one organisation
        # gets the same fake domain and a bare mention of it is masked too.
        domain = session.assign(
            "EMAIL_DOMAIN",
            domain,
            lambda: _domain(domain),
        )

    return handle(local, session) + "@" + domain


def upi_id(value, session):

    local, at, provider = value.rpartition("@")

    if not at or not local:
        return shape(value)

    return handle(local, session) + "@" + provider


def phone(value, session):

    prefix = re.match(
        r"\s*(?:\+91|\+1|\+44|\+\d{2}|0091|91(?=[\s-]?\d{10}\s*$)|0)?[\s-]*",
        value,
    ).end()

    rest = list(value[prefix:])

    first = True

    for index, char in enumerate(rest):

        if not char.isdigit():
            continue

        if first and char.isascii() and char in "6789":
            rest[index] = _rng.choice("6789")
        else:
            rest[index] = _random_digit(char)

        first = False

    return value[:prefix] + "".join(rest)


def ip_address(value, session):

    match = re.fullmatch(r"\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*", value)

    if match is None:
        return shape(value)

    a, b = int(match.group(1)), int(match.group(2))

    def octet():
        return _rng.randrange(1, 255)

    if a == 10:
        parts = [10, octet(), octet(), octet()]

    elif a == 192 and b == 168:
        parts = [192, 168, octet(), octet()]

    elif a == 172 and 16 <= b <= 31:
        parts = [172, b, octet(), octet()]

    else:
        first = _rng.choice(
            [n for n in range(20, 200) if n not in (100, 127, 169, 172, 192)]
        )
        parts = [first, octet(), octet(), octet()]

    return ".".join(str(part) for part in parts)


def date(value, session):

    text = value.strip()

    for fmt in DATE_FORMATS:

        try:
            parsed = datetime.datetime.strptime(text, fmt)

        except ValueError:
            continue

        shifted = parsed + datetime.timedelta(days=session.date_offset)

        return value.replace(text, shifted.strftime(fmt), 1)

    return None


def aadhaar(value, session):

    out = list(shape(value))

    for index, char in enumerate(out):

        if char.isdigit():

            if char.isascii() and char in "01":
                out[index] = _rng.choice("23456789")

            break

    return "".join(out)


def secret(value, session):

    for prefix in KEY_PREFIXES:

        if value.startswith(prefix):
            return shape(value, keep=len(prefix))

    # A connection string keeps its scheme, so it still reads as one.
    scheme = re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", value)

    if scheme:
        return shape(value, keep=scheme.end())

    return shape(value)


def ifsc(value, session):

    # The fifth character of an IFSC is always zero.
    if len(value) == 11 and value[4] == "0":
        return shape(value[:4]) + "0" + shape(value[5:])

    return shape(value)


def org_name(value, session):

    out = []
    replaced = False

    for token in re.split(r"(\s+)", value):

        core = token.strip(".,&()")

        if (
            not core
            or token.isspace()
            or core.lower() in ORG_SUFFIXES
            or not any(char.isalpha() for char in core)
        ):
            out.append(token)
            continue

        fake = _rng.choice(ORG_WORDS)

        out.append(token.replace(core, _match_case(fake, core), 1))
        replaced = True

    return "".join(out) if replaced else shape(value)


def private_key(value, session):

    return "\n".join(
        line if line.lstrip().startswith("-----") else shape(line)
        for line in value.split("\n")
    )


GENERATORS = {
    "PERSON_NAME": person_name,
    "EMAIL": email,
    "USERNAME": handle,
    "UPI_ID": upi_id,
    "PHONE": phone,
    "IP_ADDRESS": ip_address,
    "DATE_OF_BIRTH": date,
    "AADHAAR": aadhaar,
    "CREDIT_CARD": lambda value, session: shape(value, keep=1),
    "VEHICLE_REG": lambda value, session: shape(value, keep=2),
    "PAN_CARD": lambda value, session: shape(value),
    "PASSPORT": lambda value, session: shape(value),
    "DRIVER_LICENSE": lambda value, session: shape(value),
    "SSN": lambda value, session: shape(value),
    "PASSWORD": lambda value, session: shape(value),
    "API_KEY": secret,
    "AWS_TEST_KEY": secret,
    "GITHUB_TEST_TOKEN": secret,
    "PRIVATE_KEY": private_key,
    "SECRET": secret,
    "BANK_ACCOUNT": lambda value, session: shape(value),
    "IFSC": ifsc,
    "GSTIN": lambda value, session: shape(value),
    "VOTER_ID": lambda value, session: shape(value),
    "ORG_NAME": org_name,
}


def generate(entity_type, value, session):
    """Return a surrogate for value, or None if the type has no generator."""

    generator = GENERATORS.get(entity_type)

    if generator is None:
        return None

    return generator(value, session)
