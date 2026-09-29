import re


PATTERNS = [
    {
        "type": "AWS_TEST_KEY",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "replacement": "[AWS_KEY_REDACTED]",
    },
    {
        "type": "GITHUB_TEST_TOKEN",
        "pattern": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "replacement": "[GITHUB_TOKEN_REDACTED]",
    },
    {
        "type": "PRIVATE_KEY",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        "replacement": "[PRIVATE_KEY_REDACTED]",
    },
]


def detect_and_redact(text):

    if not isinstance(text, str):
        return text, []

    findings = []

    for rule in PATTERNS:

        pattern = rule["pattern"]

        if pattern.search(text):

            findings.append({
                "type": rule["type"],
                "action": "REDACT",
            })

            text = pattern.sub(
                rule["replacement"],
                text,
            )

    return text, findings