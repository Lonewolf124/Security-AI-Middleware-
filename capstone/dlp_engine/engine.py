import re

from .detectors import detect_and_redact
from onnx_quantized_all17.pii_model import PIIModel


# Load the ONNX model once when the engine starts.
pii_model = PIIModel()


# Regex-redacted placeholders such as:
# [AWS_KEY_REDACTED]
# [GITHUB_TOKEN_REDACTED]
# [PRIVATE_KEY_REDACTED]
#
# These regions must not be analyzed again by the ML model.
REDACTED_PLACEHOLDER = re.compile(
    r"\[[A-Z0-9_]+_REDACTED\]"
)


def inspect(value):
    """
    Recursively inspect JSON values.

    Pipeline:

        1. Regex detection + redaction
        2. Separate already-redacted regions
        3. Run ONNX PII model only on untouched text
        4. Reassemble the final text

    Returns:
        modified_value,
        findings
    """

    findings = []

    # ---------------------------------------------------------
    # Dictionary
    # ---------------------------------------------------------

    if isinstance(value, dict):

        result = {}

        for key, item in value.items():

            modified, item_findings = inspect(item)

            result[key] = modified
            findings.extend(item_findings)

        return result, findings

    # ---------------------------------------------------------
    # List
    # ---------------------------------------------------------

    if isinstance(value, list):

        result = []

        for item in value:

            modified, item_findings = inspect(item)

            result.append(modified)
            findings.extend(item_findings)

        return result, findings

    # ---------------------------------------------------------
    # String
    # ---------------------------------------------------------

    if isinstance(value, str):

        # =====================================================
        # STEP 1 — Regex detection + redaction
        # =====================================================

        modified, regex_findings = detect_and_redact(value)

        findings.extend(regex_findings)

        # =====================================================
        # STEP 2 — Separate regex-redacted regions
        # =====================================================

        parts = []
        last_end = 0

        for match in REDACTED_PLACEHOLDER.finditer(modified):

            # Untouched text before the redacted region
            if match.start() > last_end:

                parts.append({
                    "type": "text",
                    "value": modified[
                        last_end:match.start()
                    ]
                })

            # Already-redacted region
            parts.append({
                "type": "protected",
                "value": match.group(0)
            })

            last_end = match.end()

        # Remaining text after the final redacted region
        if last_end < len(modified):

            parts.append({
                "type": "text",
                "value": modified[last_end:]
            })

        # No regex redactions occurred
        if not parts:

            parts = [{
                "type": "text",
                "value": modified
            }]

        # =====================================================
        # STEP 3 — ONNX PII detection
        # =====================================================

        final_parts = []

        for part in parts:

            # Never send regex-redacted content
            # through the ML model.
            if part["type"] == "protected":

                final_parts.append(part["value"])

                continue

            segment = part["value"]

            if not segment:
                continue

            pii_redacted, pii_entities = pii_model.redact(
                segment
            )

            # Add ML findings
            for entity in pii_entities:

                findings.append({
                    "type": entity["type"],
                    "action": "REDACT"
                })

            final_parts.append(pii_redacted)

        # =====================================================
        # STEP 4 — Reassemble
        # =====================================================

        final_text = "".join(final_parts)

        return final_text, findings

    # ---------------------------------------------------------
    # Other data types
    # ---------------------------------------------------------

    return value, findings