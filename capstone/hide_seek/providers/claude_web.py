import re


PROVIDER = "claude.ai"
HOST = "claude.ai"

# /api/organizations/<org>/chat_conversations/<conversation>[/<action>]
CONVERSATION_PATH = re.compile(
    r"^/api/organizations/([0-9a-f-]{36})"
    r"/chat_conversations/([0-9a-f-]{36})"
    r"(?:/([a-z_]+))?/?$",
    re.IGNORECASE,
)

# Requests that carry the user's turn to the model. These fail closed.
COMPLETION_ACTIONS = frozenset({"completion", "retry_completion"})

# Body fields that hold user-authored text, wherever they are nested:
# the prompt itself, the text sent for title generation, and the text
# extracted client-side from pasted or attached documents.
TEXT_KEYS = frozenset({"prompt", "message_content", "extracted_content"})


def parse(host, path):
    """Return (org_id, conversation_id, action) for a conversation URL."""

    if host.lower() != HOST:
        return None

    match = CONVERSATION_PATH.match(path.split("?")[0])

    if match is None:
        return None

    org_id, conversation_id, action = match.groups()

    return org_id.lower(), conversation_id.lower(), action


def hide_body(data, hider, session):
    """
    Mask every user-text field of a decoded request body, in place.

    Returns the findings from all fields.
    """

    findings = []

    def walk(value):

        if isinstance(value, dict):

            for key, item in value.items():

                if key in TEXT_KEYS and isinstance(item, str):

                    value[key], item_findings = hider.hide(item, session)
                    findings.extend(item_findings)

                else:
                    walk(item)

        elif isinstance(value, list):

            for item in value:
                walk(item)

    walk(data)

    return findings
