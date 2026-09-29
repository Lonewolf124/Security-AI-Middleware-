from ..engine import inspect


CHATGPT_HOSTS = {
    "chatgpt.com",
    "www.chatgpt.com",
}


CHATGPT_CONVERSATION_PATH = "/backend-anon/f/conversation"


def is_chatgpt_conversation(flow):
    host = flow.request.pretty_host.lower()
    path = flow.request.path.split("?")[0]

    return (
        host in CHATGPT_HOSTS
        and path == CHATGPT_CONVERSATION_PATH
    )


def inspect_conversation(data):
    """
    Inspect only employee message content.

    Returns:
        modified_data,
        findings
    """

    findings = []

    messages = data.get("messages")

    if not isinstance(messages, list):
        return data, findings

    for message in messages:

        if not isinstance(message, dict):
            continue

        content = message.get("content")

        if not isinstance(content, dict):
            continue

        parts = content.get("parts")

        if not isinstance(parts, list):
            continue

        for index, part in enumerate(parts):

            if not isinstance(part, str):
                continue

            modified, part_findings = inspect(part)

            parts[index] = modified
            findings.extend(part_findings)

    return data, findings