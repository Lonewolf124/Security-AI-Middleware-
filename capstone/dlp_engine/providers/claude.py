from ..engine import inspect


CLAUDE_HOST = "claude.ai"


def is_claude_completion(flow):
    host = flow.request.pretty_host.lower()
    path = flow.request.path.split("?")[0]

    return (
        host == CLAUDE_HOST
        and path.startswith(
            "/api/organizations/"
        )
        and "/chat_conversations/" in path
        and path.endswith("/completion")
    )


def inspect_completion(data):
    findings = []

    prompt = data.get("prompt")

    if not isinstance(prompt, str):
        return data, findings

    modified_prompt, prompt_findings = inspect(prompt)

    data["prompt"] = modified_prompt
    findings.extend(prompt_findings)

    return data, findings