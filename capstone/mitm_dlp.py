import json

from mitmproxy import http

from dlp_engine.engine import inspect

from dlp_engine.providers.claude import (
    is_claude_completion,
    inspect_completion,
)


def request(flow: http.HTTPFlow):

    host = flow.request.pretty_host.lower()
    path = flow.request.path.split("?")[0]

# =========================================================
# ChatGPT
# =========================================================

    if (
        host == "chatgpt.com"
        and path == "/backend-api/f/conversation"
    ):

        print("\n[DLP] ChatGPT conversation request detected")

        content_type = (
            flow.request.headers.get(
                "content-type",
                ""
            ).lower()
        )

        if "application/json" not in content_type:

            print(
                "[DLP] ChatGPT: "
                "not JSON - skipping"
            )

            return

        body = flow.request.get_text()

        if not body:

            print(
                "[DLP] ChatGPT: "
                "empty body"
            )

            return

        try:

            data = json.loads(body)

        except json.JSONDecodeError:

            print(
                "[DLP] ChatGPT: "
                "invalid JSON"
            )

            return

        # ---------------------------------------------------------
        # Extract user prompt
        # ---------------------------------------------------------

        try:

            messages = data.get("messages", [])

            if not messages:

                print(
                    "[DLP] ChatGPT: "
                    "no messages found"
                )

                return

            prompt = (
                messages[0]
                .get("content", {})
                .get("parts", [None])[0]
            )

        except (AttributeError, IndexError, TypeError):

            print(
                "[DLP] ChatGPT: "
                "unable to extract prompt"
            )

            return

        if not isinstance(prompt, str):

            print(
                "[DLP] ChatGPT: "
                "prompt is not a string"
            )

            return

        print(
            f"[DLP] ChatGPT prompt detected "
            f"(length={len(prompt)})"
        )

        print(
            f"[DLP] Prompt preview: "
            f"{prompt[:200]}"
        )

        # ---------------------------------------------------------
        # Central DLP engine
        # ---------------------------------------------------------

        modified_prompt, findings = inspect(prompt)

        # ---------------------------------------------------------
        # ALLOW
        # ---------------------------------------------------------

        if not findings:

            print(
                "[DLP] ChatGPT Decision: ALLOW"
            )

            return

        # ---------------------------------------------------------
        # Findings
        # ---------------------------------------------------------

        print(
            f"[DLP] ChatGPT Findings: "
            f"{findings}"
        )

        finding_types = {
            finding["type"]
            for finding in findings
        }

        # ---------------------------------------------------------
        # BLOCK
        # ---------------------------------------------------------

        if "PRIVATE_KEY" in finding_types:

            print(
                "[DLP] ChatGPT Decision: BLOCK"
            )

            flow.response = http.Response.make(
                403,
                b"Request blocked by DLP policy.",
                {
                    "Content-Type": "text/plain",
                },
            )

            return

        # ---------------------------------------------------------
        # REDACT
        # ---------------------------------------------------------

        print(
            "[DLP] ChatGPT Decision: REDACT"
        )

        data["messages"][0]["content"]["parts"][0] = (
            modified_prompt
        )

        flow.request.set_text(
            json.dumps(data)
        )

        print(
            f"[DLP] Sanitized prompt: "
            f"{modified_prompt}"
        )

        return


    # =========================================================
    # Claude
    # =========================================================

    if is_claude_completion(flow):

        provider = "Claude"

        print(
            f"[DLP] {provider} completion: "
            f"{flow.request.pretty_host}"
            f"{flow.request.path.split('?')[0]}"
        )

        process_request(
            flow,
            provider,
            inspect_completion,
        )

        return


def process_request(flow, provider, inspector):

    content_type = flow.request.headers.get(
        "content-type",
        ""
    ).lower()

    if "application/json" not in content_type:

        print(
            f"[DLP] {provider}: "
            "not JSON - skipping"
        )

        return

    body = flow.request.get_text()

    if not body:
        return

    try:

        data = json.loads(body)

    except json.JSONDecodeError:

        print(
            f"[DLP] {provider}: "
            "invalid JSON - skipping"
        )

        return

    modified_data, findings = inspector(data)

    if not findings:

        print(
            f"[DLP] {provider} Decision: ALLOW"
        )

        return

    finding_types = {
        finding["type"]
        for finding in findings
    }

    print(
        f"[DLP] {provider} Findings: "
        f"{findings}"
    )

    # ---------------------------------------------------------
    # BLOCK
    # ---------------------------------------------------------

    if "PRIVATE_KEY" in finding_types:

        print(
            f"[DLP] {provider} Decision: BLOCK"
        )

        flow.response = http.Response.make(
            403,
            b"Request blocked by DLP policy.",
            {
                "Content-Type": "text/plain",
            },
        )

        return

    # ---------------------------------------------------------
    # REDACT
    # ---------------------------------------------------------

    print(
        f"[DLP] {provider} Decision: REDACT"
    )

    flow.request.set_text(
        json.dumps(modified_data)
    )