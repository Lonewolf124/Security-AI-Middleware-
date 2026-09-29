# import json
# import hashlib
# from mitmproxy import http


# TARGET_HOST = "chatgpt.com"
# TARGET_PATH = "/backend-anon/f/conversation"


# def describe(value, path="$"):
#     """Print structure only — never print actual values."""

#     if isinstance(value, dict):
#         print(f"[JSON] {path} -> object ({len(value)} keys)")
#         for key, child in value.items():
#             describe(child, f"{path}.{key}")

#     elif isinstance(value, list):
#         print(f"[JSON] {path} -> array ({len(value)} items)")

#         # Describe only the first item so large arrays don't flood the log.
#         if value:
#             describe(value[0], f"{path}[0]")

#     elif isinstance(value, str):
#         print(f"[JSON] {path} -> string (length={len(value)})")

#     elif isinstance(value, bool):
#         print(f"[JSON] {path} -> boolean")

#     elif isinstance(value, (int, float)):
#         print(f"[JSON] {path} -> number")

#     elif value is None:
#         print(f"[JSON] {path} -> null")

#     else:
#         print(f"[JSON] {path} -> {type(value).__name__}")


# def request(flow: http.HTTPFlow):
#     host = flow.request.pretty_host.lower()
#     path = flow.request.path.split("?")[0]

#     if (
#         host == "chatgpt.com"
#         and path == "/unauth-mweb/conversation/updates"
#     ):
#         print("\n[DLP] ChatGPT prompt request detected")

#         form = flow.request.urlencoded_form

#         prompt = form.get("prompt")

#         if prompt is None:
#             print("[DLP] Prompt field not found")
#             return

#         print(
#             f"[DLP] Prompt detected "
#             f"(length={len(prompt)})"
#         )

#         modified_prompt, findings = inspect(prompt)

#         if not findings:
#             print("[DLP] ChatGPT Decision: ALLOW")
#             return

#         print(
#             f"[DLP] ChatGPT Findings: {findings}"
#         )

#         print("[DLP] ChatGPT Decision: REDACT")

#         form["prompt"] = modified_prompt

#         flow.request.urlencoded_form = form

#         return

from mitmproxy import http

from dlp_engine.engine import inspect


def request(flow: http.HTTPFlow):

    host = flow.request.pretty_host.lower()
    path = flow.request.path.split("?")[0]

    if (
        host == "chatgpt.com"
        and path == "/unauth-mweb/conversation/updates"
    ):
        print("\n[DLP] ChatGPT prompt request detected")

        form = flow.request.urlencoded_form

        prompt = form.get("prompt")

        if prompt is None:
            print("[DLP] Prompt field not found")
            return

        print(
            f"[DLP] Prompt detected "
            f"(length={len(prompt)})"
        )

        modified_prompt, findings = inspect(prompt)

        if not findings:
            print("[DLP] ChatGPT Decision: ALLOW")
            return

        print(
            f"[DLP] ChatGPT Findings: {findings}"
        )

        print("[DLP] ChatGPT Decision: REDACT")

        form["prompt"] = modified_prompt

        flow.request.urlencoded_form = form

        return