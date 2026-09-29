import json

from mitmproxy import http


def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()

    if "claude" not in host:
        return

    path = flow.request.path.split("?")[0]

    print(f"\n[CLAUDE] {flow.request.method} https://{host}{path}")

    content_type = flow.request.headers.get(
        "content-type",
        ""
    ).lower()

    if "application/json" not in content_type:
        print(f"[CLAUDE] Content-Type: {content_type}")
        return

    body = flow.request.get_text()

    if not body:
        return

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print("[CLAUDE] JSON parse failed")
        return

    print(f"[CLAUDE] JSON root type: {type(data).__name__}")

    if not isinstance(data, dict):
        return

    print(f"[CLAUDE] JSON keys: {list(data.keys())}")

    # Inspect only the structure of the prompt.
    # Do not print the actual prompt contents.
    prompt = data.get("prompt")

    print(f"[CLAUDE] prompt type: {type(prompt).__name__}")

    if isinstance(prompt, dict):

        print(
            f"[CLAUDE] prompt keys: "
            f"{list(prompt.keys())}"
        )

    elif isinstance(prompt, list):

        print(
            f"[CLAUDE] prompt items: "
            f"{len(prompt)}"
        )

        for i, item in enumerate(prompt[:5]):

            if isinstance(item, dict):

                print(
                    f"[CLAUDE] prompt[{i}] keys: "
                    f"{list(item.keys())}"
                )

            else:

                print(
                    f"[CLAUDE] prompt[{i}] type: "
                    f"{type(item).__name__}"
                )

    elif isinstance(prompt, str):

        print(
            f"[CLAUDE] prompt is string, "
            f"length={len(prompt)}"
        )