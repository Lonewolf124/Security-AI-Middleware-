import json

from mitmproxy import http


def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()

    if "google" not in host and "gemini" not in host:
        return

    path = flow.request.path.split("?")[0]

    print(
        f"\n[GEMINI] {flow.request.method} "
        f"https://{host}{path}"
    )

    content_type = flow.request.headers.get(
        "content-type",
        ""
    ).lower()

    if "application/x-www-form-urlencoded" in content_type:

        print(
            f"[GEMINI] Form fields: "
            f"{list(flow.request.urlencoded_form.keys())}"
        )

        for key in flow.request.urlencoded_form.keys():

            value = flow.request.urlencoded_form.get(key)

            if key == "f.req":
                print(f"[GEMINI] f.req length={len(value)}")

                try:
                    parsed = json.loads(value)

                    def describe(obj, path="f.req", depth=0):
                        if depth > 8:
                            return

                        if isinstance(obj, list):
                            print(
                                f"[GEMINI] {path}: LIST "
                                f"length={len(obj)}"
                            )

                            for i, item in enumerate(obj[:10]):
                                describe(
                                    item,
                                    f"{path}[{i}]",
                                    depth + 1
                                )

                        elif isinstance(obj, dict):
                            print(
                                f"[GEMINI] {path}: DICT "
                                f"keys={list(obj.keys())}"
                            )

                        elif isinstance(obj, str):
                            print(
                                f"[GEMINI] {path}: STRING "
                                f"length={len(obj)}"
                            )

                            # Diagnostic: determine whether the long string
                            # has another encoding layer, without printing contents.
                            if len(obj) > 500:
                                stripped = obj.lstrip()

                                print(
                                    f"[GEMINI] {path}: "
                                    f"starts_with={stripped[:1]!r}, "
                                    f"ends_with={stripped[-1:]!r}"
                                )

                                has_newlines = "\n" in obj
                                has_backslash = "\\" in obj
                                has_quotes = '"' in obj

                                has_digits = any(c.isdigit() for c in obj)
                                has_upper = any(c.isupper() for c in obj)
                                has_lower = any(c.islower() for c in obj)
                                has_punctuation = any(not c.isalnum() for c in obj)

                                print(
                                    f"[GEMINI] {path}: "
                                    f"has_digits={has_digits}, "
                                    f"has_upper={has_upper}, "
                                    f"has_lower={has_lower}, "
                                    f"has_punctuation={has_punctuation}"
                                )

                                print(
                                    f"[GEMINI] {path}: "
                                    f"has_spaces={' ' in obj}, "
                                    f"has_newlines={has_newlines}, "
                                    f"has_backslash={has_backslash}, "
                                    f"has_quotes={has_quotes}"
                                )

                                try:
                                    inner = json.loads(obj)

                                    print(
                                        f"[GEMINI] {path}: "
                                        f"nested JSON type="
                                        f"{type(inner).__name__}"
                                    )

                                    if isinstance(inner, list):
                                        print(
                                            f"[GEMINI] {path}: "
                                            f"nested LIST length={len(inner)}"
                                        )

                                    elif isinstance(inner, dict):
                                        print(
                                            f"[GEMINI] {path}: "
                                            f"nested DICT keys="
                                            f"{list(inner.keys())}"
                                        )

                                except Exception as e:
                                    print(
                                        f"[GEMINI] {path}: "
                                        f"not direct JSON "
                                        f"({type(e).__name__})"
                                    )

                        else:
                            print(
                                f"[GEMINI] {path}: "
                                f"{type(obj).__name__}"
                            )

                    describe(parsed)

                    if (
                        isinstance(parsed, list)
                        and len(parsed) > 1
                        and isinstance(parsed[1], str)
                    ):
                        print("[GEMINI] Parsing nested f.req[1]")

                        try:
                            nested = json.loads(parsed[1])

                            describe(
                                nested,
                                path="f.req[1].nested",
                                depth=0
                            )

                        except Exception as e:
                            print(
                                "[GEMINI] nested f.req[1] "
                                f"parse failed: {type(e).__name__}"
                            )

                except Exception as e:
                    print(
                        f"[GEMINI] f.req parse failed: "
                        f"{type(e).__name__}"
                    )
    
            elif key == "at":
                print(
                    f"[GEMINI] at present, length={len(value)}"
                )

        return


    if "application/json" not in content_type:

        print(
            f"[GEMINI] Content-Type: "
            f"{content_type}"
        )

        return

    body = flow.request.get_text()

    if not body:
        return

    try:
        data = json.loads(body)

    except json.JSONDecodeError:
        print("[GEMINI] JSON parse failed")
        return

    print(
        f"[GEMINI] JSON root type: "
        f"{type(data).__name__}"
    )

    if not isinstance(data, dict):
        return

    print(
        f"[GEMINI] JSON keys: "
        f"{list(data.keys())}"
    )

    # Inspect common message/content structures
    # without printing actual message contents.

    for key in data:
        value = data[key]

        if isinstance(value, list):
            print(
                f"[GEMINI] {key}: "
                f"list ({len(value)} items)"
            )

            for i, item in enumerate(value[:3]):

                if isinstance(item, dict):
                    print(
                        f"[GEMINI] {key}[{i}] keys: "
                        f"{list(item.keys())}"
                    )

                else:
                    print(
                        f"[GEMINI] {key}[{i}] type: "
                        f"{type(item).__name__}"
                    )

        elif isinstance(value, dict):
            print(
                f"[GEMINI] {key}: "
                f"object ({len(value)} keys)"
            )

        elif isinstance(value, str):
            print(
                f"[GEMINI] {key}: "
                f"string (length={len(value)})"
            )