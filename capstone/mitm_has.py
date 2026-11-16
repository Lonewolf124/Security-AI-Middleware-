"""
mitmproxy entry point for the local Hide-and-Seek proxy.

claude.ai conversations go through hide_seek (reversible masking with a
per-session vault). Everything else keeps the behaviour of mitm_dlp.py.
"""

import re

import mitm_dlp

from hide_seek import trace
from hide_seek.providers import claude_web
from hide_seek.proxy import HideSeekAddon


has = HideSeekAddon()

# Requests worth tracing: anything that is not a plain page or asset load.
TRACED_PATH = re.compile(r"/claudeai-rpc/|/chat_conversations|/completion|/v1/messages")

SKIPPED_PATH = re.compile(r"/ReportViewing$")


def _traced(flow):

    request = flow.request

    if not trace.watched(request.pretty_host):
        return False

    if SKIPPED_PATH.search(request.path):
        return False

    return request.method != "GET" or bool(TRACED_PATH.search(request.path))


def _label(flow):

    return {
        "host": flow.request.pretty_host,
        "path": flow.request.path.split("?")[0],
    }


def request(flow):

    handled = has.request(flow)

    if _traced(flow):

        request = flow.request

        trace.write(
            "request",
            method=request.method,
            **_label(flow),
            content_type=request.headers.get("content-type", ""),
            content_encoding=request.headers.get("content-encoding", ""),
            connect_encoding=request.headers.get("connect-content-encoding", ""),
            handled=handled,
            blocked=flow.response is not None,
            body=trace.body_shape(
                request.get_content(strict=False),
                request.headers.get("content-type", ""),
                request.headers.get("connect-content-encoding", ""),
            ),
        )

    if handled:
        return

    if flow.request.pretty_host.lower() != claude_web.HOST:
        mitm_dlp.request(flow)


def responseheaders(flow):

    has.responseheaders(flow)

    if not _traced(flow):
        return

    response = flow.response
    content_type = response.headers.get("content-type", "")
    connect_encoding = response.headers.get("connect-content-encoding", "")

    streamed = "connect+proto" in content_type.lower()

    trace.write(
        "response",
        **_label(flow),
        status=response.status_code,
        content_type=content_type,
        content_encoding=response.headers.get("content-encoding", ""),
        connect_encoding=connect_encoding,
        streamed=streamed,
        restore_attached=callable(response.stream),
    )

    if streamed and not response.stream:
        response.stream = trace.StreamTap(_label(flow), connect_encoding)


def response(flow):

    has.response(flow)

    if not _traced(flow) or flow.response.stream:
        return

    content_type = flow.response.headers.get("content-type", "")

    trace.write(
        "response-body",
        **_label(flow),
        size=len(flow.response.raw_content or b""),
        body=trace.body_shape(
            flow.response.get_content(strict=False),
            content_type,
        ),
    )
