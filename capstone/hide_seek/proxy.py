import json
import traceback
from collections import Counter

from mitmproxy import http

from .hide import Hider
from .providers import claude_rpc, claude_web
from .seek import SSERestorer, restore, restore_json
from .vault import Vault


SESSION_KEY = "has_session"
STREAMED_KEY = "has_streamed"
TIMELINE_KEY = "has_timeline"

# A claude.ai conversation id is unique on its own, so sessions are keyed
# on it alone. Not every request that belongs to a conversation carries
# the organisation id.
ORG = ""

MAX_TRACKED_CONVERSATIONS = 200


def _block(flow, status, reason):

    flow.response = http.Response.make(
        status,
        reason.encode("utf-8"),
        {"Content-Type": "text/plain"},
    )


def _content_type(message):
    return message.headers.get("content-type", "").lower()


class HideSeekAddon:
    """
    mitmproxy hooks for Hide-and-Seek on the claude.ai web app.

    request         : Hide. Swap private values for surrogates, record the pairs.
    responseheaders : Seek, streaming. Restore inside the reply stream.
    response        : Seek, buffered. Restore in JSON replies such as the
                      conversation list and history.

    The app's current interface is RPC with protobuf bodies (claude_rpc).
    The earlier JSON interface (claude_web) is still handled.
    """

    def __init__(self, vault=None, hider=None):

        self.vault = vault or Vault()
        self.hider = hider or Hider.default()

        # conversation id -> {block id: StreamRestorer}, see TimelineRestorer.
        self._timeline_blocks = {}

        purged = self.vault.purge_expired()
        stats = self.vault.stats()

        print(
            f"[HaS] Vault ready: {stats['sessions']} sessions, "
            f"{stats['mappings']} mappings, {purged} expired sessions purged"
        )

    # ---------------------------------------------------------
    # Hide
    # ---------------------------------------------------------

    def request(self, flow):
        """Return True if this flow belongs to a claude.ai conversation."""

        rpc_method = claude_rpc.method(
            flow.request.pretty_host,
            flow.request.path,
        )

        if rpc_method is not None:
            self._rpc_request(flow, rpc_method)
            return True

        target = claude_web.parse(
            flow.request.pretty_host,
            flow.request.path,
        )

        if target is None:
            return False

        _org_id, conversation_id, action = target

        flow.metadata[SESSION_KEY] = conversation_id

        if flow.request.method not in ("POST", "PUT", "PATCH"):
            return True

        is_completion = action in claude_web.COMPLETION_ACTIONS

        try:
            self._hide(flow, conversation_id, is_completion)

        except Exception:
            self._inspection_failed(flow)

        return True

    def _inspection_failed(self, flow):

        traceback.print_exc()

        # Never forward a turn that could not be inspected.
        _block(flow, 502, "Request blocked: DLP inspection failed.")

        print("[HaS] Decision: BLOCK (inspection error)")

    def _rpc_request(self, flow, rpc_method):

        body = flow.request.get_content(strict=False) or b""

        if rpc_method == "StreamTimeline":

            conversation_id = claude_rpc.timeline_conversation(body)

            if conversation_id is not None:
                flow.metadata[SESSION_KEY] = conversation_id
                flow.metadata[TIMELINE_KEY] = True

            return

        if rpc_method != "PerformAction" or not body:
            return

        try:
            self._hide_action(flow, body)

        except Exception:
            self._inspection_failed(flow)

    def _hide_action(self, flow, body):

        conversation_id = claude_rpc.action_conversation(body)

        if conversation_id is None:
            # Without a conversation there is nowhere to record the pairs.
            raise ValueError("PerformAction carries no conversation id")

        session = self.vault.session(claude_web.PROVIDER, ORG, conversation_id)

        new_body, findings = claude_rpc.hide_action(body, self.hider, session)

        if self._decide(flow, findings, session):
            flow.request.set_content(new_body)

    def _hide(self, flow, conversation_id, is_completion):

        body = flow.request.get_text()

        if not body:
            return

        if "application/json" not in _content_type(flow.request):

            if is_completion:
                _block(flow, 415, "Request blocked: body is not JSON.")
                print("[HaS] Decision: BLOCK (completion body not JSON)")

            return

        try:
            data = json.loads(body)

        except json.JSONDecodeError:

            if is_completion:
                _block(flow, 400, "Request blocked: body is not valid JSON.")
                print("[HaS] Decision: BLOCK (completion body unparseable)")

            return

        session = self.vault.session(claude_web.PROVIDER, ORG, conversation_id)

        findings = claude_web.hide_body(data, self.hider, session)

        if is_completion:
            # Ask for an uncompressed reply so the SSE stream can be
            # rewritten chunk by chunk on the way back.
            flow.request.headers["accept-encoding"] = "identity"

        if self._decide(flow, findings, session):
            flow.request.set_text(json.dumps(data))

    def _decide(self, flow, findings, session):
        """Log the decision; return True if the masked body should be sent."""

        if not findings:
            print("[HaS] Decision: ALLOW")
            return False

        counts = Counter(finding["type"] for finding in findings)

        print(f"[HaS] Findings: {dict(counts)}")

        if any(finding["action"] == "BLOCK" for finding in findings):

            _block(flow, 403, "Request blocked by DLP policy.")
            print("[HaS] Decision: BLOCK")

            return False

        print(
            f"[HaS] Decision: MASK "
            f"(session now holds {len(session)} values)"
        )

        return True

    # ---------------------------------------------------------
    # Seek
    # ---------------------------------------------------------

    def _find(self, conversation_id):
        """The conversation's session, or None if nothing is masked in it."""

        session = self.vault.find_session(
            claude_web.PROVIDER,
            ORG,
            conversation_id,
        )

        return session if session is not None and len(session) else None

    def _session(self, flow):

        conversation_id = flow.metadata.get(SESSION_KEY)

        if conversation_id is None or flow.response is None:
            return None

        if flow.response.status_code != 200:
            return None

        return self._find(conversation_id)

    def _attach_timeline(self, flow):

        conversation_id = flow.metadata[SESSION_KEY]

        if len(self._timeline_blocks) > MAX_TRACKED_CONVERSATIONS:
            self._timeline_blocks.clear()

        # The stream is opened before the first message of a chat is sent,
        # so the session is looked up as frames arrive, not once here.
        flow.response.stream = claude_rpc.TimelineRestorer(
            lambda: self._find(conversation_id),
            self._timeline_blocks.setdefault(conversation_id, {}),
            flow.response.headers.get("connect-content-encoding", ""),
        )

        flow.metadata[STREAMED_KEY] = True

    def responseheaders(self, flow):

        if flow.metadata.get(TIMELINE_KEY):

            if (
                flow.response.status_code == 200
                and "connect+proto" in _content_type(flow.response)
            ):
                self._attach_timeline(flow)

            return

        if "text/event-stream" not in _content_type(flow.response):
            return

        encoding = flow.response.headers.get("content-encoding", "identity")

        if encoding.lower() != "identity":
            # Compressed stream: handled whole in response() instead.
            return

        session = self._session(flow)

        if session is None:
            return

        flow.response.stream = SSERestorer(session)
        flow.metadata[STREAMED_KEY] = True

    def response(self, flow):

        if flow.metadata.get(STREAMED_KEY):
            return

        session = self._session(flow)

        if session is None:
            self._restore_conversation_list(flow)
            return

        content_type = _content_type(flow.response)

        try:

            if "text/event-stream" in content_type:

                restorer = SSERestorer(session)

                flow.response.content = (
                    restorer(flow.response.content or b"") + restorer(b"")
                )

            elif "application/json" in content_type:

                flow.response.set_text(
                    json.dumps(
                        restore_json(
                            json.loads(flow.response.get_text()),
                            session,
                        )
                    )
                )

        except Exception:
            # A failed restore leaves surrogates on screen; it must not
            # break the reply.
            traceback.print_exc()

    def _restore_conversation_list(self, flow):
        """Restore chat titles in JSON listings of several conversations."""

        if (
            flow.response is None
            or flow.response.status_code != 200
            or flow.request.pretty_host.lower() != claude_web.HOST
            or "chat_conversations" not in flow.request.path
            or "application/json" not in _content_type(flow.response)
        ):
            return

        changed = [False]

        def walk(value):

            if isinstance(value, list):

                for item in value:
                    walk(item)

            elif isinstance(value, dict):

                uuid, name = value.get("uuid"), value.get("name")

                if isinstance(uuid, str) and isinstance(name, str) and name:

                    session = self._find(uuid.lower())

                    if session is not None:

                        restored = restore(name, session)[0]

                        if restored != name:
                            value["name"] = restored
                            changed[0] = True

                for item in value.values():
                    walk(item)

        try:

            data = json.loads(flow.response.get_text())

            walk(data)

            if changed[0]:
                flow.response.set_text(json.dumps(data))

        except Exception:
            traceback.print_exc()
