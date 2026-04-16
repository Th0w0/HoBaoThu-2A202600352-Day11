import json
import time
from datetime import datetime
from pathlib import Path

from google.adk.plugins import base_plugin


class AuditLogPlugin(base_plugin.BasePlugin):
    """
    Records every interaction:
    - input
    - output
    - latency
    - simple blocked/redacted inference
    """

    def __init__(self, filepath="security_audit.json"):
        super().__init__(name="audit_log")
        self.filepath = Path(filepath)
        self.logs = []
        self._inflight = {}

    def _extract_text(self, content) -> str:
        text = ""
        if content and getattr(content, "parts", None):
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    def _request_id(self, invocation_context, callback_context=None) -> str:
        if invocation_context and getattr(invocation_context, "invocation_id", None):
            return str(invocation_context.invocation_id)
        if callback_context and getattr(callback_context, "invocation_id", None):
            return str(callback_context.invocation_id)
        return f"req-{time.time_ns()}"

    def _user_id(self, invocation_context) -> str:
        if invocation_context:
            if getattr(invocation_context, "user_id", None):
                return str(invocation_context.user_id)
            if getattr(invocation_context, "invocation_id", None):
                return f"session-{invocation_context.invocation_id}"
        return "anonymous"

    async def on_user_message_callback(self, *, invocation_context, user_message):
        request_id = self._request_id(invocation_context)
        self._inflight[request_id] = {
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": self._user_id(invocation_context),
            "input": self._extract_text(user_message),
            "output": None,
            "latency_ms": None,
            "blocked": False,
            "redacted": False,
        }
        self._inflight[request_id]["start_time"] = time.time()
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        request_id = self._request_id(None, callback_context)
        record = self._inflight.get(request_id)

        if record is None:
            record = {
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "user_id": "anonymous",
                "input": None,
                "start_time": time.time(),
                "blocked": False,
                "redacted": False,
            }

        output_text = self._extract_text(llm_response.content if hasattr(llm_response, "content") else llm_response)
        record["output"] = output_text
        record["latency_ms"] = round((time.time() - record["start_time"]) * 1000, 2)
        record.pop("start_time", None)

        lowered = (output_text or "").lower()
        if "rate limit exceeded" in lowered or "cannot provide sensitive information" in lowered:
            record["blocked"] = True
        if "[redacted]" in lowered:
            record["redacted"] = True

        self.logs.append(record)
        return llm_response

    def export_json(self, filepath=None):
        target = Path(filepath) if filepath else self.filepath
        with open(target, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)