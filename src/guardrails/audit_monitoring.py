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
    - whether a later plugin appears to have blocked/redacted
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

    async def on_user_message_callback(self, *, invocation_context, user_message):
        request_id = self._request_id(invocation_context)
        self._inflight[request_id] = {
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_id": getattr(invocation_context, "user_id", "anonymous") if invocation_context else "anonymous",
            "input": self._extract_text(user_message),
            "output": None,
            "latency_ms": None,
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
            }

        output_text = self._extract_text(llm_response.content if hasattr(llm_response, "content") else llm_response)
        record["output"] = output_text
        record["latency_ms"] = round((time.time() - record["start_time"]) * 1000, 2)
        record.pop("start_time", None)

        self.logs.append(record)
        return llm_response

    def export_json(self, filepath=None):
        target = Path(filepath) if filepath else self.filepath
        with open(target, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False)

class MonitoringAlert:
    """Computes simple pipeline metrics and prints alerts when thresholds are exceeded."""

    def __init__(self, plugins):
        self.plugins = plugins

    def _find_plugin(self, name: str):
        for plugin in self.plugins:
            if getattr(plugin, "name", "") == name:
                return plugin
        return None

    def check_metrics(self):
        input_guard = self._find_plugin("input_guardrail")
        output_guard = self._find_plugin("output_guardrail")
        rate_limiter = self._find_plugin("rate_limiter")

        input_total = getattr(input_guard, "total_count", 0) or 0
        input_blocked = getattr(input_guard, "blocked_count", 0) or 0
        output_total = getattr(output_guard, "total_count", 0) or 0
        output_blocked = getattr(output_guard, "blocked_count", 0) or 0
        output_redacted = getattr(output_guard, "redacted_count", 0) or 0
        rate_total = getattr(rate_limiter, "total_count", 0) or 0
        rate_blocked = getattr(rate_limiter, "blocked_count", 0) or 0

        block_rate = (input_blocked / input_total) if input_total else 0.0
        judge_fail_rate = (output_blocked / output_total) if output_total else 0.0
        rate_limit_hit_rate = (rate_blocked / rate_total) if rate_total else 0.0

        session_guard = self._find_plugin("session_anomaly_detector")
        session_total = getattr(session_guard, "total_count", 0) or 0
        session_flagged = getattr(session_guard, "flagged_count", 0) or 0
        session_blocked = getattr(session_guard, "blocked_count", 0) or 0

        print("\n" + "=" * 70)
        print("MONITORING METRICS")
        print("=" * 70)
        print(f"Input block rate:     {input_blocked}/{input_total} ({block_rate:.1%})")
        print(f"Output blocked:       {output_blocked}/{output_total} ({judge_fail_rate:.1%})")
        print(f"Output redacted:      {output_redacted}/{output_total}" if output_total else "Output redacted:      0/0")
        print(f"Rate limit hits:      {rate_blocked}/{rate_total} ({rate_limit_hit_rate:.1%})")
        print(
            f"Session anomalies:     {session_flagged}/{session_total}"
            if session_guard else "Session anomalies:     0/0"
        )
        print(
            f"Session blocks:        {session_blocked}/{session_total}"
            if session_guard else "Session blocks:        0/0"
        )

        if block_rate > 0.50:
            print("ALERT: Input block rate is unusually high.")
        if judge_fail_rate > 0.30:
            print("ALERT: LLM judge / output block rate is unusually high.")
        if rate_limit_hit_rate > 0.20:
            print("ALERT: Rate limiter is triggering frequently.")