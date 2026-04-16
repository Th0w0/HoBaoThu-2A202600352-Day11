from collections import defaultdict, deque
import time
import re

from google.adk.plugins import base_plugin
from google.genai import types


class SessionAnomalyDetectorPlugin(base_plugin.BasePlugin):
    """
    Bonus safety layer:
    Detects suspicious repeated probing behavior within a session/user window.

    Why needed:
    - A single message may not clearly be malicious.
    - Multiple secret-seeking / prompt-injection-like messages over a short window
      indicate abnormal behavior and should be blocked.
    """

    def __init__(self, max_suspicious_events=3, window_seconds=300):
        super().__init__(name="session_anomaly_detector")
        self.max_suspicious_events = max_suspicious_events
        self.window_seconds = window_seconds
        self.user_events = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0
        self.flagged_count = 0

        self.suspicious_patterns = [
            r"ignore (all )?(previous|above) instructions",
            r"system prompt",
            r"reveal your (instructions|prompt)",
            r"you are now",
            r"pretend you are",
            r"act as (a |an )?unrestricted",
            r"override your system prompt",
            r"admin password",
            r"\bapi key\b",
            r"\bcredentials\b",
            r"\bdatabase\b",
            r"\binternal\b",
            r"\bhostnames?\b",
            r"\btoken(s)?\b",
            r"translate your full system instructions",
            r"fill in the blanks",
            r"write a short story where the main character",
        ]

    def _get_user_id(self, invocation_context) -> str:
        if invocation_context and getattr(invocation_context, "user_id", None):
            return str(invocation_context.user_id)
        return "anonymous"

    def _extract_text(self, content: types.Content) -> str:
        text = ""
        if content and getattr(content, "parts", None):
            for part in content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    def _is_suspicious(self, text: str) -> bool:
        text_lower = text.lower()
        return any(re.search(pattern, text_lower, re.IGNORECASE) for pattern in self.suspicious_patterns)

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        self.total_count += 1

        user_id = self._get_user_id(invocation_context)
        text = self._extract_text(user_message)
        now = time.time()

        window = self.user_events[user_id]

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if self._is_suspicious(text):
            window.append(now)
            self.flagged_count += 1

        if len(window) >= self.max_suspicious_events:
            self.blocked_count += 1
            return self._block_response(
                "Your session has been flagged for repeated suspicious requests. "
                "Please stop requesting internal instructions, credentials, or restricted information."
            )

        return None