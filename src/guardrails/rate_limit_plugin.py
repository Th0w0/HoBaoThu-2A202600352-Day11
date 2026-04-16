from collections import defaultdict, deque
import time

from google.adk.plugins import base_plugin
from google.genai import types

class RateLimitPlugin(base_plugin.BasePlugin):
    """Blocks users who exceed N requests within a sliding time window."""

    def __init__(self, max_requests=10, window_seconds=60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _get_user_id(self, invocation_context) -> str:
        if invocation_context and getattr(invocation_context, "user_id", None):
            return str(invocation_context.user_id)
        return "anonymous"

    async def on_user_message_callback(self, *, invocation_context, user_message):
        self.total_count += 1
        user_id = self._get_user_id(invocation_context)
        now = time.time()
        window = self.user_windows[user_id]

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait_time = max(1, int(self.window_seconds - (now - window[0])))
            return types.Content(
                role="model",
                parts=[types.Part.from_text(
                    text=f"Rate limit exceeded. Please wait {wait_time} seconds before trying again."
                )],
            )

        window.append(now)
        return None