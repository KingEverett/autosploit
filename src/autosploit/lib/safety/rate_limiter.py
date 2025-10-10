import time
import threading
from collections import deque
from typing import Dict, Optional


class RateLimiter:
    """Thread-safe rate limiter using sliding window algorithm."""

    def __init__(self, max_per_second: int = 100, window_seconds: float = 1.0):
        self.max_per_second = max_per_second
        self.window_seconds = window_seconds

        self._state: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        current_time = time.perf_counter()

        with self._lock:
            if key not in self._state:
                self._state[key] = deque()

            call_times = self._state[key]

            # Remove expired entries
            cutoff = current_time - self.window_seconds
            while call_times and call_times[0] < cutoff:
                call_times.popleft()

            if len(call_times) >= self.max_per_second:
                return False

            call_times.append(current_time)
            return True

    def wait_if_needed(self, key: str, timeout: Optional[float] = None) -> bool:
        start = time.perf_counter()

        while not self.allow(key):
            if timeout and (time.perf_counter() - start) > timeout:
                return False

            time.sleep(self.window_seconds / (self.max_per_second * 2))

        return True

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._state.clear()
            elif key in self._state:
                self._state[key].clear()

    def get_remaining(self, key: str) -> int:
        current_time = time.perf_counter()

        with self._lock:
            if key not in self._state:
                return self.max_per_second

            call_times = self._state[key]

            cutoff = current_time - self.window_seconds
            recent_count = sum(1 for t in call_times if t >= cutoff)

            return max(0, self.max_per_second - recent_count)