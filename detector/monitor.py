# detector/monitor.py
# Continuously tails the Nginx JSON access log and feeds parsed lines to the detector

import json
import time
import os
import logging
from collections import deque

log = logging.getLogger("monitor")


class LogMonitor:
    """
    Tails /var/log/nginx/hng-access.log line by line.
    For each line, it parses the JSON and updates the sliding windows.

    Sliding window explained:
      - We use a deque (double-ended queue) for each IP and one globally.
      - Each entry in the deque is a timestamp (float).
      - Every time a request comes in, we append its timestamp.
      - Before reading the deque, we pop entries from the LEFT that are
        older than `window_seconds` ago. This is the "eviction" step.
      - The length of the deque = number of requests in the last N seconds.
    """

    def __init__(self, config, detector, shared_state):
        self.log_path       = config["log"]["path"]
        self.window_sec     = config["detection"]["window_seconds"]
        self.detector       = detector
        self.shared_state   = shared_state

        # Global sliding window: deque of timestamps
        self.global_window  = deque()

        # Per-IP sliding windows: {ip: deque of timestamps}
        self.ip_windows     = {}

        # Per-IP error tracking: {ip: deque of (timestamp, is_error)}
        self.ip_error_windows = {}

    def _evict_old(self, dq, now):
        """Remove timestamps older than window_seconds from the left of the deque."""
        cutoff = now - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _parse_line(self, line):
        """Parse a JSON log line. Returns a dict or None if invalid."""
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def run(self):
        """Tail the log file forever. Waits for the file to exist first."""
        log.info(f"Waiting for log file: {self.log_path}")
        while not os.path.exists(self.log_path):
            time.sleep(2)

        log.info(f"Tailing log file: {self.log_path}")
        with open(self.log_path, "r") as f:
            # Seek to end so we don't replay old logs on startup
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.05)  # No new line yet — wait a bit
                    continue
                self._process_line(line)

    def _process_line(self, line):
        """Called for each new log line."""
        entry = self._parse_line(line)
        if not entry:
            return

        now    = time.time()
        ip     = entry.get("source_ip", "unknown")
        status = int(entry.get("status", 200))

        # ── Update global sliding window ──
        self.global_window.append(now)
        self._evict_old(self.global_window, now)
        global_rps = len(self.global_window) / self.window_sec

        # ── Update per-IP sliding window ──
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()
        self.ip_windows[ip].append(now)
        self._evict_old(self.ip_windows[ip], now)
        ip_rps = len(self.ip_windows[ip]) / self.window_sec

        # ── Track errors per IP ──
        if ip not in self.ip_error_windows:
            self.ip_error_windows[ip] = deque()
        is_error = 1 if status >= 400 else 0
        self.ip_error_windows[ip].append((now, is_error))
        # Evict old error entries
        cutoff = now - self.window_sec
        while self.ip_error_windows[ip] and self.ip_error_windows[ip][0][0] < cutoff:
            self.ip_error_windows[ip].popleft()
        error_rate = sum(e[1] for e in self.ip_error_windows[ip]) / max(self.window_sec, 1)

        # ── Update shared state for dashboard ──
        with self.shared_state["lock"]:
            self.shared_state["global_rps"] = round(global_rps, 3)
            top = self.shared_state["top_ips"]
            top[ip] = top.get(ip, 0) + 1
            # Keep only top 10
            self.shared_state["top_ips"] = dict(
                sorted(top.items(), key=lambda x: x[1], reverse=True)[:10]
            )

        # ── Feed into detector ──
        self.detector.check(ip, ip_rps, global_rps, error_rate, now)

        log.debug(f"{ip} | ip_rps={ip_rps:.2f} | global_rps={global_rps:.2f} | status={status}")
