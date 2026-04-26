# detector/baseline.py
# Computes a rolling baseline (mean + stddev) from recent traffic.
#
# How it works:
#   - Every second, we record the current global req/s into a list.
#   - We keep the last 30 minutes worth of samples (1800 entries).
#   - Every 60 seconds, we recalculate mean and stddev from those samples.
#   - We also maintain per-hour slots so that if traffic in hour 2 is very
#     different from hour 1, the baseline adapts to the current hour.

import time
import math
import logging
import yaml

log = logging.getLogger("baseline")

AUDIT_LOG = None  # set after config load


def write_audit(path, message):
    with open(path, "a") as f:
        f.write(message + "\n")


class BaselineTracker:
    def __init__(self, config, shared_state):
        self.config       = config
        self.shared_state = shared_state

        # Rolling window: stores per-second global req counts
        window_min  = config["detection"]["baseline_window_minutes"]
        self.max_samples = window_min * 60  # e.g. 30 min * 60 = 1800 samples

        self.recalc_interval = config["detection"]["baseline_recalc_interval"]
        self.floor           = config["detection"]["baseline_floor"]
        self.audit_path      = config["log"]["audit_path"]

        self.samples = []        # rolling list of (timestamp, rps) tuples
        self.hour_slots = {}     # {hour_int: [rps, ...]}

        self.mean   = self.floor
        self.stddev = 1.0

        # For error rate baseline
        self.error_samples = []
        self.error_mean    = 0.01

    def _current_hour(self):
        return time.localtime().tm_hour

    def add_sample(self, rps, error_rps=0.0):
        """Called every second with the current global req/s."""
        now  = time.time()
        hour = self._current_hour()

        self.samples.append((now, rps))
        self.error_samples.append((now, error_rps))

        # Keep only last max_samples
        cutoff = now - (self.max_samples)
        self.samples      = [(t, r) for t, r in self.samples      if t >= cutoff]
        self.error_samples = [(t, r) for t, r in self.error_samples if t >= cutoff]

        # Add to current hour slot
        if hour not in self.hour_slots:
            self.hour_slots[hour] = []
        self.hour_slots[hour].append(rps)

    def _calc_stats(self, values):
        """Return (mean, stddev) for a list of numbers."""
        if not values:
            return self.floor, 1.0
        n    = len(values)
        mean = sum(values) / n
        mean = max(mean, self.floor)
        if n < 2:
            return mean, 1.0
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        stddev   = max(math.sqrt(variance), 0.1)
        return mean, stddev

    def recalculate(self):
        """Recompute mean and stddev. Prefers the current hour's data if sufficient."""
        hour          = self._current_hour()
        hour_data     = self.hour_slots.get(hour, [])
        rolling_data  = [r for _, r in self.samples]

        # Use current hour data if we have at least 5 minutes worth
        if len(hour_data) >= 300:
            values = hour_data
            source = f"hour-{hour}"
        else:
            values = rolling_data
            source = "rolling"

        old_mean   = self.mean
        old_stddev = self.stddev

        self.mean, self.stddev = self._calc_stats(values)

        # Error baseline
        error_vals = [r for _, r in self.error_samples]
        self.error_mean, _ = self._calc_stats(error_vals) if error_vals else (0.01, 0.01)

        # Update shared state for dashboard
        with self.shared_state["lock"]:
            self.shared_state["baseline_mean"]   = round(self.mean, 4)
            self.shared_state["baseline_stddev"] = round(self.stddev, 4)

        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        # Format matches task spec: [timestamp] ACTION ip | condition | rate | baseline | duration
        audit_line = (
            f"[{ts}] BASELINE_RECALC global | "
            f"source={source} | "
            f"rate={self.mean:.4f} | "
            f"baseline={self.mean:.4f} | "
            f"stddev={self.stddev:.4f}"
        )
        log.info(audit_line)
        write_audit(self.audit_path, audit_line)

    def run(self):
        """Background thread: samples every second, recalculates every 60s."""
        log.info("Baseline tracker started.")
        last_recalc = time.time()

        while True:
            rps = self.shared_state.get("global_rps", 0.0)
            self.add_sample(rps)

            if time.time() - last_recalc >= self.recalc_interval:
                self.recalculate()
                last_recalc = time.time()

            time.sleep(1)

    def get_zscore(self, rate):
        """How many standard deviations is `rate` above the mean?"""
        if self.stddev == 0:
            return 0.0
        return (rate - self.mean) / self.stddev

    def get_error_mean(self):
        return max(self.error_mean, 0.001)
