# detector/detector.py
# Anomaly detection logic.
#
# Two triggers (whichever fires first):
#   1. Z-score > 3.0  →  rate is 3 standard deviations above normal
#   2. Rate > 5x baseline mean  →  absolute spike regardless of variance
#
# Error surge: if an IP's error rate is 3x the baseline error rate,
# we tighten the thresholds for that IP (multiply by 0.5).

import time
import logging

log = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(self, config, baseline, blocker, notifier, shared_state):
        self.config        = config
        self.baseline      = baseline
        self.blocker       = blocker
        self.notifier      = notifier
        self.shared_state  = shared_state

        self.zscore_thresh  = config["detection"]["zscore_threshold"]
        self.rate_mult      = config["detection"]["rate_multiplier"]
        self.err_surge_mult = config["detection"]["error_surge_multiplier"]
        self.tighten_factor = config["detection"]["error_surge_tighten_factor"]

        # Track when we last fired an alert to avoid spam (per IP)
        self.last_alert = {}   # ip -> timestamp
        self.cooldown   = 120  # seconds between alerts for same IP

    def _is_error_surge(self, ip, error_rps):
        """True if this IP's error rate is 3x the baseline error rate."""
        return error_rps >= (self.baseline.get_error_mean() * self.err_surge_mult)

    def check(self, ip, ip_rps, global_rps, error_rps, now):
        """
        Called for every request.
        Checks both per-IP and global anomaly conditions.
        """
        # Don't alert too frequently for same IP
        if now - self.last_alert.get(ip, 0) < self.cooldown:
            return

        mean   = self.baseline.mean
        stddev = self.baseline.stddev

        # Tighten thresholds if error surge
        zscore_thresh = self.zscore_thresh
        rate_mult     = self.rate_mult
        if self._is_error_surge(ip, error_rps):
            zscore_thresh *= self.tighten_factor
            rate_mult     *= self.tighten_factor
            log.info(f"Error surge for {ip}: tightened thresholds z>{zscore_thresh}, rate>{rate_mult}x")

        # ── Per-IP anomaly check ──
        ip_zscore  = self.baseline.get_zscore(ip_rps)
        ip_anomaly = (ip_zscore > zscore_thresh) or (ip_rps > mean * rate_mult)

        if ip_anomaly:
            condition = (
                f"z-score={ip_zscore:.2f}" if ip_zscore > zscore_thresh
                else f"rate={ip_rps:.2f} > {rate_mult}x baseline"
            )
            log.warning(f"IP ANOMALY detected: {ip} | {condition}")
            self.last_alert[ip] = now
            self.blocker.ban(ip, condition, ip_rps, now)
            return

        # ── Global anomaly check (Slack only, no IP ban) ──
        if now - self.last_alert.get("_global_", 0) < 60:
            return

        global_zscore  = self.baseline.get_zscore(global_rps)
        global_anomaly = (global_zscore > self.zscore_thresh) or (global_rps > mean * self.rate_mult)

        if global_anomaly:
            condition = (
                f"global z-score={global_zscore:.2f}" if global_zscore > self.zscore_thresh
                else f"global rate={global_rps:.2f} > {self.rate_mult}x baseline"
            )
            log.warning(f"GLOBAL ANOMALY: {condition}")
            self.last_alert["_global_"] = now
            self.notifier.send_global_alert(condition, global_rps, mean, now)
