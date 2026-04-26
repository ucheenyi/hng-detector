# detector/blocker.py
# Adds iptables DROP rules for anomalous IPs.
# Sends a Slack alert within 10 seconds of detecting the anomaly.

import subprocess
import time
import logging
from baseline import write_audit

log = logging.getLogger("blocker")


class Blocker:
    def __init__(self, config, notifier, shared_state):
        self.config       = config
        self.notifier     = notifier
        self.shared_state = shared_state
        self.audit_path   = config["log"]["audit_path"]
        self.backoff      = config["ban"]["backoff_minutes"]

    def _add_iptables(self, ip):
        """Add a DROP rule to iptables for this IP."""
        try:
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                log.info(f"iptables DROP added for {ip}")
            else:
                log.error(f"iptables error for {ip}: {result.stderr}")
        except Exception as e:
            log.error(f"Failed to add iptables rule for {ip}: {e}")

    def ban(self, ip, condition, rate, now):
        """Ban an IP. Determine duration based on how many times it's been banned."""
        with self.shared_state["lock"]:
            banned = self.shared_state["banned_ips"]
            ban_count = banned.get(ip, {}).get("ban_count", 0)

            # Determine ban duration from backoff schedule
            if ban_count < len(self.backoff):
                duration_minutes = self.backoff[ban_count]
                permanent = False
            else:
                duration_minutes = None  # Permanent
                permanent = True

            unban_at = now + (duration_minutes * 60) if not permanent else None

            banned[ip] = {
                "ban_count": ban_count + 1,
                "banned_at": now,
                "unban_at":  unban_at,
                "permanent": permanent,
                "condition": condition,
                "rate":      rate,
            }

        # Add iptables rule
        self._add_iptables(ip)

        # Send Slack alert
        duration_str = f"{duration_minutes} min" if not permanent else "permanent"
        self.notifier.send_ban_alert(ip, condition, rate, self.shared_state["baseline_mean"], now, duration_str)

        # Write audit log — format matches task spec exactly:
        # [timestamp] ACTION ip | condition | rate | baseline | duration
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
        audit = (
            f"[{ts}] BAN {ip} | "
            f"condition={condition} | "
            f"rate={rate:.4f} | "
            f"baseline={self.shared_state['baseline_mean']:.4f} | "
            f"duration={duration_str}"
        )
        log.warning(audit)
        write_audit(self.audit_path, audit)
