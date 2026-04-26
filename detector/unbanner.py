# detector/unbanner.py
# Checks every 30 seconds if any bans have expired, and removes them.
# Backoff schedule: 10 min → 30 min → 2 hr → permanent (no unban)

import subprocess
import time
import logging
from baseline import write_audit

log = logging.getLogger("unbanner")


class Unbanner:
    def __init__(self, config, notifier, shared_state):
        self.config       = config
        self.notifier     = notifier
        self.shared_state = shared_state
        self.audit_path   = config["log"]["audit_path"]

    def _remove_iptables(self, ip):
        """Remove the DROP rule for this IP from iptables."""
        try:
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                log.info(f"iptables rule removed for {ip}")
            else:
                log.warning(f"Could not remove iptables rule for {ip}: {result.stderr}")
        except Exception as e:
            log.error(f"Failed to remove iptables rule for {ip}: {e}")

    def run(self):
        """Check for expired bans every 30 seconds."""
        log.info("Unbanner started.")
        while True:
            now = time.time()
            to_unban = []

            with self.shared_state["lock"]:
                for ip, info in list(self.shared_state["banned_ips"].items()):
                    if info.get("permanent"):
                        continue  # Never unban permanent
                    if info["unban_at"] and now >= info["unban_at"]:
                        to_unban.append(ip)

            for ip in to_unban:
                self._remove_iptables(ip)

                with self.shared_state["lock"]:
                    info = self.shared_state["banned_ips"].get(ip, {})

                # Notify Slack — pass all fields the task requires in alerts
                self.notifier.send_unban_alert(
                    ip,
                    info.get("ban_count", 1),
                    info.get("condition", "unknown"),
                    info.get("rate", 0.0),
                    self.shared_state["baseline_mean"],
                    now
                )

                # Audit log — format matches task spec exactly:
                # [timestamp] ACTION ip | condition | rate | baseline | duration
                ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))
                audit = (
                    f"[{ts}] UNBAN {ip} | "
                    f"condition={info.get('condition','?')} | "
                    f"rate={info.get('rate', 0):.4f} | "
                    f"baseline={self.shared_state['baseline_mean']:.4f} | "
                    f"duration=ban#{info.get('ban_count',1)}-expired"
                )
                log.info(audit)
                write_audit(self.audit_path, audit)

                # Remove from banned list (unless permanent — but permanent never reaches here)
                with self.shared_state["lock"]:
                    self.shared_state["banned_ips"].pop(ip, None)

            time.sleep(30)
