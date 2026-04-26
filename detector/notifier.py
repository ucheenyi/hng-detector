# detector/notifier.py
# Sends Slack webhook messages for ban, unban, and global anomaly events.
#
# WEBHOOK URL RESOLUTION ORDER (most secure first):
#   1. SLACK_WEBHOOK_URL environment variable  ← preferred, never touches disk
#   2. config.yaml slack.webhook_url           ← fallback
#
# On your VM, set it once and it persists across reboots:
#   echo 'export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXX/YYY/ZZZ"' \
#       >> ~/.bashrc && source ~/.bashrc
# Or add it to the systemd service file under [Service]:
#   Environment="SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ"

import os
import requests
import time
import logging

log = logging.getLogger("notifier")


class Notifier:
    def __init__(self, config):
        # Prefer environment variable — it never gets written to a file on disk
        env_url    = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        config_url = config.get("slack", {}).get("webhook_url", "").strip()

        if env_url:
            self.webhook_url = env_url
            log.info("Slack webhook loaded from environment variable SLACK_WEBHOOK_URL")
        elif config_url and not config_url.startswith("https://hooks.slack.com/services/REPLACE"):
            self.webhook_url = config_url
            log.info("Slack webhook loaded from config.yaml")
        else:
            self.webhook_url = ""
            log.warning("No Slack webhook configured. Set SLACK_WEBHOOK_URL env var or update config.yaml.")

    def _send(self, text):
        """Post a message to the Slack webhook."""
        if not self.webhook_url:
            log.warning("Slack webhook not configured. Skipping notification.")
            return
        try:
            resp = requests.post(self.webhook_url, json={"text": text}, timeout=8)
            if resp.status_code != 200:
                log.error(f"Slack error {resp.status_code}: {resp.text}")
        except Exception as e:
            log.error(f"Slack send failed: {e}")

    def send_ban_alert(self, ip, condition, rate, baseline, timestamp, duration):
        ts  = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))
        msg = (
            f":rotating_light: *IP BANNED*\n"
            f"• IP: `{ip}`\n"
            f"• Condition: {condition}\n"
            f"• Current rate: `{rate:.2f}` req/s\n"
            f"• Baseline mean: `{baseline:.2f}` req/s\n"
            f"• Ban duration: `{duration}`\n"
            f"• Time: `{ts}`"
        )
        log.info(f"Sending ban alert for {ip}")
        self._send(msg)

    def send_unban_alert(self, ip, ban_count, condition, rate, baseline, timestamp):
        ts  = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))
        msg = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"• IP: `{ip}`\n"
            f"• This was ban #{ban_count}\n"
            f"• Original condition: {condition}\n"
            f"• Original rate: `{rate:.2f}` req/s\n"
            f"• Baseline at ban time: `{baseline:.2f}` req/s\n"
            f"• Time: `{ts}`"
        )
        log.info(f"Sending unban alert for {ip}")
        self._send(msg)

    def send_global_alert(self, condition, rate, baseline, timestamp):
        ts  = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(timestamp))
        msg = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"• Condition: {condition}\n"
            f"• Current global rate: `{rate:.2f}` req/s\n"
            f"• Baseline mean: `{baseline:.2f}` req/s\n"
            f"• Time: `{ts}`\n"
            f"_(No single IP identified — monitoring all traffic)_"
        )
        log.info("Sending global anomaly alert")
        self._send(msg)