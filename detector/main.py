# detector/main.py
# Entry point — starts all daemon threads and keeps running forever

import threading
import time
import yaml
import logging
from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import DashboardServer

# Load config — looks for config.yaml in the same directory as main.py
import os
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
with open(CONFIG_PATH) as f:
    config = yaml.safe_load(f)

# Shared state (passed between modules)
shared_state = {
    "banned_ips": {},        # ip -> {"ban_count": N, "banned_at": timestamp, "unban_at": timestamp}
    "global_rps": 0.0,       # current global requests per second
    "top_ips": {},            # ip -> request count (last window)
    "baseline_mean": 0.0,
    "baseline_stddev": 0.0,
    "start_time": time.time(),
    "lock": threading.Lock(),
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("main")


def main():
    log.info("=== HNG Anomaly Detection Daemon Starting ===")

    notifier   = Notifier(config)
    blocker    = Blocker(config, notifier, shared_state)
    baseline   = BaselineTracker(config, shared_state)
    detector   = AnomalyDetector(config, baseline, blocker, notifier, shared_state)
    unbanner   = Unbanner(config, notifier, shared_state)
    monitor    = LogMonitor(config, detector, shared_state)
    dashboard  = DashboardServer(config, shared_state)

    # Start each component in its own daemon thread
    threads = [
        threading.Thread(target=baseline.run,   name="Baseline",   daemon=True),
        threading.Thread(target=unbanner.run,    name="Unbanner",   daemon=True),
        threading.Thread(target=monitor.run,     name="Monitor",    daemon=True),
        threading.Thread(target=dashboard.run,   name="Dashboard",  daemon=True),
    ]

    for t in threads:
        t.start()
        log.info(f"Started thread: {t.name}")

    log.info("All threads running. Daemon is live.")

    # Keep main thread alive
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()
