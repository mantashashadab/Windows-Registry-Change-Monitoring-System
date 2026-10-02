import json
import os
from datetime import datetime


BASELINE_DIRECTORY = "baselines"
BASELINE_FILE = os.path.join(
    BASELINE_DIRECTORY,
    "registry_baseline.json"
)


def create_baseline(snapshot):
    """
    Save the current Registry snapshot as the baseline.
    """

    os.makedirs(BASELINE_DIRECTORY, exist_ok=True)

    baseline = {
        "created_at": datetime.now().isoformat(),
        "registry": snapshot
    }

    with open(
        BASELINE_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            baseline,
            file,
            indent=4,
            default=str
        )

    return BASELINE_FILE


def load_baseline():
    """
    Load the previously created Registry baseline.
    """

    if not os.path.exists(BASELINE_FILE):
        return None

    with open(
        BASELINE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


if __name__ == "__main__":

    from registry_collector import collect_registry_snapshot

    print("[*] Collecting Registry snapshot...")

    snapshot = collect_registry_snapshot()

    print("[*] Creating baseline...")

    path = create_baseline(snapshot)

    print(f"[+] Baseline created successfully: {path}")