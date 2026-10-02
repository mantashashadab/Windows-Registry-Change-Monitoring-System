import time

from core.registry_collector import collect_registry_snapshot
from core.baseline_manager import load_baseline

from detection.change_detector import (
    compare_snapshots,
    count_changes
)

from detection.suspicious_detector import analyze_changes
from detection.autorun_detector import analyze_autorun_entries

from scoring.risk_engine import calculate_overall_risk

from logging_system.event_logger import log_registry_changes


DEFAULT_INTERVAL = 10


def check_registry():

    baseline_data = load_baseline()

    if baseline_data is None:

        print("[!] No baseline found.")
        print(
            "[!] Create a baseline before starting monitoring."
        )

        return None

    baseline_snapshot = baseline_data["registry"]

    current_snapshot = collect_registry_snapshot()

    results = compare_snapshots(
        baseline_snapshot,
        current_snapshot
    )

    summary = count_changes(
        results
    )

    suspicious_changes = analyze_changes(
        results
    )

    autorun_entries = analyze_autorun_entries(
        current_snapshot
    )

    risk_result = calculate_overall_risk(
        results,
        suspicious_changes,
        autorun_entries
    )

    return {
        "baseline": baseline_snapshot,
        "current": current_snapshot,
        "results": results,
        "summary": summary,
        "suspicious": suspicious_changes,
        "autorun": autorun_entries,
        "risk": risk_result
    }


def display_alert(result):

    summary = result["summary"]
    risk = result["risk"]

    print("\n" + "=" * 70)
    print("REGISTRY MONITOR ALERT")
    print("=" * 70)

    print(
        f"Changes detected: {summary['total']}"
    )

    print(
        f"Added:            {summary['added']}"
    )

    print(
        f"Modified:         {summary['modified']}"
    )

    print(
        f"Deleted:          {summary['deleted']}"
    )

    print(
        f"Risk Score:       {risk['total_score']}"
    )

    print(
        f"Risk Level:       {risk['risk_level']}"
    )

    print(
        f"Suspicious:       "
        f"{len(result['suspicious'])}"
    )

    print("=" * 70)


def monitor_registry(
    interval=DEFAULT_INTERVAL
):

    print("=" * 70)
    print("CONTINUOUS WINDOWS REGISTRY MONITOR")
    print("=" * 70)

    print(
        f"\n[*] Monitoring interval: "
        f"{interval} seconds"
    )

    print(
        "[*] Press Ctrl+C to stop monitoring."
    )

    print("\n[*] Starting Registry monitoring...")

    last_change_signature = None

    try:

        while True:

            result = check_registry()

            if result is None:
                return

            summary = result["summary"]

            # -------------------------------------------------
            # CREATE CHANGE SIGNATURE
            # -------------------------------------------------

            change_signature = (
                summary["added"],
                summary["modified"],
                summary["deleted"]
            )

            # -------------------------------------------------
            # DETECT CHANGE
            # -------------------------------------------------

            if summary["total"] > 0:

                # Only alert when the detected state changes.
                if change_signature != last_change_signature:

                    display_alert(result)

                    # -----------------------------------------
                    # LOG EVENT
                    # -----------------------------------------

                    log_registry_changes(
                        result["results"],
                        risk_level=result["risk"][
                            "risk_level"
                        ],
                        risk_score=result["risk"][
                            "total_score"
                        ]
                    )

                    print(
                        "\n[+] Registry event logged."
                    )

                    last_change_signature = (
                        change_signature
                    )

                else:

                    print(
                        "\n[*] Previously detected "
                        "change still present."
                    )

            else:

                print(
                    "\n[+] No Registry changes detected."
                )

                last_change_signature = None

            print(
                f"\n[*] Next scan in "
                f"{interval} seconds..."
            )

            time.sleep(interval)

    except KeyboardInterrupt:

        print("\n")

        print("=" * 70)
        print("REGISTRY MONITOR STOPPED")
        print("=" * 70)

        print(
            "\n[+] Monitoring stopped safely."
        )


if __name__ == "__main__":

    monitor_registry()