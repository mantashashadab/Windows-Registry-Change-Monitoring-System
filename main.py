from core.registry_collector import collect_registry_snapshot
from core.baseline_manager import load_baseline

from detection.change_detector import (
    compare_snapshots,
    count_changes
)

from detection.autorun_detector import analyze_autorun_entries
from detection.suspicious_detector import analyze_changes
from detection.integrity_checker import check_integrity

from scoring.risk_engine import calculate_overall_risk

from logging_system.event_logger import log_registry_changes


def main():

    print("=" * 70)
    print("WINDOWS REGISTRY CHANGE MONITORING SYSTEM")
    print("=" * 70)

    # ---------------------------------------------------------
    # 1. LOAD BASELINE
    # ---------------------------------------------------------

    baseline_data = load_baseline()

    if baseline_data is None:

        print("\n[!] No baseline found.")
        print("[!] Create a baseline first.")

        return

    baseline_snapshot = baseline_data["registry"]

    print("\n[*] Loading baseline...")

    print(
        f"[*] Baseline created at: "
        f"{baseline_data['created_at']}"
    )

    # ---------------------------------------------------------
    # 2. COLLECT CURRENT REGISTRY SNAPSHOT
    # ---------------------------------------------------------

    print("\n[*] Collecting current Registry snapshot...")

    current_snapshot = collect_registry_snapshot()

    # ---------------------------------------------------------
    # 3. AUTORUN ANALYSIS
    # ---------------------------------------------------------

    autorun_entries = analyze_autorun_entries(
        current_snapshot
    )

    print("\n" + "=" * 70)
    print("AUTORUN ENTRIES")
    print("=" * 70)

    print(
        f"Autorun entries detected: "
        f"{len(autorun_entries)}"
    )

    for entry in autorun_entries:

        print("\n" + "-" * 70)

        print(f"Registry:   {entry['registry']}")
        print(f"Name:       {entry['name']}")
        print(f"Command:    {entry['command']}")
        print(f"Executable: {entry['executable']}")

    # ---------------------------------------------------------
    # 4. COMPARE BASELINE WITH CURRENT REGISTRY
    # ---------------------------------------------------------

    print("\n[*] Comparing baseline with current Registry...")

    results = compare_snapshots(
        baseline_snapshot,
        current_snapshot
    )

    # ---------------------------------------------------------
    # 5. SUSPICIOUS REGISTRY ANALYSIS
    # ---------------------------------------------------------

    suspicious_changes = analyze_changes(results)

    print("\n" + "=" * 70)
    print("SUSPICIOUS REGISTRY INDICATORS")
    print("=" * 70)

    print(
        f"Suspicious indicators detected: "
        f"{len(suspicious_changes)}"
    )

    for indicator in suspicious_changes:

        print("\n" + "-" * 70)

        print(
            f"Category: {indicator['category']}"
        )

        print(
            f"Pattern:  {indicator['pattern']}"
        )

        print(
            f"Path:     {indicator['registry_path']}"
        )

        print(
            f"Value:    {indicator['value_name']}"
        )

        print(
            f"Old:      {indicator['old_value']}"
        )

        print(
            f"New:      {indicator['new_value']}"
        )

    # ---------------------------------------------------------
    # 6. COUNT REGISTRY CHANGES
    # ---------------------------------------------------------

    summary = count_changes(results)

    print("\n" + "=" * 70)
    print("CHANGE DETECTION RESULTS")
    print("=" * 70)

    print(
        f"Added:    {summary['added']}"
    )

    print(
        f"Modified: {summary['modified']}"
    )

    print(
        f"Deleted:  {summary['deleted']}"
    )

    print(
        f"Total:    {summary['total']}"
    )

    # ---------------------------------------------------------
    # 7. REGISTRY INTEGRITY CHECK
    # ---------------------------------------------------------

    integrity_result = check_integrity(
        baseline_snapshot,
        current_snapshot
    )

    print("\n" + "=" * 70)
    print("REGISTRY INTEGRITY CHECK")
    print("=" * 70)

    print(
        f"Baseline SHA-256: "
        f"{integrity_result['baseline_hash']}"
    )

    print(
        f"Current SHA-256:  "
        f"{integrity_result['current_hash']}"
    )

    if integrity_result["integrity_match"]:

        print("Integrity Status: MATCH")

    else:

        print("Integrity Status: CHANGED")

    # ---------------------------------------------------------
    # 8. RISK ANALYSIS
    # ---------------------------------------------------------

    risk_result = calculate_overall_risk(
        results,
        suspicious_changes,
        autorun_entries
    )

    print("\n" + "=" * 70)
    print("RISK ANALYSIS")
    print("=" * 70)

    print(
        f"Total Risk Score: "
        f"{risk_result['total_score']}"
    )

    print(
        f"Risk Level: "
        f"{risk_result['risk_level']}"
    )

    print(
        f"Change Risk Score: "
        f"{risk_result['change_score']}"
    )

    print(
        f"Suspicious Indicator Score: "
        f"{risk_result['suspicious_score']}"
    )

    print(
        f"Autorun Observation Score: "
        f"{risk_result['autorun_score']}"
    )

    # ---------------------------------------------------------
    # 9. LOG REGISTRY CHANGES
    # ---------------------------------------------------------

    logged_events = log_registry_changes(
        results,
        risk_level=risk_result["risk_level"],
        risk_score=risk_result["total_score"]
    )

    print("\n" + "=" * 70)
    print("EVENT LOGGING")
    print("=" * 70)

    print(
        f"Registry events logged: "
        f"{len(logged_events)}"
    )

    if logged_events:

        print(
            "[+] Events saved to "
            "logs\\registry_events.json"
        )

    else:

        print(
            "[*] No new Registry changes "
            "were available to log."
        )

    # ---------------------------------------------------------
    # 10. RISK FINDINGS
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("RISK FINDINGS")
    print("=" * 70)

    if not risk_result["findings"]:

        print("\nNo risk findings detected.")

    else:

        for finding in risk_result["findings"]:

            print("\n" + "-" * 70)

            print(
                f"Type:        "
                f"{finding.get('type')}"
            )

            print(
                f"Description: "
                f"{finding.get('description')}"
            )

            print(
                f"Score:       "
                f"{finding.get('score')}"
            )

            if finding.get("registry"):

                print(
                    f"Registry:    "
                    f"{finding.get('registry')}"
                )

            if finding.get("path"):

                print(
                    f"Path:        "
                    f"{finding.get('path')}"
                )

            if finding.get("value_name"):

                print(
                    f"Value:       "
                    f"{finding.get('value_name')}"
                )

            if finding.get("command"):

                print(
                    f"Command:     "
                    f"{finding.get('command')}"
                )

            if finding.get("category"):

                print(
                    f"Category:    "
                    f"{finding.get('category')}"
                )

    # ---------------------------------------------------------
    # 11. DISPLAY DETAILED REGISTRY CHANGES
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("DETAILED REGISTRY CHANGES")
    print("=" * 70)

    changes_found = False

    for registry_name, registry_data in results.items():

        changes = registry_data["changes"]

        if (
            changes["added"]
            or changes["modified"]
            or changes["deleted"]
        ):

            changes_found = True

            print("\n" + "-" * 70)

            print(
                f"Registry: {registry_name}"
            )

            print(
                f"Path:     {registry_data['path']}"
            )

            # -------------------------------------------------
            # ADDED
            # -------------------------------------------------

            for item in changes["added"]:

                print("\n[ADDED]")

                print(
                    f"Value: {item['value_name']}"
                )

                print(
                    f"New:   {item['new_value']}"
                )

            # -------------------------------------------------
            # MODIFIED
            # -------------------------------------------------

            for item in changes["modified"]:

                print("\n[MODIFIED]")

                print(
                    f"Value: {item['value_name']}"
                )

                print(
                    f"Old:   {item['old_value']}"
                )

                print(
                    f"New:   {item['new_value']}"
                )

            # -------------------------------------------------
            # DELETED
            # -------------------------------------------------

            for item in changes["deleted"]:

                print("\n[DELETED]")

                print(
                    f"Value: {item['value_name']}"
                )

                print(
                    f"Old:   {item['old_value']}"
                )

    if not changes_found:

        print(
            "\nNo detailed Registry changes to display."
        )

    # ---------------------------------------------------------
    # 12. FINAL STATUS
    # ---------------------------------------------------------

    print("\n" + "=" * 70)

    if summary["total"] == 0:

        print(
            "STATUS: No Registry changes detected."
        )

    else:

        print(
            "STATUS: Registry changes detected."
        )

    print("=" * 70)


if __name__ == "__main__":
    main()