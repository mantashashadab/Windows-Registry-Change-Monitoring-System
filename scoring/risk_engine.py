# scoring/risk_engine.py


# ---------------------------------------------------------
# RISK WEIGHTS
# ---------------------------------------------------------

RISK_WEIGHTS = {
    "added_change": 1,
    "modified_change": 1,
    "deleted_change": 1,

    # Autorun entries are observations.
    # They do NOT automatically increase risk.
    "autorun_entry": 0,

    "new_autorun_entry": 3,

    "Windows Defender": 4,
    "Windows Firewall": 4,
    "Shell Replacement": 5,
    "UAC Bypass": 5,
    "Security Policy": 4,
}


# ---------------------------------------------------------
# RISK LEVELS
# ---------------------------------------------------------

def get_risk_level(score):
    """
    Convert a numerical risk score into a risk level.
    """

    if score == 0:
        return "LOW"

    elif score <= 3:
        return "MEDIUM"

    else:
        return "HIGH"


# ---------------------------------------------------------
# CHANGE RISK
# ---------------------------------------------------------

def calculate_change_risk(change_results):
    """
    Calculate risk from Registry additions,
    modifications, and deletions.
    """

    score = 0
    findings = []

    for registry_name, registry_data in change_results.items():

        changes = registry_data.get(
            "changes",
            {}
        )

        registry_path = registry_data.get(
            "path",
            ""
        )

        # -------------------------------------------------
        # ADDED
        # -------------------------------------------------

        for item in changes.get("added", []):

            score += RISK_WEIGHTS["added_change"]

            findings.append({
                "type": "ADDED",
                "registry": registry_name,
                "path": registry_path,
                "value_name": item.get("value_name"),
                "description": (
                    "New Registry value detected"
                ),
                "score": RISK_WEIGHTS["added_change"]
            })

        # -------------------------------------------------
        # MODIFIED
        # -------------------------------------------------

        for item in changes.get("modified", []):

            score += RISK_WEIGHTS["modified_change"]

            findings.append({
                "type": "MODIFIED",
                "registry": registry_name,
                "path": registry_path,
                "value_name": item.get("value_name"),
                "description": (
                    "Registry value modified"
                ),
                "score": RISK_WEIGHTS["modified_change"]
            })

        # -------------------------------------------------
        # DELETED
        # -------------------------------------------------

        for item in changes.get("deleted", []):

            score += RISK_WEIGHTS["deleted_change"]

            findings.append({
                "type": "DELETED",
                "registry": registry_name,
                "path": registry_path,
                "value_name": item.get("value_name"),
                "description": (
                    "Registry value deleted"
                ),
                "score": RISK_WEIGHTS["deleted_change"]
            })

    return {
        "score": score,
        "findings": findings
    }


# ---------------------------------------------------------
# SUSPICIOUS INDICATOR RISK
# ---------------------------------------------------------

def calculate_suspicious_risk(suspicious_changes):
    """
    Calculate risk from suspicious Registry indicators.
    """

    score = 0
    findings = []

    for indicator in suspicious_changes:

        category = indicator.get(
            "category",
            "Unknown"
        )

        weight = RISK_WEIGHTS.get(
            category,
            2
        )

        score += weight

        findings.append({
            "type": "SUSPICIOUS",
            "category": category,
            "pattern": indicator.get("pattern"),
            "registry_path": indicator.get(
                "registry_path"
            ),
            "value_name": indicator.get(
                "value_name"
            ),
            "description": (
                f"Suspicious {category} "
                "indicator detected"
            ),
            "score": weight
        })

    return {
        "score": score,
        "findings": findings
    }


# ---------------------------------------------------------
# AUTORUN ANALYSIS
# ---------------------------------------------------------

def calculate_autorun_risk(
    autorun_entries,
    change_results
):
    """
    Analyze autorun entries.

    Existing autorun entries are treated as observations
    and receive zero risk points.

    Newly added autorun entries receive additional risk
    because they represent a change to startup behavior.
    """

    score = 0
    findings = []

    # -----------------------------------------------------
    # Existing autorun entries
    # -----------------------------------------------------

    for entry in autorun_entries:

        findings.append({
            "type": "AUTORUN_OBSERVATION",
            "registry": entry.get(
                "registry"
            ),
            "path": entry.get(
                "path"
            ),
            "value_name": entry.get(
                "name"
            ),
            "command": entry.get(
                "command"
            ),
            "executable": entry.get(
                "executable"
            ),
            "description": (
                "Existing autorun Registry entry observed"
            ),
            "score": 0
        })

    # -----------------------------------------------------
    # Detect newly added autorun values
    # -----------------------------------------------------

    for registry_name, registry_data in change_results.items():

        if registry_name not in {
            "HKCU_Run",
            "HKCU_RunOnce",
            "HKLM_Run",
            "HKLM_RunOnce"
        }:
            continue

        changes = registry_data.get(
            "changes",
            {}
        )

        for item in changes.get("added", []):

            score += RISK_WEIGHTS[
                "new_autorun_entry"
            ]

            findings.append({
                "type": "NEW_AUTORUN",
                "registry": registry_name,
                "path": registry_data.get(
                    "path"
                ),
                "value_name": item.get(
                    "value_name"
                ),
                "command": item.get(
                    "new_value"
                ),
                "description": (
                    "New autorun Registry entry detected"
                ),
                "score": RISK_WEIGHTS[
                    "new_autorun_entry"
                ]
            })

    return {
        "score": score,
        "findings": findings
    }


# ---------------------------------------------------------
# FINAL RISK CALCULATION
# ---------------------------------------------------------

def calculate_overall_risk(
    change_results,
    suspicious_changes,
    autorun_entries
):
    """
    Combine Registry changes, suspicious indicators,
    and autorun observations.
    """

    change_result = calculate_change_risk(
        change_results
    )

    suspicious_result = calculate_suspicious_risk(
        suspicious_changes
    )

    autorun_result = calculate_autorun_risk(
        autorun_entries,
        change_results
    )

    total_score = (
        change_result["score"]
        + suspicious_result["score"]
        + autorun_result["score"]
    )

    all_findings = (
        change_result["findings"]
        + suspicious_result["findings"]
        + autorun_result["findings"]
    )

    risk_level = get_risk_level(
        total_score
    )

    return {
        "total_score": total_score,
        "risk_level": risk_level,

        "change_score": change_result["score"],
        "suspicious_score": suspicious_result["score"],
        "autorun_score": autorun_result["score"],

        "findings": all_findings
    }


# ---------------------------------------------------------
# TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 70)
    print("REGISTRY RISK ENGINE")
    print("=" * 70)

    print(
        "\n[*] Risk Engine module loaded successfully."
    )

    print("\nRisk Levels:")

    print(
        f"0      -> {get_risk_level(0)}"
    )

    print(
        f"2      -> {get_risk_level(2)}"
    )

    print(
        f"5      -> {get_risk_level(5)}"
    )

    print(
        f"10     -> {get_risk_level(10)}"
    )

    print(
        "\n[+] Risk Engine test completed."
    )