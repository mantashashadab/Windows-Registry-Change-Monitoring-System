SUSPICIOUS_PATTERNS = {
    "Windows Defender": [
        r"Windows Defender",
        r"DisableAntiSpyware",
        r"DisableAntiVirus",
        r"DisableRealtimeMonitoring",
    ],

    "Windows Firewall": [
        r"WindowsFirewall",
        r"FirewallPolicy",
        r"DisableFirewall",
    ],

    "Shell Replacement": [
        r"Winlogon.*Shell",
        r"Winlogon.*Userinit",
    ],

    "UAC Bypass": [
        r"ms-settings",
        r"fodhelper",
        r"DelegateExecute",
        r"SilentCleanup",
    ],

    "Security Policy": [
        r"Policies\\Microsoft\\Windows Defender",
        r"Policies\\Microsoft\\WindowsFirewall",
        r"Policies\\Microsoft\\Windows\\System",
    ],
}


def detect_suspicious_change(
    registry_path,
    value_name,
    old_value=None,
    new_value=None
):
    """
    Detect suspicious registry patterns.

    Returns a list of suspicious indicators.
    """

    indicators = []

    text_to_check = " ".join(
        str(value)
        for value in [
            registry_path,
            value_name,
            old_value,
            new_value,
        ]
        if value is not None
    ).lower()

    for category, patterns in SUSPICIOUS_PATTERNS.items():

        for pattern in patterns:

            if pattern.lower() in text_to_check:

                indicators.append({
                    "category": category,
                    "pattern": pattern,
                    "registry_path": registry_path,
                    "value_name": value_name,
                    "old_value": old_value,
                    "new_value": new_value,
                })

    return indicators


def analyze_changes(change_results):
    """
    Analyze detected Registry changes for suspicious patterns.
    """

    suspicious = []

    for registry_name, registry_data in change_results.items():

        registry_path = registry_data.get("path", "")
        changes = registry_data.get("changes", {})

        # Added
        for item in changes.get("added", []):

            suspicious.extend(
                detect_suspicious_change(
                    registry_path,
                    item.get("value_name"),
                    None,
                    item.get("new_value"),
                )
            )

        # Modified
        for item in changes.get("modified", []):

            suspicious.extend(
                detect_suspicious_change(
                    registry_path,
                    item.get("value_name"),
                    item.get("old_value"),
                    item.get("new_value"),
                )
            )

        # Deleted
        for item in changes.get("deleted", []):

            suspicious.extend(
                detect_suspicious_change(
                    registry_path,
                    item.get("value_name"),
                    item.get("old_value"),
                    None,
                )
            )

    return suspicious