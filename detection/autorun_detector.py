import os
import re


EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".ps1",
    ".vbs",
    ".js",
}


AUTORUN_KEYS = {
    "HKCU_Run",
    "HKCU_RunOnce",
    "HKLM_Run",
    "HKLM_RunOnce",
}


def extract_executable(command):
    """
    Extract a likely executable or script path from
    a Registry autorun command.
    """

    if not command:
        return None

    command = str(command).strip()

    # Remove surrounding quotes when appropriate
    cleaned = command.strip('"')

    # Look for a quoted executable path
    quoted_match = re.search(
        r'"([^"]+\.(?:exe|bat|cmd|com|scr|ps1|vbs|js))"',
        command,
        re.IGNORECASE,
    )

    if quoted_match:
        return quoted_match.group(1)

    # Look for an executable path without quotes
    path_match = re.search(
        r'([A-Za-z]:\\[^"]+?\.(?:exe|bat|cmd|com|scr|ps1|vbs|js))',
        cleaned,
        re.IGNORECASE,
    )

    if path_match:
        return path_match.group(1)

    # If the value itself ends with a supported extension
    if any(
        cleaned.lower().endswith(extension)
        for extension in EXECUTABLE_EXTENSIONS
    ):
        return cleaned

    return None


def analyze_autorun_entries(snapshot):
    """
    Analyze Run and RunOnce Registry entries.

    Returns a list of detected autorun entries.
    """

    autorun_entries = []

    for registry_name, registry_data in snapshot.items():

        if registry_name not in AUTORUN_KEYS:
            continue

        values = registry_data.get("values", {})

        for value_name, value_data in values.items():

            # Ignore collection errors
            if value_name == "__ERROR__":
                continue

            command = value_data.get("value")

            executable = extract_executable(command)

            autorun_entries.append({
                "registry": registry_name,
                "path": registry_data.get("path"),
                "name": value_name,
                "command": command,
                "executable": executable,
                "type": value_data.get("type"),
            })

    return autorun_entries


def get_autorun_summary(snapshot):
    """
    Return a simple summary of detected autorun entries.
    """

    entries = analyze_autorun_entries(snapshot)

    return {
        "total": len(entries),
        "entries": entries,
    }


if __name__ == "__main__":

    from core.registry_collector import collect_registry_snapshot

    print("=" * 70)
    print("AUTORUN REGISTRY ANALYSIS")
    print("=" * 70)

    snapshot = collect_registry_snapshot()

    results = analyze_autorun_entries(snapshot)

    if not results:
        print("\nNo autorun entries found.")

    else:

        print(f"\nAutorun entries detected: {len(results)}")

        for entry in results:

            print("\n" + "-" * 70)

            print(f"Registry:   {entry['registry']}")
            print(f"Name:       {entry['name']}")
            print(f"Command:    {entry['command']}")
            print(f"Executable: {entry['executable']}")

    print("\n" + "=" * 70)