import winreg


MONITORED_KEYS = {
    "HKCU_Run": (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ),
    "HKCU_RunOnce": (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    "HKLM_Run": (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ),
        "HKLM_RunOnce": (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ),

    "TEST_Key": (
        winreg.HKEY_CURRENT_USER,
        r"Software\RegistryMonitorTest",
    ),
}


def read_registry_key(root, path):
    """
    Read all values from a Windows Registry key.
    """

    values = {}

    try:
        with winreg.OpenKey(
            root,
            path,
            0,
            winreg.KEY_READ
        ) as key:

            index = 0

            while True:
                try:
                    name, value, value_type = winreg.EnumValue(
                        key,
                        index
                    )

                    values[name] = {
                        "value": value,
                        "type": value_type
                    }

                    index += 1

                except OSError:
                    break

    except FileNotFoundError:
        return {}

    except PermissionError:
        return {
            "__ERROR__": {
                "value": "Permission denied",
                "type": None
            }
        }

    return values


def collect_registry_snapshot():
    """
    Collect a snapshot of all monitored Registry locations.
    """

    snapshot = {}

    for name, (root, path) in MONITORED_KEYS.items():

        snapshot[name] = {
            "path": path,
            "values": read_registry_key(root, path)
        }

    return snapshot


if __name__ == "__main__":

    snapshot = collect_registry_snapshot()

    for key_name, data in snapshot.items():

        print("=" * 70)
        print(key_name)
        print(data["path"])
        print("-" * 70)

        if not data["values"]:
            print("No values found.")

        else:
            for value_name, value_data in data["values"].items():

                print(
                    f"{value_name}: "
                    f"{value_data['value']}"
                )