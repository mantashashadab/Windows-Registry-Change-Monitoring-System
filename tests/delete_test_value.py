import winreg


TEST_PATH = r"Software\RegistryMonitorTest"


with winreg.OpenKey(
    winreg.HKEY_CURRENT_USER,
    TEST_PATH,
    0,
    winreg.KEY_SET_VALUE
) as key:

    winreg.DeleteValue(
        key,
        "AddedValue"
    )


print("[+] AddedValue deleted successfully.")