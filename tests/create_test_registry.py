import winreg


TEST_PATH = r"Software\RegistryMonitorTest"


def create_test_key():
    with winreg.CreateKey(
        winreg.HKEY_CURRENT_USER,
        TEST_PATH
    ) as key:

        winreg.SetValueEx(
            key,
            "TestValue",
            0,
            winreg.REG_SZ,
            "Initial Value"
        )

    print("[+] Test Registry key created.")
    print(f"[+] Path: HKCU\\{TEST_PATH}")
    print("[+] TestValue = Initial Value")


if __name__ == "__main__":
    create_test_key()