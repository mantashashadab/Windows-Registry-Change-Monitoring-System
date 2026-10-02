import json
import os
from datetime import datetime


LOG_DIRECTORY = "logs"
LOG_FILE = os.path.join(
    LOG_DIRECTORY,
    "registry_events.json"
)


def ensure_log_directory():
    """
    Create the log directory if it does not exist.
    """

    os.makedirs(
        LOG_DIRECTORY,
        exist_ok=True
    )


def create_event(
    event_type,
    registry_name,
    registry_path,
    value_name,
    old_value=None,
    new_value=None,
    risk_level="LOW",
    risk_score=0,
    description=""
):
    """
    Create a structured Registry event.
    """

    return {
        "timestamp": datetime.now().isoformat(),

        "event_type": event_type,

        "registry": registry_name,

        "registry_path": registry_path,

        "value_name": value_name,

        "old_value": old_value,

        "new_value": new_value,

        "risk_level": risk_level,

        "risk_score": risk_score,

        "description": description
    }


def log_event(event):
    """
    Append a Registry event to the JSON log file.
    """

    ensure_log_directory()

    events = []

    if os.path.exists(LOG_FILE):

        try:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                events = json.load(file)

                if not isinstance(events, list):
                    events = []

        except (
            json.JSONDecodeError,
            OSError
        ):

            events = []

    events.append(event)

    with open(
        LOG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4,
            default=str
        )

    return LOG_FILE


def log_registry_changes(
    change_results,
    risk_level="LOW",
    risk_score=0
):
    """
    Log all detected Registry additions,
    modifications, and deletions.
    """

    logged_events = []

    for registry_name, registry_data in change_results.items():

        registry_path = registry_data.get(
            "path",
            ""
        )

        changes = registry_data.get(
            "changes",
            {}
        )

        # -------------------------------------------------
        # ADDED VALUES
        # -------------------------------------------------

        for item in changes.get("added", []):

            event = create_event(
                event_type="ADDED",
                registry_name=registry_name,
                registry_path=registry_path,
                value_name=item.get(
                    "value_name"
                ),
                old_value=None,
                new_value=item.get(
                    "new_value"
                ),
                risk_level=risk_level,
                risk_score=risk_score,
                description=(
                    "New Registry value detected"
                )
            )

            log_event(event)

            logged_events.append(event)

        # -------------------------------------------------
        # MODIFIED VALUES
        # -------------------------------------------------

        for item in changes.get("modified", []):

            event = create_event(
                event_type="MODIFIED",
                registry_name=registry_name,
                registry_path=registry_path,
                value_name=item.get(
                    "value_name"
                ),
                old_value=item.get(
                    "old_value"
                ),
                new_value=item.get(
                    "new_value"
                ),
                risk_level=risk_level,
                risk_score=risk_score,
                description=(
                    "Registry value modified"
                )
            )

            log_event(event)

            logged_events.append(event)

        # -------------------------------------------------
        # DELETED VALUES
        # -------------------------------------------------

        for item in changes.get("deleted", []):

            event = create_event(
                event_type="DELETED",
                registry_name=registry_name,
                registry_path=registry_path,
                value_name=item.get(
                    "value_name"
                ),
                old_value=item.get(
                    "old_value"
                ),
                new_value=None,
                risk_level=risk_level,
                risk_score=risk_score,
                description=(
                    "Registry value deleted"
                )
            )

            log_event(event)

            logged_events.append(event)

    return logged_events


if __name__ == "__main__":

    print("=" * 70)
    print("REGISTRY EVENT LOGGER")
    print("=" * 70)

    test_event = create_event(
        event_type="TEST",
        registry_name="TEST_Key",
        registry_path=(
            r"Software\RegistryMonitorTest"
        ),
        value_name="TestValue",
        old_value="Old Value",
        new_value="New Value",
        risk_level="LOW",
        risk_score=0,
        description=(
            "Event logger test entry"
        )
    )

    path = log_event(
        test_event
    )

    print(
        f"\n[+] Test event logged successfully."
    )

    print(
        f"[+] Log file: {path}"
    )