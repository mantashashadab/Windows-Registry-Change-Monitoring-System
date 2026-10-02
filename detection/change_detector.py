def compare_values(baseline_values, current_values):
    """
    Compare registry values between a baseline and current snapshot.

    Returns:
        Dictionary containing added, modified, and deleted values.
    """

    changes = {
        "added": [],
        "modified": [],
        "deleted": []
    }

    # Detect added and modified values
    for value_name, current_data in current_values.items():

        if value_name not in baseline_values:

            changes["added"].append({
                "value_name": value_name,
                "new_value": current_data.get("value"),
                "type": current_data.get("type")
            })

        else:

            baseline_data = baseline_values[value_name]

            if (
                baseline_data.get("value")
                != current_data.get("value")
            ):

                changes["modified"].append({
                    "value_name": value_name,
                    "old_value": baseline_data.get("value"),
                    "new_value": current_data.get("value"),
                    "type": current_data.get("type")
                })

    # Detect deleted values
    for value_name, baseline_data in baseline_values.items():

        if value_name not in current_values:

            changes["deleted"].append({
                "value_name": value_name,
                "old_value": baseline_data.get("value"),
                "type": baseline_data.get("type")
            })

    return changes


def compare_snapshots(baseline_snapshot, current_snapshot):
    """
    Compare the complete baseline Registry snapshot
    with the current Registry snapshot.
    """

    results = {}

    for registry_name, baseline_data in baseline_snapshot.items():

        current_data = current_snapshot.get(
            registry_name,
            {
                "path": baseline_data.get("path"),
                "values": {}
            }
        )

        baseline_values = baseline_data.get(
            "values",
            {}
        )

        current_values = current_data.get(
            "values",
            {}
        )

        results[registry_name] = {
            "path": baseline_data.get("path"),
            "changes": compare_values(
                baseline_values,
                current_values
            )
        }

    return results


def count_changes(results):
    """
    Count all detected Registry changes.
    """

    added = 0
    modified = 0
    deleted = 0

    for registry_data in results.values():

        changes = registry_data["changes"]

        added += len(changes["added"])
        modified += len(changes["modified"])
        deleted += len(changes["deleted"])

    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "total": added + modified + deleted
    }