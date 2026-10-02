import hashlib
import json


def calculate_snapshot_hash(snapshot):
    """
    Calculate a SHA-256 hash of a Registry snapshot.
    """

    serialized = json.dumps(
        snapshot,
        sort_keys=True,
        default=str
    ).encode("utf-8")

    return hashlib.sha256(serialized).hexdigest()


def check_integrity(baseline_snapshot, current_snapshot):
    """
    Compare baseline and current Registry snapshots
    using SHA-256 hashes.
    """

    baseline_hash = calculate_snapshot_hash(
        baseline_snapshot
    )

    current_hash = calculate_snapshot_hash(
        current_snapshot
    )

    return {
        "baseline_hash": baseline_hash,
        "current_hash": current_hash,
        "integrity_match": (
            baseline_hash == current_hash
        )
    }