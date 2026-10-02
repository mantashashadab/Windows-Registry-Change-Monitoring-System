import json
import os
import platform
from datetime import datetime

import streamlit as st

from core.baseline_manager import (
    load_baseline,
    create_baseline
)

from detection.change_detector import (
    compare_snapshots,
    count_changes
)

from detection.autorun_detector import (
    analyze_autorun_entries
)

from detection.suspicious_detector import (
    analyze_changes
)

from detection.integrity_checker import (
    check_integrity
)

from scoring.risk_engine import (
    calculate_overall_risk
)


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Windows Registry Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# ENVIRONMENT
# =========================================================

IS_WINDOWS = platform.system() == "Windows"


# winreg is Windows-only.
# Import it only when running on Windows.

if IS_WINDOWS:
    from core.registry_collector import (
        collect_registry_snapshot
    )


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 2.4rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }

    .subtitle {
        color: #6b7280;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="main-title">'
    '🛡️ Windows Registry Change Monitoring System'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Registry integrity • Persistence monitoring • '
    'Suspicious-change detection • Risk analysis'
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("⚙️ Controls")


if st.sidebar.button(
    "🔄 Refresh Analysis",
    use_container_width=True
):

    st.rerun()


if IS_WINDOWS:

    st.sidebar.markdown("---")

    st.sidebar.markdown(
        "### Registry Controls"
    )

    if st.sidebar.button(
        "📸 Create New Baseline",
        use_container_width=True
    ):

        snapshot = collect_registry_snapshot()

        path = create_baseline(
            snapshot
        )

        st.sidebar.success(
            "Baseline created successfully."
        )

else:

    st.sidebar.info(
        "Deployment mode uses safe demonstration data."
    )


st.sidebar.markdown("---")

st.sidebar.markdown(
    "### Monitoring Modules"
)

st.sidebar.markdown(
    """
    ✓ Registry Collector

    ✓ Baseline Comparison

    ✓ ADD / MODIFY / DELETE Detection

    ✓ Autorun Detection

    ✓ Suspicious Pattern Detection

    ✓ SHA-256 Integrity Checking

    ✓ Risk Analysis

    ✓ Event Logging

    ✓ Continuous Monitoring
    """
)

st.sidebar.markdown("---")

st.sidebar.caption(
    "Defensive monitoring only. "
    "The system does not modify security settings "
    "or create persistence."
)


# =========================================================
# DEMO DATA
# =========================================================

def create_demo_data():

    baseline = {

        "HKCU_Run": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\Run"
            ),

            "values": {

                "OneDrive": {
                    "value": (
                        "C:\\Program Files\\Microsoft OneDrive"
                        "\\OneDrive.exe"
                    ),
                    "type": 1
                }
            }
        },

        "HKCU_RunOnce": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\RunOnce"
            ),

            "values": {}
        },

        "HKLM_Run": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\Run"
            ),

            "values": {

                "SecurityHealth": {
                    "value": (
                        "C:\\Windows\\System32"
                        "\\SecurityHealthSystray.exe"
                    ),
                    "type": 1
                }
            }
        },

        "HKLM_RunOnce": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\RunOnce"
            ),

            "values": {}
        },

        "TEST_Key": {
            "path": (
                "Software\\RegistryMonitorTest"
            ),

            "values": {

                "TestValue": {
                    "value": "Initial Value",
                    "type": 1
                }
            }
        }
    }


    current = {

        "HKCU_Run": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\Run"
            ),

            "values": {

                "OneDrive": {
                    "value": (
                        "C:\\Program Files\\Microsoft OneDrive"
                        "\\OneDrive.exe"
                    ),
                    "type": 1
                }
            }
        },

        "HKCU_RunOnce": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\RunOnce"
            ),

            "values": {}
        },

        "HKLM_Run": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\Run"
            ),

            "values": {

                "SecurityHealth": {
                    "value": (
                        "C:\\Windows\\System32"
                        "\\SecurityHealthSystray.exe"
                    ),
                    "type": 1
                }
            }
        },

        "HKLM_RunOnce": {
            "path": (
                "Software\\Microsoft\\Windows"
                "\\CurrentVersion\\RunOnce"
            ),

            "values": {}
        },

        "TEST_Key": {
            "path": (
                "Software\\RegistryMonitorTest"
            ),

            "values": {

                "TestValue": {
                    "value": "Modified Value",
                    "type": 1
                },

                "DemoEntry": {
                    "value": (
                        "C:\\Users\\User"
                        "\\AppData\\demo.exe"
                    ),
                    "type": 1
                }
            }
        }
    }

    return baseline, current


# =========================================================
# LOAD BASELINE / CURRENT SNAPSHOT
# =========================================================

baseline_data = load_baseline()


if IS_WINDOWS and baseline_data is not None:

    baseline_snapshot = (
        baseline_data["registry"]
    )

    current_snapshot = (
        collect_registry_snapshot()
    )

    environment_mode = (
        "LIVE WINDOWS REGISTRY"
    )

    baseline_created_at = (
        baseline_data.get(
            "created_at",
            "Unknown"
        )
    )


elif IS_WINDOWS:

    st.warning(
        "No Registry baseline has been created yet."
    )

    st.info(
        "Use 'Create New Baseline' in the sidebar."
    )

    st.stop()


else:

    baseline_snapshot, current_snapshot = (
        create_demo_data()
    )

    environment_mode = (
        "DEMO / DEPLOYMENT MODE"
    )

    baseline_created_at = (
        "Demonstration baseline"
    )


# =========================================================
# ANALYSIS
# =========================================================

results = compare_snapshots(
    baseline_snapshot,
    current_snapshot
)


summary = count_changes(
    results
)


autorun_entries = analyze_autorun_entries(
    current_snapshot
)


suspicious_changes = analyze_changes(
    results
)


integrity_result = check_integrity(
    baseline_snapshot,
    current_snapshot
)


risk_result = calculate_overall_risk(
    results,
    suspicious_changes,
    autorun_entries
)


# =========================================================
# SCAN TIME
# =========================================================

scan_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)


# =========================================================
# ENVIRONMENT
# =========================================================

st.markdown(
    "## 🖥️ Monitoring Environment"
)


environment_col1, environment_col2, environment_col3 = (
    st.columns(3)
)


with environment_col1:

    st.metric(
        "Monitoring Mode",
        environment_mode
    )


with environment_col2:

    if IS_WINDOWS:

        st.metric(
            "Registry Access",
            "AVAILABLE"
        )

    else:

        st.metric(
            "Registry Access",
            "DEMO"
        )


with environment_col3:

    st.metric(
        "Last Scan",
        scan_time
    )


if IS_WINDOWS:

    st.success(
        "Windows environment detected — "
        "live Registry monitoring is available."
    )

else:

    st.info(
        "Deployment environment detected — "
        "live Windows Registry access is unavailable. "
        "Safe demonstration data is being displayed."
    )


# =========================================================
# BASELINE INFORMATION
# =========================================================

with st.expander(
    "📸 Baseline Information"
):

    st.write(
        f"**Baseline created:** "
        f"{baseline_created_at}"
    )

    st.write(
        "**Purpose:** "
        "The baseline represents the known Registry "
        "state used for change and integrity comparison."
    )


# =========================================================
# SECURITY OVERVIEW
# =========================================================

st.markdown(
    "## 📊 Security Overview"
)


col1, col2, col3, col4, col5 = (
    st.columns(5)
)


with col1:

    st.metric(
        "Added",
        summary["added"]
    )


with col2:

    st.metric(
        "Modified",
        summary["modified"]
    )


with col3:

    st.metric(
        "Deleted",
        summary["deleted"]
    )


with col4:

    st.metric(
        "Suspicious",
        len(suspicious_changes)
    )


with col5:

    st.metric(
        "Autorun Entries",
        len(autorun_entries)
    )


# =========================================================
# CHANGE CHART
# =========================================================

st.markdown(
    "## 📈 Registry Change Breakdown"
)


chart_data = {

    "Added": summary["added"],

    "Modified": summary["modified"],

    "Deleted": summary["deleted"]
}


st.bar_chart(
    chart_data
)


# =========================================================
# RISK ANALYSIS
# =========================================================

st.markdown(
    "## 🚨 Risk Analysis"
)


risk_col1, risk_col2, risk_col3, risk_col4 = (
    st.columns(4)
)


with risk_col1:

    st.metric(
        "Risk Score",
        risk_result["total_score"]
    )


with risk_col2:

    st.metric(
        "Risk Level",
        risk_result["risk_level"]
    )


with risk_col3:

    st.metric(
        "Change Risk",
        risk_result["change_score"]
    )


with risk_col4:

    st.metric(
        "Suspicious Risk",
        risk_result["suspicious_score"]
    )


if risk_result["risk_level"] == "HIGH":

    st.error(
        "🔴 HIGH RISK — Registry activity "
        "requires investigation."
    )

elif risk_result["risk_level"] == "MEDIUM":

    st.warning(
        "🟠 MEDIUM RISK — Registry changes "
        "have been detected."
    )

else:

    st.success(
        "🟢 LOW RISK — No significant "
        "suspicious activity detected."
    )


st.caption(
    "Risk scoring is heuristic. A suspicious indicator "
    "is an investigation signal and does not by itself "
    "prove malware."
)


# =========================================================
# INTEGRITY
# =========================================================

st.markdown(
    "## 🔐 Registry Integrity"
)


if integrity_result["integrity_match"]:

    st.success(
        "✅ Integrity Status: MATCH"
    )

else:

    st.warning(
        "⚠️ Integrity Status: CHANGED"
    )


hash_col1, hash_col2 = (
    st.columns(2)
)


with hash_col1:

    st.caption(
        "Baseline SHA-256"
    )

    st.code(
        integrity_result["baseline_hash"]
    )


with hash_col2:

    st.caption(
        "Current SHA-256"
    )

    st.code(
        integrity_result["current_hash"]
    )


# =========================================================
# REGISTRY CHANGES
# =========================================================

st.markdown(
    "## 🔎 Detected Registry Changes"
)


change_rows = []


for registry_name, registry_data in results.items():

    changes = registry_data["changes"]


    for item in changes["added"]:

        change_rows.append({

            "Registry": registry_name,

            "Path": registry_data["path"],

            "Change": "ADDED",

            "Value Name": item["value_name"],

            "Old Value": "",

            "New Value": str(
                item["new_value"]
            )
        })


    for item in changes["modified"]:

        change_rows.append({

            "Registry": registry_name,

            "Path": registry_data["path"],

            "Change": "MODIFIED",

            "Value Name": item["value_name"],

            "Old Value": str(
                item["old_value"]
            ),

            "New Value": str(
                item["new_value"]
            )
        })


    for item in changes["deleted"]:

        change_rows.append({

            "Registry": registry_name,

            "Path": registry_data["path"],

            "Change": "DELETED",

            "Value Name": item["value_name"],

            "Old Value": str(
                item["old_value"]
            ),

            "New Value": ""
        })


if change_rows:

    st.dataframe(
        change_rows,
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No Registry changes detected."
    )


# =========================================================
# SUSPICIOUS INDICATORS
# =========================================================

st.markdown(
    "## 🚨 Suspicious Registry Indicators"
)


if suspicious_changes:

    suspicious_rows = []


    for indicator in suspicious_changes:

        suspicious_rows.append({

            "Category": indicator["category"],

            "Pattern": indicator["pattern"],

            "Registry Path": (
                indicator["registry_path"]
            ),

            "Value": indicator["value_name"],

            "Old Value": str(
                indicator["old_value"]
            ),

            "New Value": str(
                indicator["new_value"]
            )
        })


    st.dataframe(
        suspicious_rows,
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No suspicious Registry indicators detected."
    )


# =========================================================
# AUTORUN
# =========================================================

st.markdown(
    "## 🚀 Autorun Registry Entries"
)


st.info(
    "Autorun entries are monitored persistence locations. "
    "Their presence alone does not indicate malware."
)


if autorun_entries:

    autorun_rows = []


    for entry in autorun_entries:

        autorun_rows.append({

            "Registry": entry["registry"],

            "Name": entry["name"],

            "Command": str(
                entry["command"]
            ),

            "Executable": str(
                entry["executable"]
            )
        })


    st.dataframe(
        autorun_rows,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No autorun entries detected."
    )


# =========================================================
# RISK FINDINGS
# =========================================================

st.markdown(
    "## 📋 Risk Findings"
)


if risk_result["findings"]:

    finding_rows = []


    for finding in risk_result["findings"]:

        finding_rows.append({

            "Type": finding.get(
                "type",
                ""
            ),

            "Description": finding.get(
                "description",
                ""
            ),

            "Score": finding.get(
                "score",
                0
            ),

            "Registry": finding.get(
                "registry",
                ""
            ),

            "Value": finding.get(
                "value_name",
                ""
            )
        })


    st.dataframe(
        finding_rows,
        use_container_width=True,
        hide_index=True
    )

else:

    st.success(
        "No risk findings available."
    )


# =========================================================
# EVENT LOG
# =========================================================

st.markdown(
    "## 📝 Registry Event Log"
)


LOG_FILE = os.path.join(
    "logs",
    "registry_events.json"
)


events = []


if os.path.exists(LOG_FILE):

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            events = json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        events = []


if events:

    st.metric(
        "Logged Events",
        len(events)
    )


    st.dataframe(
        events,
        use_container_width=True,
        hide_index=True
    )


    log_data = json.dumps(
        events,
        indent=4,
        default=str
    )


    st.download_button(
        label="📥 Download Event Log",
        data=log_data,
        file_name="registry_events.json",
        mime="application/json"
    )

else:

    st.info(
        "No Registry events have been logged yet."
    )


# =========================================================
# EXPORT FULL ANALYSIS
# =========================================================

st.markdown(
    "## 📥 Export Analysis"
)


export_data = {

    "generated_at": scan_time,

    "environment": environment_mode,

    "baseline_created_at": (
        baseline_created_at
    ),

    "registry_summary": summary,

    "integrity": integrity_result,

    "risk": risk_result,

    "suspicious_indicators": (
        suspicious_changes
    ),

    "autorun_entries": (
        autorun_entries
    ),

    "changes": results
}


export_json = json.dumps(
    export_data,
    indent=4,
    default=str
)


st.download_button(
    label="📥 Download Full Analysis",
    data=export_json,
    file_name="registry_monitor_analysis.json",
    mime="application/json",
    use_container_width=True
)


# =========================================================
# FOOTER
# =========================================================

st.markdown("---")


st.caption(
    "Windows Registry Change Monitoring System • "
    "Defensive registry auditing and integrity monitoring"
)


st.caption(
    "Read-only monitoring design • "
    "Suspicious indicators require further investigation"
)