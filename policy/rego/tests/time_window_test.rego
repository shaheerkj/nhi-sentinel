package nhi.time_window_test

import data.nhi.time_window
import rego.v1

# No time window declared — always within window
test_no_time_window_always_allowed if {
    time_window.within_window with input as {
        "agent_type": "InfraAgent",
        "context": {},
    }
}

# SecOpsAgent with incident_id is exempt from time restrictions
test_secops_incident_override if {
    time_window.within_window with input as {
        "agent_type": "SecOpsAgent",
        "context": {
            "incident_id": "INC-2026-001",
            "time_window": {"start_hour_utc": 8, "end_hour_utc": 20},
        },
    }
}

# SecOpsAgent without incident_id is NOT exempt
test_secops_no_incident_follows_window if {
    # This test validates the rule does NOT fire for SecOpsAgent without incident_id.
    # The time_window rule requires incident_id for the SecOps exemption.
    not time_window.within_window with input as {
        "agent_type": "SecOpsAgent",
        "context": {
            "time_window": {"start_hour_utc": 0, "end_hour_utc": 0},
        },
    }
}
