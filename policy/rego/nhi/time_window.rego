package nhi.time_window

import rego.v1

# Agent time windows are declared in the identity manifest and embedded
# in the task context. SecOpsAgent is exempt (24/7 for incident response).

within_window if {
    # No time window declared — allow at any time
    not input.context.time_window
}

within_window if {
    # SecOpsAgent with active incident_id is exempt from time restrictions
    input.agent_type == "SecOpsAgent"
    input.context.incident_id
}

within_window if {
    tw := input.context.time_window
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour >= tw.start_hour_utc
    current_hour < tw.end_hour_utc
}

deny_reason := "Action is outside the agent's declared operating time window" if {
    not within_window
}
