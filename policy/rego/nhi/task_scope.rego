package nhi.task_scope

import rego.v1

# Every agent action must be bound to an active task owned by this agent.
# This prevents "freelance" actions — agents acting outside their current assignment
# even if their token scopes would technically permit the action.

task_is_active if {
    count(input.task_id) > 0
    # Phase 1/2: task_id presence is sufficient.
    # Phase 3: will query the task registry to validate expiry and ownership.
}

# Environment binding: agents may only operate in their declared environments.
environment_allowed if {
    not input.context.allowed_environments
}

environment_allowed if {
    input.environment == input.context.allowed_environments[_]
}

deny_reason := "No active task_id bound to this request" if {
    not task_is_active
}

deny_reason := "Environment not in agent's declared allowed environments" if {
    task_is_active
    not environment_allowed
}
