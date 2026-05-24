package nhi.rate_limit

import rego.v1

# Rate limiting is enforced per agent per time window.
# The PEP injects the current action count from Redis into the request context.
# OPA evaluates whether the count exceeds the agent's declared limit.
#
# Note: OPA is stateless — it cannot count actions itself.
# The PEP is responsible for maintaining counters in Redis and injecting
# the current count into the input before calling OPA.

default max_actions_per_minute := 30

max_actions_per_minute := input.context.max_actions_per_minute if {
    input.context.max_actions_per_minute
}

within_rate_limit if {
    not input.context.current_action_count_per_minute
}

within_rate_limit if {
    input.context.current_action_count_per_minute < max_actions_per_minute
}

deny_reason := "Agent has exceeded its declared action rate limit" if {
    not within_rate_limit
}
