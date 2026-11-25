# Test your defense policy

Run the same suite and seed twice, first with the adapter alone and then with your defense configured. Compare the JSON reports with `canary-ci diff`. A defense block appears as `defense_decision` in the trace and counts as a mitigation when the trial has zero remaining breaches.

## Policy webhook

```yaml
defense_proxy:
  kind: webhook_policy
  policy_url: https://policy.example/check
  fail_closed: true
```

Replace the reserved hostname with the URL of your test gateway. CanaryCI sends a JSON POST with `tool_name`, `arguments`, `trust_zone`, `is_sink`, `session_id`, and `turn_index`. Respond with `{"allow": true}` or `{"allow": false, "reason": "Policy denied"}`. An allowed response can include `modified_args`. The harness grades the executed arguments and records the original attempt.

## Command filter

```yaml
defense_proxy:
  kind: mcp_command_wrapper
  command: [python3, policy_filter.py]
  fail_closed: true
```

The command reads a JSON object containing `tool_name` and `arguments` on stdin and writes a single policy decision object to stdout. Log diagnostics on stderr. A timeout, malformed response, or failed request follows `fail_closed`. With `true`, the synthetic tool call is blocked.

For an offline comparison, run `uv run python examples/run_benchmark_demo.py`. It exercises a fixture webhook through an in-process HTTP transport and shows residual policy failures after egress filtering.
