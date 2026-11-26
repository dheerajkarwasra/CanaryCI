# CanaryCI quickstart

Use Python 3.12 or later and `uv`. Starting at the root of a CanaryCI checkout, run the eight smoke scenarios in a temporary directory.

```bash
canary_source="$PWD"
cd "$(mktemp -d)"
uvx --from "$canary_source" canary-ci init --demo
uvx --from "$canary_source" canary-ci run --config canary.demo.yaml
uvx --from "$canary_source" canary-ci run --config canary.demo.yaml --adapter-mode benign
```

The first invocation can download dependencies. Both demo runs are offline. The compromised fixture returns exit code `1` and the benign fixture returns `0`. The terminal shows the evidence chain for each breach. Run artifacts, including JSONL traces, JSON summary, and SARIF, are under `.canary/runs/<run-id>/`.

## Connect a model

Run from the checkout with `uv run --extra llm canary-ci` to use LiteLLM. Update your configuration with a provider model that supports function calling.

```yaml
adapter:
  kind: litellm
  model: openai/your-tool-calling-model
  system_prompt_file: prompts/review.md
  temperature: 0.0
```

Use `openai/` with `OPENAI_API_KEY` or `anthropic/` with `ANTHROPIC_API_KEY`. For local Ollama tool calling, use the `ollama_chat/` prefix, for example `model: ollama_chat/qwen3:1.7b`. Set `OLLAMA_API_BASE` if your Ollama server uses a different address than `http://localhost:11434`. Keep credentials in the environment. Start with one smoke case and use `--trials 5` to measure a live model's variability.

A scenario can set its own `trials` count. An explicit `--trials` overrides it. The project configuration supplies the default.

## Compare two runs

Save a reference run using `canary-ci run --json-report baseline.json`. After changing your agent or policy, save a second run using `--json-report current.json`, then compare them.

```bash
canary-ci diff baseline.json current.json --json-out comparison.json --fail-on-regression
```

The command prints a Markdown table and writes the comparison to JSON. Each scenario shows completed trial counts, mean wall-clock duration in milliseconds, and mean prompt plus completion tokens per trial. Deltas subtract the baseline mean from the current mean. Keep the scenario, adapter settings, host, and concurrency consistent when comparing performance. Only a new security or task-completion failure triggers the regression gate. To embed the comparison in a run summary, use `canary-ci run --baseline baseline.json --json-report current.json`.

A missing measurement appears as an em dash in the table and `null` in JSON. A token mean requires both counts for every session of every trial, including each LiteLLM response. Scripted trials report zero. Older summaries can contain zeros or partial totals for adapters that omitted counts.

## Add the repository action

Run the demo against code from your own pull request. The starter includes a workflow, a config, a Python agent, and a scenario that requires the private note `reviewed` on ticket `T1`. The scenario also forbids a public reply. [Workflow](../../examples/ticket-check/pull-request.yml) · [Config](../../examples/ticket-check/canary.yaml) · [Agent](../../examples/ticket-check/support_agent.py) · [Scenario](../../examples/scenarios/support-task.yaml)

Start in a CanaryCI checkout. Set `target` to the local path of a fresh GitHub repository with an initial commit and Actions enabled. Copy the files into it and keep these paths. [Get a CanaryCI checkout](../../README.md#development)

```bash
target=/absolute/path/to/your-agent-repo
mkdir -p "$target/.github/workflows" "$target/examples/ticket-check" "$target/examples/scenarios"
cp examples/ticket-check/pull-request.yml "$target/.github/workflows/agent-security.yml"
cp examples/ticket-check/canary.yaml examples/ticket-check/support_agent.py "$target/examples/ticket-check/"
cp examples/scenarios/support-task.yaml "$target/examples/scenarios/"
```

1. Open a pull request with the four files. The **Verify the internal note on T1** job should pass. The Action installs CanaryCI from the v0.1.0 commit and runs the downstream agent on Python 3.12.
2. In the same PR, open `support_agent.py`, change the note from `"reviewed"` to `"pending"`, and push. Open the failed workflow run’s **Summary**. Under **TASK INCOMPLETE**, look for `note_saved`, zero breaches, and `0/1` tasks completed. The gate exits with code `1`.
3. Restore `"reviewed"` and push again. The summary shows **PASS**, zero breaches, and `1/1` tasks completed. The gate exits with code `0`.

For a local run, install the wheel and use the same config from the downstream repository root. [Wheel install command](../../README.md#quickstart)

```bash
PYTHONPATH=examples/ticket-check canary-ci run --config examples/ticket-check/canary.yaml
```

To check your own agent, point `adapter.callable_path` at its entry point and set `PYTHONPATH` to its module directory. Keep the ticket scenario as the contract. For a larger suite, the scheduled workflow example runs smoke checks on relevant PRs and five trials per scenario each night. [Scheduled workflow](../../examples/github-workflow-pr-gate.yml)

The starter needs only `contents: read` and writes its verdict to the Actions job summary. To opt into GitHub Code Scanning in a repository with that feature enabled, set `upload-sarif: "true"` and add `security-events: write` alongside `contents: read` in the workflow’s `permissions` block. [Action inputs and outputs](../../action/action.yml) · [Run exit codes](../../README.md#run-in-ci)

Trying this for the first time? Tell us how long it took to find the failed assertion and which step, if any, held you up. [Share feedback on GitHub](https://github.com/dheerajkarwasra/CanaryCI/issues/new)
