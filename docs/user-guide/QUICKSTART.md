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

For a checkout containing `action/action.yml`, put this workflow in `.github/workflows/agent-security.yml`.

```yaml
name: Agent security
on: [pull_request]
permissions: {contents: read, security-events: write}
jobs:
  canary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./action
        with: {config: canary.yaml, tags: smoke}
```

For another repository, use `dheerajkarwasra/CanaryCI/action` at a reviewed commit SHA. Run `canary-ci run --help` for CLI flags. [Consumer workflow](../../examples/github-workflow-pr-gate.yml) · [Action inputs and outputs](../../action/action.yml) · [Run exit codes](../../README.md#run-in-ci)
