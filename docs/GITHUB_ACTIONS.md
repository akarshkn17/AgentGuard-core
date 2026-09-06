# GitHub Actions CI/CD Adapter

## Before package publication

Use `integrations/github/example-local-workflow.yml`. It installs `packages/core` and `packages/cli` from the checked-out distribution source and then invokes the CLI.

## After publication

Customer repositories only need:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.11"
- run: python -m pip install "agentguard-cli==0.4.0"
- run: >-
    agentguard scan .
    --output-dir agentguard-results
    --format json --format sarif --format html --format html-summary
    --format aibom --format agent-bom
    --fail-on high
```

The example workflow also uploads `agentguard-results/` as a build artifact and publishes `agentguard.sarif` into GitHub code scanning.

## Exit codes

- `0`: scan completed and no finding met the configured `--fail-on` threshold.
- `1`: at least one finding met/exceeded the threshold.
- `2`: CLI/rule validation/configuration error.

Use `--fail-on none` during initial rollout. Move to `critical`, then `high` after baseline triage.

## Recommended CI rollout

1. Run on pull requests with `--fail-on none` and collect reports.
2. Establish a baseline and eliminate obvious false positives/rule gaps.
3. Gate only new Critical findings.
4. Extend to High after developer remediation guidance is proven usable.
5. Add future authenticated result upload separately; do not make local CI scanning depend on SaaS availability.
