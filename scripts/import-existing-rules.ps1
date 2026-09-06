param(
  [Parameter(Mandatory=$true)]
  [string]$SourceRules
)
$ErrorActionPreference = "Stop"
$destination = Join-Path $PSScriptRoot "..\packages\core\src\agentguard_core\rules\builtin"
if (-not (Test-Path $SourceRules)) { throw "Rule directory not found: $SourceRules" }
Get-ChildItem $destination -Filter *.yaml -ErrorAction SilentlyContinue | Remove-Item -Force
Copy-Item (Join-Path $SourceRules "*.yaml") $destination -Force
Write-Host "Imported canonical AgentGuard rules into $destination"
$env:PYTHONPATH = (Join-Path $PSScriptRoot "..\packages\core\src")
python -c "from pathlib import Path; from agentguard_core.rules import RuleStore; p=Path(r'$destination'); s=RuleStore(p); print('rules:', len(s.load()), 'validation errors:', s.validate())"
