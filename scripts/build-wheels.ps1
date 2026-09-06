$ErrorActionPreference = "Stop"
if (Test-Path .\dist) { Remove-Item -Recurse -Force .\dist }
New-Item -ItemType Directory -Path .\dist | Out-Null
python -m pip wheel --no-deps --no-build-isolation .\packages\core -w .\dist
python -m pip wheel --no-deps --no-build-isolation .\packages\cli -w .\dist
Get-ChildItem .\dist
