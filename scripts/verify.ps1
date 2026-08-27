$ErrorActionPreference = "Stop"

$AtlasRepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $AtlasRepoRoot
try {
    $env:PYTHONPATH = Join-Path $AtlasRepoRoot "src"

    & py -3.11 -m compileall -q src tests
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & py -3.11 -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    & py -3.11 -m atlas_test --json doctor
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
