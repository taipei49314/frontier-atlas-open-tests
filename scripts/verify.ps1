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

    $PacketManifests = Get-ChildItem -LiteralPath "packets" -Filter "packet.json" -File -Recurse
    foreach ($PacketManifest in $PacketManifests) {
        & py -3.11 -m atlas_test --json packet validate --packet $PacketManifest.FullName
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}
finally {
    Pop-Location
}
