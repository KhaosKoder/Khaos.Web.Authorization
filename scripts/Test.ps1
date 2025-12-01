[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [switch]$NoBuild
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$solution = Join-Path $repoRoot "Khaos.Web.Authorization.sln"
$resultsRoot = Join-Path $repoRoot "TestResults"

Push-Location $repoRoot
try {
    $arguments = @(
        "test",
        $solution,
        "-c", $Configuration,
        "--results-directory", $resultsRoot
    )

    if ($NoBuild) {
        $arguments += "--no-build"
    }

    Write-Host "Running tests ($Configuration)..."
    dotnet @arguments
}
finally {
    Pop-Location
}
