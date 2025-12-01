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
$coverageReportDir = Join-Path $resultsRoot "coverage"

Push-Location $repoRoot
try {
    if (Test-Path $coverageReportDir) {
        Remove-Item -Path $coverageReportDir -Recurse -Force
    }

    $arguments = @(
        "test",
        $solution,
        "-c", $Configuration,
        "--collect:XPlat Code Coverage",
        "--results-directory", $resultsRoot
    )

    if ($NoBuild) {
        $arguments += "--no-build"
    }

    Write-Host "Running coverage-enabled tests ($Configuration)..."
    dotnet @arguments

    $coverageFile = Get-ChildItem -Path $resultsRoot -Recurse -Filter "coverage.cobertura.xml" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $coverageFile) {
        throw "Unable to locate coverage.cobertura.xml under $resultsRoot."
    }

    Write-Host "Restoring local dotnet tools..."
    dotnet tool restore

    if (-not (Test-Path $coverageReportDir)) {
        New-Item -Path $coverageReportDir -ItemType Directory | Out-Null
    }

    $reportArgs = @(
        "-reports:$($coverageFile.FullName)",
        "-targetdir:$coverageReportDir",
        "-reporttypes:Html;Cobertura"
    )

    Write-Host "Generating coverage report in $coverageReportDir ..."
    dotnet tool run reportgenerator @reportArgs

    Write-Host "Coverage artifacts:"
    Write-Host "  Cobertura: $(Join-Path $coverageReportDir "Cobertura.xml")"
    Write-Host "  HTML: $(Join-Path $coverageReportDir "index.html")"
}
finally {
    Pop-Location
}
