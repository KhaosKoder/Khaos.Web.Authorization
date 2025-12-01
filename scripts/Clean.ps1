[CmdletBinding()]
param(
    [string]$Configuration = "Release"
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$solution = Join-Path $repoRoot "Khaos.Web.Authorization.sln"

Push-Location $repoRoot
try {
    Write-Host "Cleaning solution ($Configuration)..."
    dotnet clean $solution -c $Configuration

    $pathsToRemove = @(
        (Join-Path $repoRoot "artifacts"),
        (Join-Path $repoRoot "TestResults")
    )

    foreach ($path in $pathsToRemove) {
        if (Test-Path $path) {
            Write-Host "Removing $path"
            Remove-Item -Path $path -Recurse -Force
        }
    }
}
finally {
    Pop-Location
}
