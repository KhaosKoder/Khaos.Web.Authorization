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
    Write-Host "Restoring solution dependencies..."
    dotnet restore $solution

    Write-Host "Building solution ($Configuration)..."
    dotnet build $solution -c $Configuration --no-restore
}
finally {
    Pop-Location
}
