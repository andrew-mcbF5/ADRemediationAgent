#Requires -Version 5.1
<#
.SYNOPSIS
    Packages the AD Remediation Agent as a versioned zip for distribution.

.DESCRIPTION
    Reads AgentVersion from Config\AgentConfig.psd1, stages a clean copy of
    the deliverable files into a temp folder, compresses to a zip, and writes
    it to the Releases\ folder at the repository root.

    Output: Releases\ADRemediationAgent-v<version>.zip

    The zip contains:
        ADRemediationAgent\          (all scripts, config, core, modules)
        DESIGN_DECISIONS.md          (architecture and decision record)

    Runtime output directories (Logs, Reports, Baselines, ADAgent-Output)
    are never included even if they exist locally.

.EXAMPLE
    .\New-Release.ps1
    .\New-Release.ps1 -Force    # Overwrite existing zip for this version
#>

[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot   = $PSScriptRoot
$agentRoot  = Join-Path $repoRoot "ADRemediationAgent"
$configPath = Join-Path $agentRoot "Config\AgentConfig.psd1"
$releasesDir = Join-Path $repoRoot "Releases"

# -----------------------------------------------------------------------
# Read version from config
# -----------------------------------------------------------------------
if (-not (Test-Path $configPath)) {
    Write-Error "Config not found: $configPath"
}

$configContent = Get-Content $configPath -Raw
if ($configContent -notmatch 'AgentVersion\s*=\s*"([^"]+)"') {
    Write-Error "AgentVersion not found in $configPath"
}
$version = $Matches[1]

$zipName = "ADRemediationAgent-v$version.zip"
$zipPath = Join-Path $releasesDir $zipName

Write-Host ""
Write-Host "  AD Remediation Agent -- Release Packager" -ForegroundColor Cyan
Write-Host "  Version : $version" -ForegroundColor White
Write-Host "  Output  : $zipPath" -ForegroundColor White
Write-Host ""

# -----------------------------------------------------------------------
# Guard: don't overwrite without -Force
# -----------------------------------------------------------------------
if (Test-Path $zipPath) {
    if (-not $Force) {
        Write-Error "$zipName already exists. Use -Force to overwrite."
    }
    Remove-Item $zipPath -Force
    Write-Host "  [!] Existing zip removed (Force)" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# Create Releases folder if needed
# -----------------------------------------------------------------------
if (-not (Test-Path $releasesDir)) {
    New-Item -Path $releasesDir -ItemType Directory | Out-Null
    Write-Host "  [+] Created Releases\" -ForegroundColor Gray
}

# -----------------------------------------------------------------------
# Stage clean copy in temp folder
# -----------------------------------------------------------------------
$stagingRoot = Join-Path $env:TEMP "ADRemAgent-Release-$(Get-Date -Format 'yyyyMMddHHmmss')"
$stagingAgent = Join-Path $stagingRoot "ADRemediationAgent"

Write-Host "  Staging files..." -ForegroundColor Gray
New-Item -Path $stagingRoot -ItemType Directory | Out-Null

# Directories to exclude from the agent folder (runtime output)
$excludeDirs = @("ADAgent-Output", "Logs", "Reports", "Baselines", "GPOBackup*")

# Copy ADRemediationAgent\ recursively, skipping runtime dirs
Get-ChildItem -Path $agentRoot -Recurse | ForEach-Object {
    $relative = $_.FullName.Substring($agentRoot.Length).TrimStart('\')

    # Skip any path that starts with an excluded directory name
    $skip = $false
    foreach ($pattern in $excludeDirs) {
        if ($relative -like "$pattern*") { $skip = $true; break }
    }
    if ($skip) { return }

    $destPath = Join-Path $stagingAgent $relative

    if ($_.PSIsContainer) {
        New-Item -Path $destPath -ItemType Directory -Force | Out-Null
    } else {
        $destDir = Split-Path $destPath -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }
        Copy-Item -Path $_.FullName -Destination $destPath -Force
    }
}

# Copy DESIGN_DECISIONS.md to staging root
$ddSrc = Join-Path $repoRoot "DESIGN_DECISIONS.md"
if (Test-Path $ddSrc) {
    Copy-Item -Path $ddSrc -Destination (Join-Path $stagingRoot "DESIGN_DECISIONS.md")
}

# Count staged files
$stagedFiles = @(Get-ChildItem -Path $stagingRoot -Recurse -File)
Write-Host "  Staged $($stagedFiles.Count) file(s)" -ForegroundColor Gray

# -----------------------------------------------------------------------
# Compress
# -----------------------------------------------------------------------
Write-Host "  Compressing to $zipName..." -ForegroundColor Gray
Compress-Archive -Path "$stagingRoot\*" -DestinationPath $zipPath

# -----------------------------------------------------------------------
# Cleanup staging
# -----------------------------------------------------------------------
Remove-Item -Path $stagingRoot -Recurse -Force

$zipSize = [math]::Round((Get-Item $zipPath).Length / 1KB, 1)
Write-Host ""
Write-Host "  [OK] $zipName  ($zipSize KB)" -ForegroundColor Green
Write-Host ""
