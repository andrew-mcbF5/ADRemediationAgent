<#
.SYNOPSIS
    Write-AgentLog - Structured log writer for the AD Remediation Agent.

    Writes to:
      - The per-run log file  ($Global:AgentLogPath)
      - Console (colour-coded by level)

    Log format (CSV-compatible):
      Timestamp | RunId | Level | Milestone | Message
#>

function Write-AgentLog {
    [CmdletBinding()]
    param(
        [ValidateSet("INFO","WARN","ERROR","ACTION","FINDING","APPROVED","DENIED","BASELINE")]
        [string]$Level = "INFO",

        [string]$Message,

        [string]$Milestone = "AGENT",

        [PSObject]$Data = $null
    )

    $ts      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $runId   = if ($Global:AgentRunId)  { $Global:AgentRunId }  else { "UNKNOWN" }
    $logPath = if ($Global:AgentLogPath){ $Global:AgentLogPath } else { $null }

    # Colour map
    $colour = switch ($Level) {
        "INFO"     { "Cyan" }
        "WARN"     { "Yellow" }
        "ERROR"    { "Red" }
        "ACTION"   { "Magenta" }
        "FINDING"  { "Yellow" }
        "APPROVED" { "Green" }
        "DENIED"   { "DarkYellow" }
        "BASELINE" { "Magenta" }
        default    { "White" }
    }

    # Console output (indented under milestone header)
    $prefix = "  [{0,-8}]" -f $Level
    Write-Host "$prefix $Message" -ForegroundColor $colour

    # File output
    if ($logPath) {
        $logDir = Split-Path $logPath
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory $logDir -Force | Out-Null }

        $dataJson = if ($Data) { $Data | ConvertTo-Json -Compress -Depth 3 } else { "" }

        $line = '"{0}","{1}","{2}","{3}","{4}","{5}"' -f `
            $ts, $runId, $Level, $Milestone, $Message, $dataJson

        # Write CSV header if file is new
        if (-not (Test-Path $logPath)) {
            '"Timestamp","RunId","Level","Milestone","Message","Data"' | Out-File -FilePath $logPath -Encoding UTF8
        }

        $line | Out-File -FilePath $logPath -Append -Encoding UTF8
    }
}
