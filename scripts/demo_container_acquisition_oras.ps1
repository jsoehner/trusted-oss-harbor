<#
.SYNOPSIS
    Interactive PowerShell demo showing all HTTP requests/responses and ORAS CLI calls
    for acquiring an uncached container artifact from the Trusted OSS Harbor & Gatekeeper registry.

.DESCRIPTION
    Supports docs/reports/container-artifact-acquisition-and-oras-verification.md by printing
    every HTTP request, status code, relevant response headers, JSON payload previews, and
    ORAS CLI command/output across the full lifecycle:
      Stage 0: Registry health & OCI v2 conformance check (/healthz, /v2/)
      Stage 1: Pull-through manifest request with 15-second retry timer on HTTP 451
      Stage 2: Re-request via ORAS (resolve, manifest fetch, discover, blob fetch for SBOM & CBOM)
      Stage 3: Public key & detached signature inspection (GPG .asc + NIST FIPS 204 ML-DSA-65 .mldsa65)
      Stage 4: Vulnerability scan, advisories & HMAC-SHA384 provenance ledger verification
      Stage 5: 6-Gate Approval Summary

.EXAMPLE
    .\scripts\demo_container_acquisition_oras.ps1 "chainguard/jre:latest"

.EXAMPLE
    .\scripts\demo_container_acquisition_oras.ps1 "chainguard/jre:latest" -Detailed

.EXAMPLE
    .\scripts\demo_container_acquisition_oras.ps1 -Image "chainguard/python:latest" -RegistryHost "192.168.100.50:8080" -KeepProofDir

.EXAMPLE
    .\scripts\demo_container_acquisition_oras.ps1 "apache/airflow:slim-latest-python3.12" -Namespace "docker-cache" -Detailed -TranscriptPath ".\demo-output.log"
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Alias("Artifact", "RepoTag")]
    [string]$Image = "chainguard/jre:latest",
    [string]$RegistryHost = "oss.jsigroup.local:8080",
    [ValidateSet("http", "https")]
    [string]$Scheme = "http",
    [string]$Namespace = "",
    [int]$MaxRetries = 5,
    [int]$RetryDelaySeconds = 15,
    [string]$ProofDir = "",
    [switch]$KeepProofDir,
    [Alias("FullOutput", "ShowAll")]
    [switch]$Detailed,
    [switch]$ShowHeaders,
    [string]$TranscriptPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($PSBoundParameters.Count -eq 0) {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor DarkCyan
    Write-Host "  Trusted OSS Registry — Container Acquisition & ORAS Verification Demo" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor DarkCyan
    Write-Host "No parameters supplied. Provide an image in '<repo>:<tag>' format to run the demo." -ForegroundColor Yellow
    Write-Host "Namespace is auto-derived from the repo prefix + '-cache' unless -Namespace is set." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor White
    Write-Host "  .\scripts\demo_container_acquisition_oras.ps1 <repo>:<tag> [Options]" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor White
    Write-Host "  # Auto-derives Namespace = 'chainguard-cache'" -ForegroundColor DarkGray
    Write-Host "  .\scripts\demo_container_acquisition_oras.ps1 `"chainguard/jre:latest`"" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Verbose/detailed mode: full untruncated SBOM/CBOM/vuln/provenance JSON (add -ShowHeaders for all HTTP headers & ORAS --debug)" -ForegroundColor DarkGray
    Write-Host "  .\scripts\demo_container_acquisition_oras.ps1 `"chainguard/jre:latest`" -Detailed" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Target a specific registry host and keep downloaded SBOM/CBOM/signature proofs" -ForegroundColor DarkGray
    Write-Host "  .\scripts\demo_container_acquisition_oras.ps1 -Image `"chainguard/python:latest`" -RegistryHost `"192.168.100.50:8080`" -KeepProofDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Override namespace explicitly and save the full request/response transcript" -ForegroundColor DarkGray
    Write-Host "  .\scripts\demo_container_acquisition_oras.ps1 `"apache/airflow:slim-latest-python3.12`" -Namespace `"docker-cache`" -Detailed -TranscriptPath `".\demo-output.log`"" -ForegroundColor Green
    Write-Host ""
    exit 0
}

$script:TranscriptWriter = $null
$script:AnsiEsc = [char]27
$script:AnsiReset = "$($script:AnsiEsc)[0m"
$script:AnsiColorMap = @{
    "Black"       = "$($script:AnsiEsc)[30m"
    "DarkRed"     = "$($script:AnsiEsc)[31m"
    "DarkGreen"   = "$($script:AnsiEsc)[32m"
    "DarkYellow"  = "$($script:AnsiEsc)[33m"
    "DarkBlue"    = "$($script:AnsiEsc)[34m"
    "DarkMagenta" = "$($script:AnsiEsc)[35m"
    "DarkCyan"    = "$($script:AnsiEsc)[36m"
    "Gray"        = "$($script:AnsiEsc)[37m"
    "DarkGray"    = "$($script:AnsiEsc)[90m"
    "Red"         = "$($script:AnsiEsc)[91m"
    "Green"       = "$($script:AnsiEsc)[92m"
    "Yellow"      = "$($script:AnsiEsc)[93m"
    "Blue"        = "$($script:AnsiEsc)[94m"
    "Magenta"     = "$($script:AnsiEsc)[95m"
    "Cyan"        = "$($script:AnsiEsc)[96m"
    "White"       = "$($script:AnsiEsc)[97m"
}

if ($TranscriptPath) {
    $resolvedTranscriptPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TranscriptPath)
    $transcriptDir = Split-Path -Parent $resolvedTranscriptPath
    if ($transcriptDir -and -not (Test-Path $transcriptDir)) {
        New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
    }
    $script:TranscriptWriter = New-Object System.IO.StreamWriter($resolvedTranscriptPath, $false, [System.Text.UTF8Encoding]::new($false))
    $script:TranscriptWriter.AutoFlush = $true
    $script:TranscriptWriter.WriteLine("$($script:AnsiColorMap['DarkGray'])**********************$($script:AnsiReset)")
    $script:TranscriptWriter.WriteLine("$($script:AnsiColorMap['DarkGray'])ANSI Color Transcript Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')$($script:AnsiReset)")
    $script:TranscriptWriter.WriteLine("$($script:AnsiColorMap['DarkGray'])Host: $env:COMPUTERNAME | User: $env:USERNAME | PS: $($PSVersionTable.PSVersion)$($script:AnsiReset)")
    $script:TranscriptWriter.WriteLine("$($script:AnsiColorMap['DarkGray'])**********************$($script:AnsiReset)")
}

function Write-Host {
    <#
    .SYNOPSIS
        Script-scoped Write-Host wrapper that preserves console colors AND writes
        matching ANSI SGR color escape codes to -TranscriptPath when enabled.
    #>
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        $Object = "",
        [switch]$NoNewline,
        [ConsoleColor]$ForegroundColor,
        [ConsoleColor]$BackgroundColor
    )

    $text = if ($null -eq $Object) { "" } else { [string]$Object }

    $whParams = @{ Object = $text }
    if ($NoNewline) { $whParams["NoNewline"] = $true }
    if ($PSBoundParameters.ContainsKey("ForegroundColor")) { $whParams["ForegroundColor"] = $ForegroundColor }
    if ($PSBoundParameters.ContainsKey("BackgroundColor")) { $whParams["BackgroundColor"] = $BackgroundColor }
    Microsoft.PowerShell.Utility\Write-Host @whParams

    if ($null -ne $script:TranscriptWriter) {
        # Skip transient carriage-return countdown overwrites in the persistent log file
        if ($NoNewline -and $text.StartsWith("`r")) {
            return
        }
        $cleanText = $text.TrimStart("`r")
        $ansiLine = if ($PSBoundParameters.ContainsKey("ForegroundColor") -and $script:AnsiColorMap.ContainsKey($ForegroundColor.ToString())) {
            "$($script:AnsiColorMap[$ForegroundColor.ToString()])${cleanText}$($script:AnsiReset)"
        } else {
            $cleanText
        }
        if ($NoNewline) {
            $script:TranscriptWriter.Write($ansiLine)
        } else {
            $script:TranscriptWriter.WriteLine($ansiLine)
        }
    }
}

# ------------------------------------------------------------------------------
# Formatting & HTTP / CLI Helpers
# ------------------------------------------------------------------------------
function Write-Banner {
    param([string]$Title)
    $line = "=" * 80
    Write-Host ""
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ">>> $Title" -ForegroundColor Yellow
}

function Get-Prop {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) {
        return $Object.$Name
    }
    return $Default
}

function Format-JsonPreview {
    param(
        [string]$RawBody,
        [int]$MaxLines = 24
    )
    if ([string]::IsNullOrWhiteSpace($RawBody)) {
        return "<empty body>"
    }
    $trimmed = $RawBody.TrimStart()
    if ($trimmed.StartsWith("{") -or $trimmed.StartsWith("[")) {
        try {
            $obj = $RawBody | ConvertFrom-Json
            $pretty = $obj | ConvertTo-Json -Depth 10
        } catch {
            $pretty = $RawBody
        }
    } else {
        $pretty = $RawBody
    }
    $lines = $pretty -split "`r?`n"
    if (-not $script:Detailed -and $MaxLines -gt 0 -and $lines.Count -gt $MaxLines) {
        $shown = ($lines[0..($MaxLines - 1)] -join "`n")
        return "$shown`n... ($($lines.Count - $MaxLines) more lines truncated; pass -Detailed to show full body)"
    }
    return ($lines -join "`n")
}

function Write-JsonFilePreview {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$FilePath,
        [int]$MaxLines = 35
    )
    $raw = Get-Content -Path $FilePath -Raw
    $preview = Format-JsonPreview -RawBody $raw -MaxLines $MaxLines
    Write-Host "  [$Label]" -ForegroundColor DarkCyan
    foreach ($line in ($preview -split "`r?`n")) {
        Write-Host "             $line" -ForegroundColor Gray
    }
}

function Invoke-LoggedHttpRequest {
    <#
    .SYNOPSIS
        Executes an HTTP request and prints the request line, response status,
        key headers, and an optional formatted body preview. Works on PS 5.1 & PS 7+.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [switch]$ShowBodyPreview,
        [int]$MaxBodyLines = 20,
        [string]$OutFile = ""
    )

    Write-Host "  [REQUEST ] $Method $Uri" -ForegroundColor Blue
    foreach ($k in $Headers.Keys) {
        Write-Host "             Header: ${k}: $($Headers[$k])" -ForegroundColor DarkGray
    }

    $statusCode = 0
    $statusDesc = ""
    $respHeaders = @{}
    $bodyText = ""

    $isPs7 = $PSVersionTable.PSVersion.Major -ge 7

    try {
        $iwrParams = @{
            Uri        = $Uri
            Method     = $Method
            Headers    = $Headers
            TimeoutSec = 120
        }
        if (-not $isPs7) {
            $iwrParams["UseBasicParsing"] = $true
        } else {
            $iwrParams["SkipHttpErrorCheck"] = $true
        }

        $resp = Invoke-WebRequest @iwrParams
        $statusCode = [int]$resp.StatusCode
        $statusDesc = [string]$resp.StatusDescription
        foreach ($hk in $resp.Headers.Keys) {
            $val = $resp.Headers[$hk]
            if ($val -is [System.Array]) { $val = ($val -join ", ") }
            $respHeaders[$hk.ToLowerInvariant()] = [string]$val
        }
        if ($resp.Content -is [byte[]]) {
            $bodyText = [System.Text.Encoding]::UTF8.GetString($resp.Content)
        } else {
            $bodyText = [string]$resp.Content
        }
        if ($OutFile -and $statusCode -eq 200) {
            if ($resp.Content -is [byte[]]) {
                [System.IO.File]::WriteAllBytes($OutFile, $resp.Content)
            } elseif ($resp.RawContentStream -and $resp.RawContentStream.Length -gt 0) {
                $resp.RawContentStream.Position = 0
                $fs = [System.IO.File]::Create($OutFile)
                try { $resp.RawContentStream.CopyTo($fs) } finally { $fs.Dispose() }
            } else {
                [System.IO.File]::WriteAllText($OutFile, $bodyText, [System.Text.UTF8Encoding]::new($false))
            }
        }
    } catch {
        $exResp = $_.Exception.Response
        if ($null -ne $exResp) {
            $statusCode = [int]$exResp.StatusCode
            try { $statusDesc = [string]$exResp.StatusDescription } catch { $statusDesc = "" }
            try {
                foreach ($hk in $exResp.Headers.AllKeys) {
                    $respHeaders[$hk.ToLowerInvariant()] = [string]$exResp.Headers[$hk]
                }
            } catch {}
            try {
                $stream = $exResp.GetResponseStream()
                if ($null -ne $stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $bodyText = $reader.ReadToEnd()
                    $reader.Dispose()
                }
            } catch {}
        } else {
            Write-Host "  [ERROR   ] Connection failed: $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }

    $color = if ($statusCode -ge 200 -and $statusCode -lt 300) {
        "Green"
    } elseif ($statusCode -eq 451) {
        "Magenta"
    } else {
        "Red"
    }

    $metaParts = @()
    if ($respHeaders.ContainsKey("x-cache-status") -and -not [string]::IsNullOrWhiteSpace($respHeaders["x-cache-status"])) {
        $metaParts += "cache: $($respHeaders['x-cache-status'])"
    }
    if ($respHeaders.ContainsKey("content-length") -and -not [string]::IsNullOrWhiteSpace($respHeaders["content-length"])) {
        $metaParts += "$($respHeaders['content-length']) bytes"
    }
    if ($respHeaders.ContainsKey("content-type") -and -not [string]::IsNullOrWhiteSpace($respHeaders["content-type"])) {
        $metaParts += $respHeaders["content-type"]
    }
    $metaSuffix = if ($metaParts.Count -gt 0) { " ($($metaParts -join ' | '))" } else { "" }

    Write-Host "  [RESPONSE] HTTP $statusCode $statusDesc$metaSuffix" -ForegroundColor $color

    if ($OutFile -and $statusCode -eq 200 -and (Test-Path $OutFile)) {
        $fi = Get-Item -Path $OutFile
        $dlSha = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host "  [DOWNLOAD] $($fi.Name) ($($fi.Length) bytes | sha256:$($dlSha.Substring(0, 12))...) -> $OutFile" -ForegroundColor DarkGreen
    }

    if ($script:ShowHeaders) {
        foreach ($hk in ($respHeaders.Keys | Sort-Object)) {
            if (-not [string]::IsNullOrWhiteSpace($respHeaders[$hk])) {
                Write-Host "             ${hk}: $($respHeaders[$hk])" -ForegroundColor DarkGray
            }
        }
    }

    if ($ShowBodyPreview) {
        $preview = Format-JsonPreview -RawBody $bodyText -MaxLines $MaxBodyLines
        Write-Host "  [BODY    ]" -ForegroundColor DarkCyan
        foreach ($line in ($preview -split "`r?`n")) {
            Write-Host "             $line" -ForegroundColor Gray
        }
    }

    return [PSCustomObject]@{
        StatusCode = $statusCode
        Headers    = $respHeaders
        Body       = $bodyText
    }
}

function Invoke-LoggedCli {
    <#
    .SYNOPSIS
        Logs and executes an external CLI command (e.g., oras, gpg, python),
        printing its command line and captured output.
    #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowNonZeroExit
    )

    $displayCmd = "$Command " + (($Arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join " ")
    Write-Host "  [CLI CMD ] $displayCmd" -ForegroundColor Blue

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Command @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }

    $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        Write-Host "  [CLI OUT ]" -ForegroundColor DarkCyan
        foreach ($line in ($text -split "`r?`n")) {
            Write-Host "             $line" -ForegroundColor Gray
        }
    }

    if ($exitCode -ne 0 -and -not $AllowNonZeroExit) {
        throw "Command exited with code ${exitCode}: $displayCmd"
    }

    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output   = $text
    }
}

# ------------------------------------------------------------------------------
# Initialization & URL Resolution
# ------------------------------------------------------------------------------
$trimmedImage = $Image.Trim().TrimStart("/")
if ([string]::IsNullOrWhiteSpace($trimmedImage)) {
    throw "Parameter -Image cannot be empty. Expected format: '<repo>:<tag>' (e.g., 'chainguard/jre:latest')."
}

if ($trimmedImage -match '^([^@]+)@(sha256:[a-fA-F0-9]{64})$') {
    $Repo = $Matches[1]
    $Tag = $Matches[2]
    $RefSeparator = "@"
} elseif ($trimmedImage -match '^(.+):([^:/]+)$') {
    $Repo = $Matches[1]
    $Tag = $Matches[2]
    $RefSeparator = ":"
} else {
    $Repo = $trimmedImage
    $Tag = "latest"
    $RefSeparator = ":"
}

$NamespaceSource = "explicit"
if ([string]::IsNullOrWhiteSpace($Namespace)) {
    $repoBase = ($Repo -split "/")[0].ToLowerInvariant()
    $Namespace = if ($repoBase.EndsWith("-cache")) { $repoBase } else { "${repoBase}-cache" }
    $NamespaceSource = "auto-derived from repo '$repoBase'"
}

$RegistryUrl = "${Scheme}://${RegistryHost}"
[string[]]$OrasCommonArgs = if ($Scheme -eq "http") { @("--plain-http") } else { @() }
[string[]]$OrasVerboseArgs = if ($ShowHeaders) { @($OrasCommonArgs) + @("--debug") } else { @($OrasCommonArgs) }

if ($Namespace -eq "chainguard-cache") {
    $ManifestUrl = "${RegistryUrl}/v2/chainguard-cache/${Repo}/manifests/${Tag}"
    $OrasPullRef = "${RegistryHost}/chainguard-cache/${Repo}${RefSeparator}${Tag}"
} else {
    $ManifestUrl = "${RegistryUrl}/v2/virtual/${Namespace}/${Repo}/manifests/${Tag}"
    $OrasPullRef = "${RegistryHost}/virtual/${Namespace}/${Repo}${RefSeparator}${Tag}"
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$PqcVerifyScript = Join-Path (Join-Path $RepoRoot "client-templates") "pqc-verify.py"

$CreatedTempDir = $false
if ([string]::IsNullOrWhiteSpace($ProofDir)) {
    $tempRoot = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
    $ProofDir = Join-Path $tempRoot ("trusted-oss-demo-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    $CreatedTempDir = $true
}
New-Item -ItemType Directory -Path $ProofDir -Force | Out-Null

$Gates = [ordered]@{
    ManifestPromoted   = "PENDING"
    SbomVerified       = "PENDING"
    CbomVerified       = "PENDING"
    SignaturesVerified = "PENDING"
    VulnScanClean      = "PENDING"
    AdvisoriesClean    = "PENDING"
}

try {
    Write-Banner "TRUSTED OSS REGISTRY — CONTAINER ACQUISITION & ORAS VERIFICATION DEMO"
    Write-Host "  Registry URL  : $RegistryUrl" -ForegroundColor White
    Write-Host "  Namespace     : $Namespace ($NamespaceSource)" -ForegroundColor White
    Write-Host "  Target Image  : ${Namespace}/${Repo}${RefSeparator}${Tag}" -ForegroundColor White
    Write-Host "  Manifest URL  : $ManifestUrl" -ForegroundColor White
    Write-Host "  451 Retry     : Up to $MaxRetries attempts, ${RetryDelaySeconds}s timer between retries" -ForegroundColor White
    $modeText = if ($Detailed -and $ShowHeaders) {
        "DETAILED + HEADERS (full JSON, all HTTP headers, ORAS --debug)"
    } elseif ($Detailed) {
        "DETAILED (full JSON bodies, compact headers; pass -ShowHeaders for raw headers & ORAS --debug)"
    } elseif ($ShowHeaders) {
        "STANDARD + HEADERS (JSON previews, all HTTP headers, ORAS --debug)"
    } else {
        "STANDARD (compact headers, JSON previews; pass -Detailed for full JSON, -ShowHeaders for raw headers)"
    }
    Write-Host "  Output Mode   : $modeText" -ForegroundColor White
    Write-Host "  Proof Dir     : $ProofDir" -ForegroundColor White

    # Verify oras is available before starting
    $orasCmd = Get-Command oras -ErrorAction SilentlyContinue
    if ($null -eq $orasCmd) {
        Write-Host ""
        Write-Host "  [WARN] 'oras' CLI was not found on PATH. Install via 'winget install ORASProject.ORAS' (Windows) or 'brew install oras' (macOS/Linux)." -ForegroundColor Yellow
        Write-Host "         Stage 2 will require 'oras' to run ORAS discovery & blob fetch." -ForegroundColor Yellow
    } else {
        $orasVer = (& oras version 2>&1 | Select-String "Version:" | Select-Object -First 1)
        Write-Host "  ORAS CLI      : $($orasVer.ToString().Trim())" -ForegroundColor White
    }

    # --------------------------------------------------------------------------
    # STAGE 0: Health & OCI v2 Conformance Check
    # --------------------------------------------------------------------------
    Write-Banner "STAGE 0 — REGISTRY HEALTH & OCI V2 CONFORMANCE CHECK"
    Write-Section "0.1 Gatekeeper Liveness & Signing Authority Readiness"
    $null = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/healthz" -ShowBodyPreview -MaxBodyLines 12

    Write-Section "0.2 OCI Distribution Spec v2 Root Probe"
    $null = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/v2/" -ShowBodyPreview -MaxBodyLines 10

    # --------------------------------------------------------------------------
    # STAGE 1: Uncached Container Pull-Through + 15-Second Timer Loop on HTTP 451
    # --------------------------------------------------------------------------
    Write-Banner "STAGE 1 — PULL-THROUGH REQUEST & 15s TIMER RETRY LOOP ON HTTP 451"
    $acquired = $false
    $probeFile = Join-Path $ProofDir "manifest-probe.json"

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-Section "1.$attempt Requesting Manifest (Attempt $attempt of $MaxRetries)"
        $resp = Invoke-LoggedHttpRequest -Uri $ManifestUrl -ShowBodyPreview -MaxBodyLines 14 -OutFile $probeFile

        if ($resp.StatusCode -eq 200) {
            Write-Host "  [PASS] Artifact promoted and available (HTTP 200 OK)." -ForegroundColor Green
            $acquired = $true
            $Gates.ManifestPromoted = "PASS (HTTP 200)"
            break
        } elseif ($resp.StatusCode -eq 451) {
            Write-Host "  [WAIT] HTTP 451 Unavailable For Legal Reasons — Artifact is quarantined / being scanned & signed." -ForegroundColor Magenta
            if ($attempt -lt $MaxRetries) {
                Write-Host "  [TIMER] Waiting ${RetryDelaySeconds} seconds before retrying..." -ForegroundColor Yellow
                for ($sec = $RetryDelaySeconds; $sec -gt 0; $sec--) {
                    Write-Host -NoNewline "`r          Retrying in ${sec}s...   " -ForegroundColor DarkYellow
                    Start-Sleep -Seconds 1
                }
                Write-Host "`r          Timer elapsed. Re-sending request...   " -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [FAIL] Unexpected HTTP $($resp.StatusCode). Stopping demo." -ForegroundColor Red
            $Gates.ManifestPromoted = "FAIL (HTTP $($resp.StatusCode))"
            exit 1
        }
    }

    if (-not $acquired) {
        $Gates.ManifestPromoted = "BLOCKED (HTTP 451 after $MaxRetries attempts)"
        Write-Section "1.D Diagnosing Persistent HTTP 451 via /audit/activity & /catalog/vulnerabilities"
        $null = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/audit/activity?limit=10" -ShowBodyPreview -MaxBodyLines 25
        $null = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/catalog/vulnerabilities?ecosystem=oci&components=${Repo}" -ShowBodyPreview -MaxBodyLines 25
        throw "Artifact remained HTTP 451 after $MaxRetries attempts (likely permanently blocked by ClamAV or CVSS >= 7.0)."
    }

    # --------------------------------------------------------------------------
    # STAGE 2: Re-Request with ORAS & Verify SBOM / CBOM via OCI 1.1 Referrers
    # --------------------------------------------------------------------------
    Write-Banner "STAGE 2 — RE-REQUEST VIA ORAS & VERIFY SBOM + CBOM (OCI 1.1 REFERRERS)"
    if ($null -eq $orasCmd) {
        throw "The 'oras' CLI is required for Stage 2. Install via 'winget install ORASProject.ORAS' (Windows) or 'brew install oras' (macOS/Linux) and re-run."
    }

    Write-Section "2.1 Resolve Immutable Manifest Digest via ORAS"
    $resolveRes = Invoke-LoggedCli -Command "oras" -Arguments (@("resolve") + $OrasVerboseArgs + @($OrasPullRef))
    $ManifestDigest = ($resolveRes.Output -split "`r?`n" | Where-Object { $_ -match "^sha256:" } | Select-Object -Last 1).Trim()
    if (-not $ManifestDigest) {
        throw "Failed to parse sha256 digest from 'oras resolve' output."
    }
    Write-Host "  Pinned Digest : $ManifestDigest" -ForegroundColor Green

    Write-Section "2.2 Fetch Signed Manifest via ORAS & Verify Local SHA-256"
    $ManifestFile = Join-Path $ProofDir "manifest.json"
    $null = Invoke-LoggedCli -Command "oras" -Arguments (@("manifest", "fetch") + $OrasVerboseArgs + @("--output", $ManifestFile, $OrasPullRef))
    $actualManifestSha = "sha256:" + (Get-FileHash -Path $ManifestFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualManifestSha -ne $ManifestDigest) {
        throw "Manifest SHA-256 mismatch! Expected $ManifestDigest, got $actualManifestSha"
    }
    $mfInfo = Get-Item -Path $ManifestFile
    Write-Host "  [DOWNLOAD] $($mfInfo.Name) ($($mfInfo.Length) bytes | $actualManifestSha) -> $ManifestFile" -ForegroundColor DarkGreen
    Write-Host "  [PASS] Local manifest.json matches resolved digest ($actualManifestSha)." -ForegroundColor Green

    $OrasReferrerRef = "${RegistryHost}/${Namespace}/${Repo}@${ManifestDigest}"

    Write-Section "2.3 Discover Attached CycloneDX 1.6 Referrers (Tree View)"
    $null = Invoke-LoggedCli -Command "oras" -Arguments (@("discover") + $OrasVerboseArgs + @("--artifact-type", "application/vnd.cyclonedx+json", "--format", "tree", $OrasReferrerRef))

    Write-Section "2.4 Discover Attached CycloneDX 1.6 Referrers (Machine-Readable JSON)"
    $discoverJsonRes = Invoke-LoggedCli -Command "oras" -Arguments (@("discover") + $OrasCommonArgs + @("--artifact-type", "application/vnd.cyclonedx+json", "--format", "json", $OrasReferrerRef))
    $referrersObj = $discoverJsonRes.Output | ConvertFrom-Json

    $referrerList = @()
    if ($referrersObj.PSObject.Properties['referrers'] -and $null -ne $referrersObj.referrers) {
        $referrerList = @($referrersObj.referrers)
    }

    if ($referrerList.Count -eq 0) {
        Write-Host "  [NOTE] 'oras discover' returned 0 referrers (oras v1.4+ requires Content-Type: application/vnd.oci.image.index.v1+json on /referrers/)." -ForegroundColor DarkYellow
        Write-Host "         Querying OCI 1.1 Referrers API directly and continuing with 'oras blob fetch'..." -ForegroundColor DarkYellow
        $referrersUrl = "${RegistryUrl}/v2/${Namespace}/${Repo}/referrers/${ManifestDigest}?artifactType=application/vnd.cyclonedx%2Bjson"
        $refHttpResp = Invoke-LoggedHttpRequest -Uri $referrersUrl -ShowBodyPreview -MaxBodyLines 30
        if ($refHttpResp.StatusCode -eq 200 -and -not [string]::IsNullOrWhiteSpace($refHttpResp.Body)) {
            $refIndexObj = $refHttpResp.Body | ConvertFrom-Json
            if ($refIndexObj.PSObject.Properties['manifests'] -and $null -ne $refIndexObj.manifests) {
                $referrerList = @($refIndexObj.manifests)
            }
        }
    }

    $sbomDesc = $referrerList | Where-Object { $_.annotations.'io.cyclonedx.type' -eq 'sbom' } | Select-Object -First 1
    $cbomDesc = $referrerList | Where-Object { $_.annotations.'io.cyclonedx.type' -eq 'cbom' } | Select-Object -First 1

    if ($null -eq $sbomDesc -or $null -eq $cbomDesc) {
        $Gates.SbomVerified = if ($null -ne $sbomDesc) { "FOUND" } else { "MISSING" }
        $Gates.CbomVerified = if ($null -ne $cbomDesc) { "FOUND" } else { "MISSING" }
        throw "Missing required SBOM or CBOM OCI 1.1 referrer descriptor for $OrasReferrerRef"
    }

    $SbomDigest = $sbomDesc.digest
    $CbomDigest = $cbomDesc.digest
    $SbomFile = Join-Path $ProofDir "sbom.cdx.json"
    $CbomFile = Join-Path $ProofDir "cbom.cdx.json"

    Write-Section "2.5 Fetch SBOM & CBOM Blobs via ORAS and Verify SHA-256 Digests"
    $null = Invoke-LoggedCli -Command "oras" -Arguments (@("blob", "fetch") + $OrasVerboseArgs + @("--output", $SbomFile, "${RegistryHost}/${Namespace}/${Repo}@${SbomDigest}"))
    $null = Invoke-LoggedCli -Command "oras" -Arguments (@("blob", "fetch") + $OrasVerboseArgs + @("--output", $CbomFile, "${RegistryHost}/${Namespace}/${Repo}@${CbomDigest}"))

    $actualSbomSha = "sha256:" + (Get-FileHash -Path $SbomFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $actualCbomSha = "sha256:" + (Get-FileHash -Path $CbomFile -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($actualSbomSha -ne $SbomDigest) { throw "SBOM SHA-256 mismatch! Expected $SbomDigest, got $actualSbomSha" }
    if ($actualCbomSha -ne $CbomDigest) { throw "CBOM SHA-256 mismatch! Expected $CbomDigest, got $actualCbomSha" }

    $sbomFi = Get-Item -Path $SbomFile
    $cbomFi = Get-Item -Path $CbomFile
    Write-Host "  [DOWNLOAD] $($sbomFi.Name) ($($sbomFi.Length) bytes | $actualSbomSha) -> $SbomFile" -ForegroundColor DarkGreen
    Write-Host "  [DOWNLOAD] $($cbomFi.Name) ($($cbomFi.Length) bytes | $actualCbomSha) -> $CbomFile" -ForegroundColor DarkGreen

    $sbomObj = Get-Content -Path $SbomFile -Raw | ConvertFrom-Json
    $cbomObj = Get-Content -Path $CbomFile -Raw | ConvertFrom-Json
    $sbomCompCount = if ($sbomObj.PSObject.Properties['components'] -and $null -ne $sbomObj.components) { @($sbomObj.components).Count } else { 0 }

    $cbomProps = @{}
    if ($cbomObj.metadata -and $cbomObj.metadata.properties) {
        foreach ($prop in $cbomObj.metadata.properties) {
            if ($prop.name) { $cbomProps[[string]$prop.name] = [string]$prop.value }
        }
    }

    $cbomStatus = if ($cbomProps.ContainsKey("trusted-oss:crypto-scan-status")) { $cbomProps["trusted-oss:crypto-scan-status"] } else { "UNKNOWN" }
    $cbomScope = if ($cbomProps.ContainsKey("trusted-oss:scan-scope")) { $cbomProps["trusted-oss:scan-scope"] } else { "legacy" }
    $riskLevel = if ($cbomProps.ContainsKey("trusted-oss:crypto-risk-level")) { $cbomProps["trusted-oss:crypto-risk-level"] } else { "UNKNOWN" }
    $activeRiskCount = if ($cbomProps.ContainsKey("trusted-oss:active-risk-count")) { [int]$cbomProps["trusted-oss:active-risk-count"] } else { 0 }
    $passiveRiskCount = if ($cbomProps.ContainsKey("trusted-oss:passive-risk-count")) { [int]$cbomProps["trusted-oss:passive-risk-count"] } else { 0 }
    $certTotal = if ($cbomProps.ContainsKey("trusted-oss:cert-total")) { [int]$cbomProps["trusted-oss:cert-total"] } else { 0 }
    $certExpired = if ($cbomProps.ContainsKey("trusted-oss:cert-expired")) { [int]$cbomProps["trusted-oss:cert-expired"] } else { 0 }
    $certExp90 = if ($cbomProps.ContainsKey("trusted-oss:cert-expiring-90d")) { [int]$cbomProps["trusted-oss:cert-expiring-90d"] } else { 0 }
    $certSha1Roots = if ($cbomProps.ContainsKey("trusted-oss:cert-sha1-roots")) { [int]$cbomProps["trusted-oss:cert-sha1-roots"] } else { 0 }
    $certWeakKeys = if ($cbomProps.ContainsKey("trusted-oss:cert-weak-keys")) { [int]$cbomProps["trusted-oss:cert-weak-keys"] } else { 0 }
    $pqcAdoption = if ($cbomProps.ContainsKey("trusted-oss:pqc-adoption-status")) { $cbomProps["trusted-oss:pqc-adoption-status"] } else { "UNKNOWN" }
    $pqcCompiledRisk = if ($cbomProps.ContainsKey("trusted-oss:pqc-compiled-risk")) { $cbomProps["trusted-oss:pqc-compiled-risk"] } else { "UNKNOWN" }
    $pqcCodingRisk = if ($cbomProps.ContainsKey("trusted-oss:pqc-coding-risk")) { $cbomProps["trusted-oss:pqc-coding-risk"] } else { "UNKNOWN" }

    $cryptoAssets = @()
    if ($cbomObj.PSObject.Properties['components'] -and $null -ne $cbomObj.components) {
        $cryptoAssets = @($cbomObj.components | Where-Object { $_.type -eq "cryptographic-asset" } | ForEach-Object { $_.name })
    }

    $isLegacyInertCbom = ($cbomStatus -eq "VERIFIED_INERT" -and ($riskLevel -eq "UNKNOWN" -or $cbomScope -eq "legacy"))
    $sbomBannerColor = if ($sbomCompCount -gt 0) { "Green" } else { "Yellow" }
    $sbomStatusTag = if ($sbomCompCount -gt 0) { "[PASS]" } else { "[WARN]" }
    Write-Host "  $sbomStatusTag SBOM Verified : $($sbomObj.bomFormat) $($sbomObj.specVersion) | SHA-256 OK | Components: $sbomCompCount" -ForegroundColor $sbomBannerColor
    Write-JsonFilePreview -Label "SBOM JSON" -FilePath $SbomFile -MaxLines 30

    $cbomBannerColor = if ($certExpired -gt 0 -or $certWeakKeys -gt 0) {
        "Red"
    } elseif ($cbomStatus -eq "MANIFEST_ONLY_UNINSPECTED" -or $isLegacyInertCbom -or $activeRiskCount -gt 0 -or $certSha1Roots -gt 0) {
        "Yellow"
    } else {
        "Green"
    }
    $assetPreview = if ($cryptoAssets.Count -gt 0) {
        $shownAssets = ($cryptoAssets | Select-Object -First 8) -join ', '
        if ($cryptoAssets.Count -gt 8) { "$shownAssets ... (+$($cryptoAssets.Count - 8) more)" } else { $shownAssets }
    } else {
        "none ($cbomStatus)"
    }
    Write-Host "  [CBOM] Verified : $($cbomObj.bomFormat) $($cbomObj.specVersion) | SHA-256 OK | Status: $cbomStatus (scope=$cbomScope) | Risk: $riskLevel | Assets: $assetPreview" -ForegroundColor $cbomBannerColor

    # Display core ORAS OCI 1.1 Referrer risk annotations if exposed by Gatekeeper
    if ($cbomDesc.annotations -and $cbomDesc.annotations.PSObject.Properties['trusted-oss.crypto.risk-level']) {
        Write-Host "  [ORAS REFERRER ANNOTATIONS]" -ForegroundColor Cyan
        Write-Host "    • Risk Level : $($cbomDesc.annotations.'trusted-oss.crypto.risk-level') (Active=$($cbomDesc.annotations.'trusted-oss.crypto.active-risks'), Passive=$($cbomDesc.annotations.'trusted-oss.crypto.passive-risks'))" -ForegroundColor Gray
        Write-Host "    • Certs      : total=$($cbomDesc.annotations.'trusted-oss.crypto.cert-total'), expired=$($cbomDesc.annotations.'trusted-oss.crypto.cert-expired'), sha1-roots=$($cbomDesc.annotations.'trusted-oss.crypto.cert-sha1-roots'), weak-keys=$($cbomDesc.annotations.'trusted-oss.crypto.cert-weak-keys')" -ForegroundColor Gray
        Write-Host "    • PQC Gap    : $($cbomDesc.annotations.'trusted-oss.crypto.pqc-adoption') (CompiledRisk=$($cbomDesc.annotations.'trusted-oss.crypto.compiled-risk'), CodingRisk=$($cbomDesc.annotations.'trusted-oss.crypto.coding-risk'))" -ForegroundColor Gray
    }

    Write-Section "2.6 Cryptographic Risk Posture: Active vs. Passive, Cert Hygiene & PQC Compiled vs. Coding"
    Write-Host "  • Scan Status / Scope : $cbomStatus [$cbomScope]" -ForegroundColor White
    Write-Host "  • Overall Risk Level  : $riskLevel (Active=$activeRiskCount, Passive=$passiveRiskCount)" -ForegroundColor $cbomBannerColor
    Write-Host "  • Truststore / Certs  : total=$certTotal | expired=$certExpired | expiring<=90d=$certExp90 | sha1-roots=$certSha1Roots | weak-keys=$certWeakKeys" -ForegroundColor $(if ($certExpired -gt 0) { "Red" } elseif ($certSha1Roots -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  • PQC Compiled vs Code: status=$pqcAdoption | compiled_risk=$pqcCompiledRisk | coding_risk=$pqcCodingRisk" -ForegroundColor $(if ($pqcAdoption -eq "PQC_COMPILED_BUT_UNUSED") { "Yellow" } elseif ($pqcAdoption -eq "PQC_COMPILED_AND_USED") { "Green" } else { "Cyan" })

    if ($cbomProps.ContainsKey("trusted-oss:risk-detail-json") -and $cbomProps["trusted-oss:risk-detail-json"]) {
        try {
            $detailObj = $cbomProps["trusted-oss:risk-detail-json"] | ConvertFrom-Json
            if ($detailObj.active_risks -and @($detailObj.active_risks).Count -gt 0) {
                Write-Host "  [ACTIVE RISKS]" -ForegroundColor Red
                foreach ($ar in $detailObj.active_risks) {
                    Write-Host "    - [$($ar.severity)] $($ar.id): $($ar.title) — $($ar.detail)" -ForegroundColor Red
                }
            }
            if ($detailObj.passive_risks -and @($detailObj.passive_risks).Count -gt 0) {
                Write-Host "  [PASSIVE RISKS]" -ForegroundColor Yellow
                foreach ($pr in $detailObj.passive_risks) {
                    Write-Host "    - [$($pr.severity)] $($pr.id): $($pr.title) — $($pr.detail)" -ForegroundColor Yellow
                }
            }
            if ($detailObj.pqc_ready_unused_libraries -and @($detailObj.pqc_ready_unused_libraries).Count -gt 0) {
                Write-Host "  [PQC-READY LIBRARIES UNUSED IN CODE (Coding Risk)]" -ForegroundColor Cyan
                foreach ($lib in $detailObj.pqc_ready_unused_libraries) {
                    Write-Host "    - $lib" -ForegroundColor Gray
                }
            }
        } catch {}
    }

    Write-JsonFilePreview -Label "CBOM JSON" -FilePath $CbomFile -MaxLines 30
    $Gates.SbomVerified = if ($sbomCompCount -gt 0) {
        "PASS ($sbomCompCount components)"
    } else {
        "WARN (0 components — legacy/uninspected layers; run POST /catalog/backfill-boms?force=true)"
    }
    if ($certExpired -gt 0 -or $certWeakKeys -gt 0) {
        $Gates.CbomVerified = "FAIL ($cbomStatus | risk=$riskLevel | expired=$certExpired | weak_keys=$certWeakKeys)"
    } elseif ($cbomStatus -eq "MANIFEST_ONLY_UNINSPECTED") {
        $Gates.CbomVerified = "WARN ($cbomStatus — layers not inspected)"
    } elseif ($isLegacyInertCbom) {
        $Gates.CbomVerified = "WARN (VERIFIED_INERT — legacy manifest-only CBOM; run POST /catalog/backfill-boms?force=true)"
    } elseif ($activeRiskCount -gt 0 -or $certSha1Roots -gt 0) {
        $Gates.CbomVerified = "WARN ($cbomStatus | risk=$riskLevel | active=$activeRiskCount passive=$passiveRiskCount sha1_roots=$certSha1Roots | $pqcAdoption)"
    } else {
        $Gates.CbomVerified = "PASS ($cbomStatus | risk=$riskLevel | $pqcAdoption)"
    }

    # --------------------------------------------------------------------------
    # STAGE 3: Public Keys & Detached Signatures (GPG .asc + ML-DSA-65 .mldsa65)
    # --------------------------------------------------------------------------
    Write-Banner "STAGE 3 — PUBLIC KEYS & DETACHED CRYPTOGRAPHIC SIGNATURES"
    Write-Section "3.1 Fetch Registry Public Signing Keys (RSA-3072 GPG & NIST FIPS 204 ML-DSA-65)"
    $GpgPubFile = Join-Path $ProofDir "trusted-oss-pubkey.asc"
    $PqcPubFile = Join-Path $ProofDir "trusted-oss-mldsa65.pub"
    $null = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/keys/trusted-oss-pubkey.asc" -OutFile $GpgPubFile
    $null = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/keys/trusted-oss-mldsa65.pub" -OutFile $PqcPubFile
    $null = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/keys/trusted-oss-mldsa65.fingerprint" -ShowBodyPreview -MaxBodyLines 5

    Write-Section "3.2 Fetch Detached Signatures (.asc & .mldsa65) for Manifest, SBOM & CBOM"
    $manifestBaseDirUrl = $ManifestUrl.Substring(0, $ManifestUrl.LastIndexOf("/"))

    # Match the exact manifest entry (tag vs digest) that produced the pulled SBOM/CBOM blobs
    $sbomArtPath = [string](($sbomObj.metadata.properties | Where-Object { $_.name -eq "trusted-oss:artifact-path" } | Select-Object -First 1).value)
    $cbomArtPath = [string](($cbomObj.metadata.properties | Where-Object { $_.name -eq "trusted-oss:artifact-path" } | Select-Object -First 1).value)
    $sbomRefUrl = if ($sbomArtPath -match '/manifests/([^/]+)$') { "${manifestBaseDirUrl}/$($Matches[1])" } else { $ManifestUrl }
    $cbomRefUrl = if ($cbomArtPath -match '/manifests/([^/]+)$') { "${manifestBaseDirUrl}/$($Matches[1])" } else { $ManifestUrl }

    $sigTargets = @(
        @{ Name = "manifest.json"; File = $ManifestFile; BaseUrl = $ManifestUrl; Suffix = "" },
        @{ Name = "sbom.cdx.json"; File = $SbomFile;     BaseUrl = $sbomRefUrl;  Suffix = ".sbom.cdx.json" },
        @{ Name = "cbom.cdx.json"; File = $CbomFile;     BaseUrl = $cbomRefUrl;  Suffix = ".cbom.cdx.json" }
    )

    $allSigsFetched = $true
    foreach ($t in $sigTargets) {
        $ascResp = Invoke-LoggedHttpRequest -Uri "$($t.BaseUrl)$($t.Suffix).asc" -OutFile "$($t.File).asc"
        $pqcResp = Invoke-LoggedHttpRequest -Uri "$($t.BaseUrl)$($t.Suffix).mldsa65" -OutFile "$($t.File).mldsa65"
        if ($ascResp.StatusCode -ne 200 -or $pqcResp.StatusCode -ne 200) {
            $allSigsFetched = $false
        }
    }

    $sigVerifiedParts = @()
    $gpgCmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($null -ne $gpgCmd -and $allSigsFetched) {
        Write-Section "3.3 Local Classical GPG (RSA-3072) Verification"
        $gpgHome = Join-Path $ProofDir "gnupg"
        New-Item -ItemType Directory -Path $gpgHome -Force | Out-Null
        if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
            $chmodCmd = Get-Command chmod -ErrorAction SilentlyContinue
            if ($null -ne $chmodCmd) { & chmod 700 $gpgHome }
        }
        $prevGpgHome = $env:GNUPGHOME
        $env:GNUPGHOME = $gpgHome
        try {
            $null = Invoke-LoggedCli -Command "gpg" -Arguments @("--batch", "--quiet", "--import", $GpgPubFile)
            $fprLines = & gpg --batch --with-colons --fingerprint 2>$null
            $gpgFpr = ($fprLines | Where-Object { $_ -match '^fpr:' } | Select-Object -First 1)
            if ($gpgFpr) {
                $gpgFpr = ($gpgFpr -split ':')[9]
            }
            if ($gpgFpr) {
                "${gpgFpr}:6:" | & gpg --batch --quiet --import-ownertrust 2>$null
                & gpg --batch --quiet --check-trustdb 2>$null
                Write-Host "  [INFO] Imported GPG Public Key Fingerprint: $gpgFpr (trust: ultimate)" -ForegroundColor DarkGray
            }
            foreach ($t in $sigTargets) {
                $gpgRes = Invoke-LoggedCli -Command "gpg" -Arguments @("--batch", "--verify", "$($t.File).asc", $t.File) -AllowNonZeroExit
                if ($gpgRes.ExitCode -ne 0 -and $ManifestDigest) {
                    $origAscUrl = "$($t.BaseUrl)$($t.Suffix).asc"
                    $altAscUrl = "${manifestBaseDirUrl}/${ManifestDigest}$($t.Suffix).asc"
                    if ($altAscUrl -ne $origAscUrl) {
                        Write-Host "  [WARN] $origAscUrl failed GPG verification against active key (e.g., rotated historical key); retrying with digest-pinned $altAscUrl for identical bytes." -ForegroundColor Yellow
                        $altResp = Invoke-LoggedHttpRequest -Uri $altAscUrl -OutFile "$($t.File).asc"
                        if ($altResp.StatusCode -eq 200) {
                            $gpgRes = Invoke-LoggedCli -Command "gpg" -Arguments @("--batch", "--verify", "$($t.File).asc", $t.File) -AllowNonZeroExit
                        }
                    }
                }
                if ($gpgRes.ExitCode -ne 0) {
                    throw "GPG signature verification failed for $($t.Name) (exit code $($gpgRes.ExitCode))."
                }
            }
            $sigVerifiedParts += "GPG"
        } finally {
            $env:GNUPGHOME = $prevGpgHome
        }
    } else {
        Write-Host "  [INFO] Skipping local 'gpg --verify' (gpg not found on PATH)." -ForegroundColor DarkYellow
    }

    $pythonCandidates = @(
        (Join-Path (Join-Path (Join-Path $RepoRoot ".venv") "Scripts") "python.exe"),
        (Join-Path (Join-Path (Join-Path $RepoRoot ".venv") "bin") "python")
    )
    $pythonExe = ""
    foreach ($cand in $pythonCandidates) {
        if (Test-Path $cand) {
            $pythonExe = $cand
            break
        }
    }
    if (-not $pythonExe) {
        foreach ($cmdName in @("python3", "python")) {
            $pyCmd = Get-Command $cmdName -ErrorAction SilentlyContinue
            if ($null -ne $pyCmd) {
                $pythonExe = $pyCmd.Source
                break
            }
        }
    }

    if ($pythonExe -and (Test-Path $PqcVerifyScript) -and $allSigsFetched) {
        Write-Section "3.4 Local Post-Quantum NIST FIPS 204 (ML-DSA-65) Verification"
        $pqcPassed = 0
        $manifestBaseDirUrl = $ManifestUrl.Substring(0, $ManifestUrl.LastIndexOf("/"))
        foreach ($t in $sigTargets) {
            $res = Invoke-LoggedCli -Command $pythonExe -Arguments @($PqcVerifyScript, $t.File, "$($t.File).mldsa65", $PqcPubFile) -AllowNonZeroExit
            if ($res.ExitCode -ne 0 -and $ManifestDigest) {
                $origPqcUrl = "$($t.BaseUrl)$($t.Suffix).mldsa65"
                $altSigUrl = "${manifestBaseDirUrl}/${ManifestDigest}$($t.Suffix).mldsa65"
                if ($altSigUrl -ne $origPqcUrl) {
                    # Referrer blob or tag signature may belong to the digest-named manifest entry if both tag and digest are cached
                    $altResp = Invoke-LoggedHttpRequest -Uri $altSigUrl -OutFile "$($t.File).mldsa65"
                    if ($altResp.StatusCode -eq 200) {
                        $res = Invoke-LoggedCli -Command $pythonExe -Arguments @($PqcVerifyScript, $t.File, "$($t.File).mldsa65", $PqcPubFile) -AllowNonZeroExit
                    }
                }
            }
            if ($res.ExitCode -eq 0) {
                $pqcPassed++
            } else {
                Write-Host "  [WARN] PQC verification did not match for $($t.Name)." -ForegroundColor Yellow
            }
        }
        if ($pqcPassed -eq $sigTargets.Count) {
            $sigVerifiedParts += "ML-DSA-65 ($pqcPassed/$($sigTargets.Count))"
        } elseif ($pqcPassed -gt 0) {
            $sigVerifiedParts += "ML-DSA-65 ($pqcPassed/$($sigTargets.Count))"
        }
    }

    $Gates.SignaturesVerified = if ($sigVerifiedParts.Count -gt 0) {
        "PASS ($($sigVerifiedParts -join ' + '))"
    } elseif ($allSigsFetched) {
        "FETCHED (HTTP 200; install gpg/dilithium-py for offline verify)"
    } else {
        "FAIL"
    }

    # --------------------------------------------------------------------------
    # STAGE 4: Vulnerability Scan, Advisories & Provenance Ledger Verification
    # --------------------------------------------------------------------------
    Write-Banner "STAGE 4 — VULNERABILITY SCAN, ADVISORIES & PROVENANCE LEDGER"

    Write-Section "4.1 Live Vulnerability & Malware Posture (/catalog/vulnerabilities)"
    $vulnResp = Invoke-LoggedHttpRequest `
        -Uri "${RegistryUrl}/catalog/vulnerabilities?ecosystem=oci&components=${Repo}&verify_signatures=true" `
        -ShowBodyPreview -MaxBodyLines 30

    $vulnClean = $false
    if ($vulnResp.StatusCode -eq 200) {
        $vulnObj = $vulnResp.Body | ConvertFrom-Json
        $comp = $vulnObj.components | Select-Object -First 1
        if ($null -ne $comp) {
            $clamOk = $comp.clamav_status -in @("CLEAN", "CLAMD_OK", "OK")
            $vulnClean = $clamOk -and ($comp.vulnerability_status -eq "CLEAN") -and ([double]$comp.max_cvss -lt 7.0)
            $Gates.VulnScanClean = if ($vulnClean) {
                "PASS (ClamAV=$($comp.clamav_status), CVE=$($comp.vulnerability_status), CVSS=$($comp.max_cvss))"
            } else {
                "FAIL (ClamAV=$($comp.clamav_status), CVE=$($comp.vulnerability_status), CVSS=$($comp.max_cvss))"
            }
        } else {
            $Gates.VulnScanClean = "WARN (Component not listed in /catalog/vulnerabilities)"
        }
    }

    Write-Section "4.2 Active Security Advisories (/catalog/advisories)"
    $advResp = Invoke-LoggedHttpRequest `
        -Uri "${RegistryUrl}/catalog/advisories?ecosystem=oci&component=${Repo}" `
        -ShowBodyPreview -MaxBodyLines 20

    if ($advResp.StatusCode -eq 200) {
        $advObj = $advResp.Body | ConvertFrom-Json
        $advCount = [int]$advObj.count
        $Gates.AdvisoriesClean = if ($advCount -eq 0) { "PASS (0 active advisories)" } else { "FAIL ($advCount active advisories)" }
    }

    Write-Section "4.2b Catalog Cryptographic Risk Posture (/catalog/crypto-risk)"
    $cryptoResp = Invoke-LoggedHttpRequest `
        -Uri "${RegistryUrl}/catalog/crypto-risk?ecosystem=oci&components=${Repo}" `
        -ShowBodyPreview -MaxBodyLines 30
    if ($cryptoResp.StatusCode -eq 404) {
        Write-Host "  [INFO] /catalog/crypto-risk returned HTTP 404 (registry instance predates Gatekeeper v2.0 CBOM risk API)." -ForegroundColor DarkYellow
    }

    Write-Section "4.3 Tamper-Evident HMAC-SHA384 Provenance Ledger (/audit/provenance)"
    $provResp = Invoke-LoggedHttpRequest -Uri "${RegistryUrl}/audit/provenance?limit=500"
    if ($provResp.StatusCode -eq 200) {
        $provObj = $provResp.Body | ConvertFrom-Json
        $manifestHex = $ManifestDigest -replace "^sha256:", ""
        $match = $provObj.records | Where-Object { $_.sha256 -eq $manifestHex } | Select-Object -Last 1
        if ($null -ne $match) {
            Write-Host "  [MATCHED PROVENANCE RECORD]" -ForegroundColor Green
            if ($Detailed) {
                $prettyProv = $match | ConvertTo-Json -Depth 10
                foreach ($line in ($prettyProv -split "`r?`n")) {
                    Write-Host "             $line" -ForegroundColor Gray
                }
            } else {
                $hmacVal = [string](Get-Prop $match "attestation_hmac" "")
                $matchSummary = [PSCustomObject]@{
                    timestamp        = Get-Prop $match "timestamp" "n/a"
                    ecosystem        = Get-Prop $match "ecosystem" "n/a"
                    artifact         = Get-Prop $match "artifact" "n/a"
                    sha256           = Get-Prop $match "sha256" "n/a"
                    clamav_status    = Get-Prop $match "clamav_status" "n/a"
                    cve_status       = Get-Prop $match "cve_status" "n/a"
                    max_cvss         = Get-Prop $match "max_cvss" "n/a"
                    cbom_scan_status = Get-Prop $match "cbom_scan_status" "n/a"
                    pqc_status       = Get-Prop $match "pqc_status" "n/a"
                    attestation_hmac = if ($hmacVal) { $hmacVal.Substring(0, [Math]::Min(24, $hmacVal.Length)) + "..." } else { "n/a" }
                }
                $matchSummary | Format-List | Out-String | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
            }
        } else {
            Write-Host "  [WARN] No provenance record matched sha256:$manifestHex in latest 500 entries." -ForegroundColor Yellow
        }
    }

    # --------------------------------------------------------------------------
    # STAGE 5: Final Approval Summary
    # --------------------------------------------------------------------------
    Write-Banner "STAGE 5 — FINAL VERIFICATION SUMMARY"
    Write-Host ("  {0,-20}  {1}" -f "Gate", "Result") -ForegroundColor White
    Write-Host ("  {0,-20}  {1}" -f ("-" * 20), ("-" * 52)) -ForegroundColor DarkGray
    foreach ($entry in $Gates.GetEnumerator()) {
        $val = [string]$entry.Value
        $rowColor = if ($val.StartsWith("PASS")) {
            "Green"
        } elseif ($val.StartsWith("FAIL") -or $val.StartsWith("BLOCKED") -or $val.StartsWith("MISSING")) {
            "Red"
        } else {
            "Yellow"
        }
        Write-Host ("  {0,-20}  {1}" -f $entry.Key, $val) -ForegroundColor $rowColor
    }
    Write-Host ""
    Write-Host "  Digest-Pinned Reference: ${Namespace}/${Repo}@${ManifestDigest}" -ForegroundColor Green
    if ($KeepProofDir) {
        Write-Host "  Proof Artifacts Saved  : $ProofDir" -ForegroundColor Cyan
    }
} finally {
    if ($CreatedTempDir -and -not $KeepProofDir -and (Test-Path $ProofDir)) {
        Remove-Item -Path $ProofDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $script:TranscriptWriter) {
        $script:TranscriptWriter.WriteLine("$($script:AnsiColorMap['DarkGray'])**********************$($script:AnsiReset)")
        $script:TranscriptWriter.WriteLine("$($script:AnsiColorMap['DarkGray'])ANSI Color Transcript End: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')$($script:AnsiReset)")
        $script:TranscriptWriter.WriteLine("$($script:AnsiColorMap['DarkGray'])**********************$($script:AnsiReset)")
        $script:TranscriptWriter.Flush()
        $script:TranscriptWriter.Dispose()
        $script:TranscriptWriter = $null
    }
}
