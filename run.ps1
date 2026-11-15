<#
.SYNOPSIS
    Download and run the NextDNS network diagnostic on Windows.

.DESCRIPTION
    For RMM jobs such as N-able N-sight. Unattended by default: prompts are
    skipped and the report is sent. Pass -Interactive to ask first.
    Traceroute needs an elevated session. RMM agents already run as SYSTEM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run.ps1 -Email ops@example.com

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run.ps1 -Interactive
#>
param(
    [switch]$Interactive,
    [string]$Email = '',
    [string]$Version = ''
)

function Get-DiagArch {
    param(
        [string]$Architecture = $env:PROCESSOR_ARCHITECTURE,
        [string]$NativeArchitecture = $env:PROCESSOR_ARCHITEW6432
    )
    $arch = $Architecture
    if (-not [string]::IsNullOrWhiteSpace($NativeArchitecture)) {
        # 32-bit PowerShell on 64-bit Windows reports x86. Use the OS arch.
        $arch = $NativeArchitecture
    }
    switch ($arch) {
        'AMD64' { return 'amd64' }
        'x86' { return '386' }
        'ARM64' { return 'arm64' }
        default { throw "Unsupported architecture: $arch" }
    }
}

function ConvertTo-DiagVersion([string]$Tag) {
    if ([string]::IsNullOrWhiteSpace($Tag)) {
        throw 'Missing release tag'
    }
    return $Tag.Trim().TrimStart('v')
}

function Get-DiagAssetName([string]$Version, [string]$Arch) {
    return "diag_${Version}_windows_${Arch}.exe"
}

function Get-DiagDownloadUrl([string]$Version, [string]$Arch) {
    $name = Get-DiagAssetName -Version $Version -Arch $Arch
    return "https://github.com/nextdns/diag/releases/download/v$Version/$name"
}

function Invoke-Diag {
    param(
        [switch]$Interactive,
        [string]$Email,
        [string]$Version
    )

    $ErrorActionPreference = 'Stop'
    # Windows PowerShell 5.1 on older .NET does not enable TLS 1.2 by default.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    $headers = @{ 'User-Agent' = 'nextdns-diag' }

    $arch = Get-DiagArch
    if (-not $Version) {
        $release = Invoke-RestMethod -Headers $headers -Uri 'https://api.github.com/repos/nextdns/diag/releases/latest'
        $Version = $release.tag_name
    }
    $ver = ConvertTo-DiagVersion $Version
    $url = Get-DiagDownloadUrl -Version $ver -Arch $arch

    # Stable name so an allow rule for this program can stick across runs.
    $dir = Join-Path $env:TEMP 'nextdns'
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $dest = Join-Path $dir 'nextdns-diag.exe'
    try {
        Invoke-WebRequest -Headers $headers -Uri $url -OutFile $dest -UseBasicParsing
    } catch {
        throw "Failed to download ${url}: $_"
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning 'Not running as Administrator. Traceroute may be incomplete.'
    }

    $exeArgs = @()
    if (-not $Interactive) {
        $exeArgs += '-y'
    }
    if ($Email) {
        $exeArgs += @('-email', $Email)
    }
    & $dest @exeArgs
    if ($null -ne $LASTEXITCODE) {
        exit $LASTEXITCODE
    }
}

# Tests set DIAG_PS_LIB and dot-source this file. A normal launch runs the tool.
if (-not $env:DIAG_PS_LIB) {
    Invoke-Diag -Interactive:$Interactive -Email $Email -Version $Version
}
