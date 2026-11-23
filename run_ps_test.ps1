$ErrorActionPreference = 'Stop'
$env:DIAG_PS_LIB = '1'
try {
    . "$PSScriptRoot/run.ps1"

    function Assert-Equal($Name, $Got, $Want) {
        if ($Got -ne $Want) {
            throw "$Name = '$Got', want '$Want'"
        }
    }

    Assert-Equal 'trim v' (ConvertTo-DiagVersion 'v2.0.1') '2.0.1'
    Assert-Equal 'bare version' (ConvertTo-DiagVersion '2.0.1') '2.0.1'
    Assert-Equal 'asset' (Get-DiagAssetName '2.0.1' 'amd64') 'diag_2.0.1_windows_amd64.exe'
    Assert-Equal 'url' (Get-DiagDownloadUrl '2.0.1' '386') 'https://github.com/nextdns/diag/releases/download/v2.0.1/diag_2.0.1_windows_386.exe'
    Assert-Equal 'amd64' (Get-DiagArch -Architecture 'AMD64' -NativeArchitecture '') 'amd64'
    Assert-Equal 'wow64' (Get-DiagArch -Architecture 'x86' -NativeArchitecture 'AMD64') 'amd64'
    Assert-Equal '386' (Get-DiagArch -Architecture 'x86' -NativeArchitecture '') '386'
    Assert-Equal 'arm64' (Get-DiagArch -Architecture 'ARM64' -NativeArchitecture '') 'arm64'

    $failed = $false
    try {
        Get-DiagArch -Architecture 'ia64' -NativeArchitecture '' | Out-Null
    } catch {
        $failed = $true
        if ($_.Exception.Message -notmatch 'Unsupported architecture') {
            throw
        }
    }
    if (-not $failed) {
        throw 'unsupported architecture was accepted'
    }

    try {
        ConvertTo-DiagVersion '   ' | Out-Null
        throw 'blank tag was accepted'
    } catch {
        if ($_.Exception.Message -notmatch 'Missing release tag') {
            throw
        }
    }

    Write-Output 'OK'
} finally {
    Remove-Item Env:DIAG_PS_LIB -ErrorAction SilentlyContinue
}
