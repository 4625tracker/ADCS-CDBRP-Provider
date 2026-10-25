<#
.SYNOPSIS
    Convenience wrapper around `scripts/install.ps1 -Mode uninstall`.

.EXAMPLE
    pwsh -File scripts/uninstall.ps1 -RemoveFiles
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramData 'OcspDbProvider'),
    [string]$CAConfig = '',
    [switch]$RemoveFiles
)

$install = Join-Path $PSScriptRoot 'install.ps1'
$p = @{ Mode = 'uninstall'; InstallDir = $InstallDir; RemoveFiles = $RemoveFiles }
if (-not [string]::IsNullOrEmpty($CAConfig)) { $p.CAConfig = $CAConfig }
& $install @p
