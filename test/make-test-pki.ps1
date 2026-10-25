<#
.SYNOPSIS
    Create a throw-away test PKI (CA + leaf) for integration testing.

.DESCRIPTION
    Builds a self-signed test CA and one leaf certificate in the *current user* certificate
    store, then exports them next to this script (test\out by default):

        ca.cer / ca.pem          issuer certificate (DER + PEM)
        leaf.cer / leaf.pem      leaf certificate
        leaf.serial.txt          leaf serial number, ready for a snapshot row

    The certificates are for local testing only: they are not trusted by anything and are
    never added to a machine trust store.

.EXAMPLE
    pwsh -File test/make-test-pki.ps1

.EXAMPLE
    pwsh -File test/make-test-pki.ps1 -OutDir C:\temp\cdbrp-pki -CaName 'CDBRP Test CA'
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string]$CaName = 'CDBRP Test CA',
    [string]$LeafName = 'cdbrp-test-leaf',
    [int]$CaYears = 10,
    [int]$LeafYears = 5,
    [switch]$KeepInStore
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) { $OutDir = Join-Path $ScriptDir 'out' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    throw 'New-SelfSignedCertificate not available (needs Windows 8.1+ / PowerShell 4+)'
}

function Export-Pem([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$path) {
    $b64 = [Convert]::ToBase64String($cert.RawData)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('-----BEGIN CERTIFICATE-----')
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        [void]$sb.AppendLine($b64.Substring($i, [Math]::Min(64, $b64.Length - $i)))
    }
    [void]$sb.AppendLine('-----END CERTIFICATE-----')
    [System.IO.File]::WriteAllText($path, $sb.ToString(), (New-Object System.Text.ASCIIEncoding))
}

Write-Host '--- creating test CA' -ForegroundColor Cyan
$ca = New-SelfSignedCertificate `
    -Subject ("CN=" + $CaName) `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable -KeyUsage CertSign, CRLSign, DigitalSignature `
    -TextExtension @('2.5.29.19={critical}{text}ca=1', '2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2') `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddYears($CaYears)
Write-Host ("    thumbprint " + $ca.Thumbprint)

Write-Host '--- creating test leaf' -ForegroundColor Cyan
$leaf = New-SelfSignedCertificate `
    -Subject ("CN=" + $LeafName) `
    -Signer $ca `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -NotAfter (Get-Date).AddYears($LeafYears)
Write-Host ("    thumbprint " + $leaf.Thumbprint)

[System.IO.File]::WriteAllBytes((Join-Path $OutDir 'ca.cer'), $ca.RawData)
[System.IO.File]::WriteAllBytes((Join-Path $OutDir 'leaf.cer'), $leaf.RawData)
Export-Pem $ca   (Join-Path $OutDir 'ca.pem')
Export-Pem $leaf (Join-Path $OutDir 'leaf.pem')

$serial = $leaf.SerialNumber
Set-Content -Path (Join-Path $OutDir 'leaf.serial.txt') -Value $serial -Encoding ASCII

if (-not $KeepInStore) {
    # The exported files are enough; do not leave keys lying around in the user store.
    Remove-Item ("Cert:\CurrentUser\My\" + $leaf.Thumbprint) -Force -ErrorAction SilentlyContinue
    Remove-Item ("Cert:\CurrentUser\My\" + $ca.Thumbprint) -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("test PKI written to " + $OutDir) -ForegroundColor Green
Write-Host ("leaf serial: " + $serial)
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1. import CA into a test CA and issue from it, or use these certs with a test responder'
Write-Host '  2. snapshot row:  <serial> <TAB> 20 <TAB> 0 <TAB> 0 <TAB> 0'
Write-Host '  3. probe:         openssl ocsp -issuer ca.pem -serial 0x<serial> -url <responder> -CAfile ca.pem -no_nonce'
