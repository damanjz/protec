# Registers the protec-host native-messaging host for Chromium + Firefox.
# Usage: powershell -ExecutionPolicy Bypass -File register-host.ps1 -HostExe "C:\path\to\protec-host.exe" -ChromiumExtId "<id>" -FirefoxExtId "protec@local"
param(
  [Parameter(Mandatory=$true)][string]$HostExe,
  [string]$ChromiumExtId = "REPLACE_WITH_CHROMIUM_EXTENSION_ID",
  [string]$FirefoxExtId = "protec@local"
)

$ErrorActionPreference = "Stop"
$hostName = "dev.protec.host"
$dir = Join-Path $env:LOCALAPPDATA "Protec\nmh"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# Chromium manifest
$chromium = @{
  name = $hostName
  description = "Protec native messaging host"
  path = $HostExe
  type = "stdio"
  allowed_origins = @("chrome-extension://$ChromiumExtId/")
} | ConvertTo-Json -Depth 5
$chromiumPath = Join-Path $dir "$hostName.chromium.json"
Set-Content -Path $chromiumPath -Value $chromium -Encoding UTF8

# Firefox manifest
$firefox = @{
  name = $hostName
  description = "Protec native messaging host"
  path = $HostExe
  type = "stdio"
  allowed_extensions = @($FirefoxExtId)
} | ConvertTo-Json -Depth 5
$firefoxPath = Join-Path $dir "$hostName.firefox.json"
Set-Content -Path $firefoxPath -Value $firefox -Encoding UTF8

# Register via the per-user registry keys.
$chromeKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
New-Item -Path $chromeKey -Force | Out-Null
Set-ItemProperty -Path $chromeKey -Name "(default)" -Value $chromiumPath

$edgeKey = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$hostName"
New-Item -Path $edgeKey -Force | Out-Null
Set-ItemProperty -Path $edgeKey -Name "(default)" -Value $chromiumPath

$ffKey = "HKCU:\Software\Mozilla\NativeMessagingHosts\$hostName"
New-Item -Path $ffKey -Force | Out-Null
Set-ItemProperty -Path $ffKey -Name "(default)" -Value $firefoxPath

Write-Host "Registered protec-host for Chrome, Edge, and Firefox."
Write-Host "Chromium manifest: $chromiumPath"
Write-Host "Firefox manifest:  $firefoxPath"
