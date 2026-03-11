param(
  [string]$Repo = "https://github.com/tbagzhao668/OpenclawFW.git",
  [string]$Tag = "latest"
)
$ErrorActionPreference='Stop'
$dst = Join-Path $env:ProgramFiles 'OpenClawProtector'
$tmp = Join-Path $env:TEMP ("ocp_"+[guid]::NewGuid().ToString())
$os = "windows"
$arch = if ($env:PROCESSOR_ARCHITECTURE -match "ARM64") { "arm64" } else { "amd64" }
$base = ($Repo -replace '\.git$','')
$asset = "consent-agent-$os-$arch.exe"
$url = "$base/releases/$Tag/download/$asset"
if(-not (Test-Path $dst)){ New-Item -ItemType Directory -Path $dst | Out-Null }
try {
  Write-Host "Attempting to download $url"
  iwr -UseBasicParsing -Uri $url -OutFile (Join-Path $dst 'consent-agent.exe')
} catch {
  Write-Host "Release asset unavailable; falling back to local build from source"
  git clone --depth=1 $Repo $tmp
  $agent = Join-Path $tmp 'protector\cmd\agent'
  Push-Location $agent
  go build -o consent-agent.exe
  Pop-Location
  Copy-Item (Join-Path $agent 'consent-agent.exe') (Join-Path $dst 'consent-agent.exe') -Force
}
$startup = [Environment]::GetFolderPath('Startup')
$lnk = Join-Path $startup 'OpenClaw Protector.lnk'
$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut($lnk)
$sc.TargetPath = (Join-Path $dst 'consent-agent.exe')
$sc.WorkingDirectory = $dst
$sc.Save()
Start-Process (Join-Path $dst 'consent-agent.exe') -WindowStyle Hidden
Start-Process 'http://127.0.0.1:48231/'
