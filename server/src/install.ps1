# Oculyx agent installer for Windows (PowerShell 5.1+). Run in an elevated PowerShell:
#
#   [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm '__SERVER__/install.ps1'))) -Token 'ocx_...' -Name 'my-pc'
#
# Read it first:  irm '__SERVER__/install.ps1' | more
# Runs the agent as a scheduled task under SYSTEM with a portable Node.js (no installer, no MSI).
# Running it again upgrades the agent and keeps its identity.
[CmdletBinding()]
param(
  [string]$Token = '',
  [string]$Name = $env:COMPUTERNAME,
  [string]$Server = '__SERVER__',
  [switch]$AllowActions,
  [switch]$Uninstall,
  [switch]$Purge
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # makes Invoke-WebRequest much faster
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

$Root      = Join-Path $env:ProgramData 'Oculyx'
$NodeDir   = Join-Path $Root 'node'
$AgentDir  = Join-Path $Root 'agent'
$StateDir  = Join-Path $Root 'state'
$LogFile   = Join-Path $Root 'agent.log'
$RunCmd    = Join-Path $Root 'run.cmd'
$TaskName  = 'OculyxAgent'
$Server    = $Server.TrimEnd('/')

function Step($m) { Write-Host ''; Write-Host "==> $m" -ForegroundColor White }
function Ok($m)   { Write-Host "  + $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  ! $m" -ForegroundColor Yellow }

function Stop-Agent {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  }
  # the task launches cmd.exe -> node.exe from our folder; make sure nothing keeps files locked
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 500
}

function Install-Agent {
  Write-Host "Oculyx agent installer for Windows  $Server" -ForegroundColor White

  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw 'Please run this in an elevated PowerShell (right-click > Run as administrator).' }

  if ($Uninstall) {
    Step 'Removing the Oculyx agent'
    Stop-Agent
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false; Ok 'Scheduled task removed' }
    Remove-Item -Recurse -Force $NodeDir, $AgentDir, $LogFile, "$LogFile.old", $RunCmd -ErrorAction SilentlyContinue
    if ($Purge) { Remove-Item -Recurse -Force $StateDir -ErrorAction SilentlyContinue; Ok 'Credentials removed' }
    Write-Host ''
    Write-Host 'Done. You can also delete the host from the Oculyx web UI.'
    return
  }

  if ($Name -notmatch '^[A-Za-z0-9._ -]{1,60}$') { throw "The name may only contain letters, numbers, spaces, dot, dash and underscore: '$Name'" }
  if ($Token -and $Token -notmatch '^[A-Za-z0-9_-]{8,80}$') { throw 'The token looks malformed. Copy it again from Oculyx: Settings > Add hosts.' }

  Step 'Checking requirements'
  if ([Environment]::OSVersion.Version.Major -lt 10) { throw 'Node.js 24 needs Windows 10 / Windows Server 2016 or newer.' }
  switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { $arch = 'x64' } 'ARM64' { $arch = 'arm64' } default { throw "Unsupported CPU architecture: $env:PROCESSOR_ARCHITECTURE" } }
  Ok "Windows $([Environment]::OSVersion.Version) ($arch)"

  try { Invoke-RestMethod -Uri "$Server/healthz" -TimeoutSec 10 | Out-Null } catch {
    throw "Cannot reach the Oculyx server at $Server from this machine. Check the address, DNS and firewall."
  }
  Ok 'Oculyx server reachable'

  $haveIdentity = Test-Path (Join-Path $StateDir 'credentials.json')
  if (-not $Token -and -not $haveIdentity) { throw '-Token is required for a first install. Create one in Oculyx: Settings > Add hosts.' }

  New-Item -ItemType Directory -Force -Path $Root, $StateDir | Out-Null
  # credentials live here: only SYSTEM and Administrators may read them
  & icacls.exe $Root /inheritance:r /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null

  Stop-Agent

  # ---- Node.js (portable, checksum verified)
  $nodeExe = Join-Path $NodeDir 'node.exe'
  $haveNode = $false
  if (Test-Path $nodeExe) { try { $haveNode = ([int](((& $nodeExe -p process.versions.node) | Select-Object -First 1).Split('.')[0])) -ge 24 } catch { } }
  if ($haveNode) {
    Ok "Node.js $((& $nodeExe -v)) (already installed)"
  } else {
    Step 'Installing Node.js 24 (official build)'
    $base = 'https://nodejs.org/dist/latest-v24.x'
    $sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHASUMS256.txt" -TimeoutSec 30).Content -split "`n"
    $line = $sums | Where-Object { $_ -match "node-v[\d.]+-win-$arch\.zip\s*$" } | Select-Object -First 1
    if (-not $line) { throw 'Could not find a Node.js build for this CPU on nodejs.org.' }
    $parts = $line.Trim() -split '\s+'
    $sha = $parts[0]; $file = $parts[1]
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("oculyx-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
      Invoke-WebRequest -UseBasicParsing -Uri "$base/$file" -OutFile (Join-Path $tmp $file) -TimeoutSec 600
      $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $file)).Hash
      if ($actual -ne $sha.ToUpper()) { throw 'Node.js checksum mismatch; aborting.' }
      Expand-Archive -Path (Join-Path $tmp $file) -DestinationPath $tmp -Force
      $inner = Get-ChildItem $tmp -Directory | Where-Object { $_.Name -like 'node-v*' } | Select-Object -First 1
      if (Test-Path $NodeDir) { Remove-Item -Recurse -Force $NodeDir }
      Move-Item $inner.FullName $NodeDir
    } finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
    Ok "Node.js $((& $nodeExe -v)) in $NodeDir"
  }

  # ---- agent files from your server
  Step 'Downloading the agent'
  $new = "$AgentDir.new"
  if (Test-Path $new) { Remove-Item -Recurse -Force $new }
  New-Item -ItemType Directory -Path $new | Out-Null
  $manifest = (Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent/manifest.txt" -TimeoutSec 20).Content -split "`n"
  foreach ($f in $manifest) {
    $f = $f.Trim()
    if (-not $f -or $f -eq 'Dockerfile') { continue }
    if ($f -match '\.\.' -or $f.StartsWith('/') -or $f -match ':') { throw "Refusing unsafe path from server: $f" }
    $dest = Join-Path $new ($f -replace '/', '\')
    New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent/files/$f" -OutFile $dest -TimeoutSec 30
  }
  if (-not (Test-Path (Join-Path $new 'src\main.ts'))) { throw 'The server did not provide the agent files.' }
  if (Test-Path $AgentDir) { Remove-Item -Recurse -Force $AgentDir }
  Move-Item $new $AgentDir
  Ok "Agent files in $AgentDir"

  Step 'Installing agent dependencies'
  Push-Location $AgentDir
  try {
    $env:PATH = "$NodeDir;$env:PATH"
    $env:NODE_ENV = 'production'
    & (Join-Path $NodeDir 'npm.cmd') install --omit=dev --no-audit --no-fund --silent
    if ($LASTEXITCODE -ne 0) { throw 'npm install failed.' }
  } finally { Pop-Location }
  Ok 'Dependencies installed'

  # ---- launcher + scheduled task (SYSTEM, at startup, restarted if it ever fails)
  Step 'Starting the agent (scheduled task)'
  $allow = if ($AllowActions) { 'true' } else { 'false' }
  $lines = @('@echo off', "set `"OCULYX_SERVER=$Server`"", "set `"OCULYX_NAME=$Name`"", "set `"OCULYX_ALLOW_ACTIONS=$allow`"", "set `"OCULYX_STATE_DIR=$StateDir`"")
  if ($Token) { $lines += "set `"OCULYX_ENROLL_TOKEN=$Token`"" }
  $lines += @(
    "cd /d `"$AgentDir`"",
    "for %%A in (`"$LogFile`") do if %%~zA GTR 5000000 move /y `"$LogFile`" `"$LogFile.old`" >nul",
    "`"$nodeExe`" --disable-warning=ExperimentalWarning src\main.ts >> `"$LogFile`" 2>&1"
  )
  Set-Content -Path $RunCmd -Value $lines -Encoding ASCII
  New-Item -ItemType File -Force -Path $LogFile | Out-Null   # fresh log; also keeps the size check in run.cmd valid

  $action    = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$RunCmd`""
  $trigger   = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
               -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force `
    -Description 'Oculyx monitoring agent' | Out-Null
  Start-ScheduledTask -TaskName $TaskName

  $connected = $false
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    $log = if (Test-Path $LogFile) { Get-Content $LogFile -Tail 60 -ErrorAction SilentlyContinue } else { @() }
    if ($log -match 'enrollment rejected') { throw 'The server rejected the token. It may have expired or already been used. Create a new one in Settings > Add hosts.' }
    if ($log -match '\] connected\s*$') { $connected = $true; break }
  }

  if ($connected) {
    # the one-time token is useless now; do not leave it on disk
    if ($Token) { Set-Content -Path $RunCmd -Value ($lines | Where-Object { $_ -notlike '*OCULYX_ENROLL_TOKEN*' }) -Encoding ASCII }
    Ok 'Connected to Oculyx'
    Write-Host ''
    Write-Host "All set. `"$Name`" should now appear in $Server" -ForegroundColor Green
  } else {
    Warn 'The agent is running but has not confirmed the connection yet.'
    Write-Host "  Check the log: Get-Content '$LogFile' -Tail 30"
  }
  if ($AllowActions) { Write-Host '  Container start/stop/restart from the UI is enabled for this host.' }
  else { Write-Host '  Read-only mode. Re-run with -AllowActions to manage Docker containers from the UI.' }
}

try {
  Install-Agent
} catch {
  Write-Host ''
  Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
  $global:LASTEXITCODE = 1
}
