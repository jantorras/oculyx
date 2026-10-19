# Builds server/assets/OculyxSetup.exe (setup window + silent installer + tray icon in one file).
# Uses the C# compiler that ships with Windows, so no SDK or Visual Studio is needed.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'windows\OculyxSetup'
$out  = Join-Path $root 'server\assets\OculyxSetup.exe'
$csc  = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc.exe not found at $csc (needs the .NET Framework 4.x that ships with Windows)." }
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null

# --- application icon: the Oculyx ring+dot mark at 16/32/48/256 px, PNG-compressed inside an .ico
Add-Type -AssemblyName System.Drawing
function New-Mark([int]$s) {
  $bmp = New-Object System.Drawing.Bitmap $s, $s
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $col = [System.Drawing.Color]::FromArgb(45, 212, 191)
  $pen = [Math]::Max(2, $s * 0.12)
  $p = New-Object System.Drawing.Pen $col, $pen
  $g.DrawEllipse($p, $pen, $pen, $s - 2 * $pen, $s - 2 * $pen)
  $d = $s * 0.32
  $b = New-Object System.Drawing.SolidBrush $col
  $g.FillEllipse($b, ($s - $d) / 2, ($s - $d) / 2, $d, $d)
  $g.Dispose()
  $bmp
}
$sizes = 16, 32, 48, 256
$pngs = foreach ($s in $sizes) { $ms = New-Object System.IO.MemoryStream; (New-Mark $s).Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); ,$ms.ToArray() }
$ico = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter $ico
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
  $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
  $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
  $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$pngs[$i].Length); $w.Write([uint32]$offset)
  $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $w.Write($p) }
$icoPath = Join-Path ([IO.Path]::GetTempPath()) 'oculyx.ico'
[IO.File]::WriteAllBytes($icoPath, $ico.ToArray())

& $csc /nologo /target:winexe /optimize+ "/out:$out" "/win32icon:$icoPath" "/win32manifest:$(Join-Path $src 'app.manifest')" `
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Web.Extensions.dll (Join-Path $src 'Program.cs')
if ($LASTEXITCODE -ne 0) { throw "csc failed with exit code $LASTEXITCODE" }
Write-Host ("Built {0} ({1:N0} KB)" -f $out, ((Get-Item $out).Length / 1KB))
