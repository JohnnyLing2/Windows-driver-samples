param(
  [string]$MonitorExe = "..\exe\x64\Debug\monitor.exe",
  [string]$ConfigPath = "..\config\default.nettraceguard.json"
)

$ErrorActionPreference = 'Stop'
$testRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$outRoot = Join-Path $testRoot "out"
New-Item -ItemType Directory -Path $outRoot -Force | Out-Null

$attackInput = Join-Path $testRoot "replay\attack-icmp-ddos.csv"
$benignInput = Join-Path $testRoot "replay\benign.csv"
$attackJson = Join-Path $outRoot "attack.json"
$attackTxt = Join-Path $outRoot "attack.txt"
$benignJson = Join-Path $outRoot "benign.json"
$benignTxt = Join-Path $outRoot "benign.txt"

& $MonitorExe analyze --config $ConfigPath --input $attackInput --json $attackJson --text $attackTxt
if ($LASTEXITCODE -ne 0) { throw "Attack replay analysis failed" }

& $MonitorExe analyze --config $ConfigPath --input $benignInput --json $benignJson --text $benignTxt
if ($LASTEXITCODE -ne 0) { throw "Benign replay analysis failed" }

$attackReport = Get-Content $attackTxt -Raw
$benignReport = Get-Content $benignTxt -Raw

if ($attackReport -notmatch "icmp_flood") { throw "Expected icmp_flood incident was not detected" }
if ($attackReport -notmatch "distributed_flood") { throw "Expected distributed_flood incident was not detected" }
if ($benignReport -match "critical") { throw "Benign trace produced critical severity incident" }

Write-Host "Replay tests passed"
