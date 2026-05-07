---
page_type: sample
description: "NetTraceGuard sample combines a WFP kernel callout and user-mode analyzer for adapter-scoped threat monitoring."
languages:
- cpp
products:
- windows
- windows-wdk
---

# NetTraceGuard (WFP Adapter-Scoped Network Threat Monitor)

NetTraceGuard is a new deliverable under `network/trans/` that combines:

- **Kernel-mode WFP callout driver** (based on the `inspect` sample pattern)
- **User-mode control + analysis CLI** (`monitor.exe`, based on the `msnmntr` app structure)
- **Replay-driven validation assets** and operational scripts

## Capabilities

1. **Windows support**
   - Built for Visual Studio 2022 + WDK 11 using standard sample toolchains.

2. **Adapter-scoped monitoring**
   - Driver supports filtering by adapter interface index (`AdapterIfIndex`) and optional adapter LUID registry fields.
   - Live adapter switching is done by updating registry values and restarting the service (no rebuild/reinstall required).

3. **Attack checks**
   - ICMP flood heuristic: high-rate ICMP echo (`icmpType=8`) in a sampling window.
   - DDoS heuristics:
     - aggregate packet-rate spike
     - per-source packet-rate spike
     - fan-in anomaly (many concurrent sources)
   - Thresholds, windows, severity, and cooldown are configurable.

4. **Analysis summary with user experience focus**
   - Dashboard mode with top talkers and incident timeline.
   - Exportable JSON + text reports with:
     - what happened
     - why it was flagged
     - recommended action

## Folder layout

- `sys/` - kernel WFP callout driver source and INF
- `exe/` - user-mode CLI (`monitor.exe`) for config/analyze/dashboard
- `config/` - JSON schema + default thresholds
- `scripts/` - install/uninstall scripts
- `tests/` - replay traces and replay validation script

## Build

Open `nettraceguard.sln` in Visual Studio 2022 with WDK 11 installed.

Or use the repository build helper in a Developer PowerShell:

```powershell
cd <repo-root>
.\Build-Sample.ps1 -Directory .\network\trans\nettraceguard -Configuration Debug -Platform x64 -Verbose
```

## Deploy and run

1. Build the solution.
2. On target machine (Admin prompt):

```cmd
cd <repo>\network\trans\nettraceguard\scripts
NetTraceGuardInstall.cmd
```

3. Configure analyzer defaults:

```cmd
cd <repo>\network\trans\nettraceguard\exe
monitor.exe configure --config ..\config\default.nettraceguard.json --adapter-ifindex 12 --window-sec 10 --icmp-threshold 10 --ddos-aggregate-threshold 30 --ddos-per-source-threshold 10 --ddos-fanin-threshold 8 --cooldown-sec 15 --fail-mode permit
```

4. Analyze trace and export reports:

```cmd
monitor.exe analyze --config ..\config\default.nettraceguard.json --input ..\tests\replay\attack-icmp-ddos.csv --json .\attack-report.json --text .\attack-report.txt
```

5. Run dashboard summary:

```cmd
monitor.exe dashboard --config ..\config\default.nettraceguard.json --input ..\tests\replay\attack-icmp-ddos.csv
```

## Adapter switching

To switch adapters without reinstall:

```cmd
reg add "HKLM\System\CurrentControlSet\Services\inspect\Parameters" /v AdapterIfIndex /t REG_DWORD /d <NEW_IFINDEX> /f
sc stop inspect
sc start inspect
```

## Validation and quality gates

Replay validation script:

```powershell
cd <repo>\network\trans\nettraceguard\tests
.\run-replay-tests.ps1 -MonitorExe ..\exe\x64\Debug\monitor.exe -ConfigPath ..\config\default.nettraceguard.json
```

Acceptance criteria:

- Attack replay triggers `icmp_flood` and `distributed_flood` incidents.
- Benign replay does not trigger critical incidents.
- Reports are generated in both JSON and text forms.

## Non-functional notes

- **Low overhead**: adapter scoping and threshold-based detection limit analysis overhead.
- **Fail mode**: configurable `permit`/`block` policy in analyzer config.
- **Telemetry**: incident timeline and protocol/source summaries support triage.
- **Privileges**: driver install, registry updates under service key, and callout registration require Administrator rights.

## Troubleshooting

- `msbuild cannot be called from current environment`:
  - Use a Visual Studio Developer Command Prompt with WDK components.
- Driver service not starting:
  - Verify test signing/provisioning and INF install status.
- No incidents detected in attack replay:
  - Lower thresholds in config and verify adapterIfIndex matches input traces.

## Known limitations

- Current analyzer expects CSV trace input (`timestampMs,adapterIfIndex,src,dst,protocol,icmpType,bytes`).
- LUID matching fields are loaded for adapter identity continuity but current driver classification path filters on interface index.
- Heuristics are intentionally conservative sample logic, not production-grade threat intelligence.
