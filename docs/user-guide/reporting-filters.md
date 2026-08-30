# Reporting channel filters

The Reporting page applies filters independently for each output channel. When filters are enabled, an event must first match at least one **include** pattern (when the include list is non-empty); an **exclude** match then vetoes delivery. Patterns are regular expressions and are case-insensitive by default.

## Useful prefixes and keywords

The following values are taken from the logging tags and structured event types used by the firmware. They are also available as autocomplete suggestions in the Reporting page.

| Category | Prefix or keyword | Typical use |
| --- | --- | --- |
| Startup/configuration | `MAIN`, `Config`, `REPORTING`, `AsyncStorage`, `FSDelegate` | Boot, configuration and persistence diagnostics |
| Connectivity | `EthernetManager`, `WiFiManager`, `WIFI_CONNECT`, `WIFI_DISCONNECT`, `PacketCapture`, `EthL2Adapter` | Link, DHCP/static IP and packet capture events |
| Web/API | `Web`, `WebServer`, `WebServerTask`, `HTTPD_MON`, `SESSION`, `API_AUTH`, `ACCESS_LOG` | Management UI, authentication and HTTP activity |
| Detection | `IDS_ENGINE`, `SIG_DETECT`, `NetworkPresenceTracker`, `PRESENCE_`, `intrusion_detected`, `ids_detection_detailed` | IDS, signatures and network-presence findings |
| Discovery | `DISCOVERY_MGR`, `GeneralDiscovery`, `S7Plugin`, `ModbusTCP`, `PROFINETPlugin`, `EtherNetIPPlugin`, `OPCUA_PLUGIN` | Passive/protocol discovery diagnostics |
| Assessment | `VULNERABILITY_SCANNER`, `VULN_SCANNER`, `Scanner`, `FUZZING_ENGINE`, `FuzzingEngine`, `SCAN_JOBS`, `CronScheduler` | Vulnerability scans, fuzzing and scheduled jobs |
| Protocol codecs | `OPCUACodec`, `OPCUAVulnTest`, `OPCUAFuzz`, `S7Plugin`, `ModbusTCP` | Protocol parsing and test details |
| Reporting/storage | `REPORTQ`, `ReportingEngine`, `FileReporter`, `MQTT`, `EMAIL`, `AUDIT`, `gpio_event` | Delivery, queue, audit and GPIO records |
| Memory/runtime | `MEM_MONITOR`, `PSRAMTelemetry`, `PSRAMUtils`, `PSRAMJson`, `NVSOverride`, `TaskConfig` | Memory and task-health diagnostics |

## Examples

Simple include: `IDS_ENGINE` or `NetworkPresenceTracker`.

Simple exclude: `debug|trace` or `heartbeat`.

Combined include (any of several areas): `^(MAIN|Config|REPORTING):`.

Combined exclude (noise from health probes): `HTTPD_MON|MEM_MONITOR|PSRAMTelemetry`.

To keep only security findings while excluding periodic telemetry, use include `intrusion_detected|ids_detection|signature` and exclude `MEM_MONITOR|PSRAMTelemetry`.

Patterns are evaluated per channel; changing the serial filter does not alter MQTT, email, webhook or file routing. The file channel editor is intentionally owned by `/logging`, while the Reporting page keeps the file channel available for stream preview and status only.
