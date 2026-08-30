# Protocol Discovery

![Protocol Discovery page](assets/protocol-discovery.png)

Protocol Discovery is an independent, non-offensive workspace for finding and characterizing OT
services and devices. Open it from the dashboard or directly at `/discovery`. Vulnerability
scanning, fuzzing and scheduled scans are managed separately on `/scanner` (with the legacy
aliases `/vulnerability-scanner`, `/fuzzing` and `/scheduled-scans`).

## Module controls

Discovery has no Offensive Testing toggle and does not change the Scanner/Fuzzing feature flags.
Its availability depends on the compiled protocol support and the selected network interface.
The assessment controls are intentionally kept on the separate Scanner & Fuzzing page.

## Protocol-specific discovery

Select a protocol, enter the target required by its hint, set a timeout and choose **Start
Discovery**.

| Button | Target and behavior |
| --- | --- |
| **Modbus** | An IPv4 host or subnet, normally using TCP 502. Probes Modbus reachability and configured unit IDs. |
| **S7** | An IPv4 host or subnet, normally TCP 102. Some builds require Ethernet to be ready. |
| **PROFINET DCP** | Uses Layer 2 discovery and therefore does not require an IP subnet. Select the recommended Ethernet/L2 interface value shown by the form. |
| **EtherNet/IP** | An IPv4 host or subnet, normally TCP 44818, using EtherNet/IP discovery. |
| **OPC UA Hello** | An IPv4 host or subnet, normally TCP 4840, using an OPC UA HEL probe rather than a full secure session. |

**Active Discoveries** shows running tasks and provides **Cancel**. **Discovery Results** shows
completed findings and **Download JSON** exports the current result set.

## General Discovery

- **Ping sweep** looks for responsive hosts.
- **Port scan** checks the comma-separated port list.
- **Target subnet or IP** accepts an individual address or CIDR range.
- **Interface** selects the OT Ethernet interface used by the discovery engine.
- Per-host and connection timeouts prevent a slow host from holding the scan indefinitely.
- **Max hosts** bounds the amount of work; keep it small on large or sensitive networks.

Discovery generates network traffic and can trigger OT monitoring. Start with narrow targets,
longer delays and explicit authorization.

[Back to the guide index](README.md)
