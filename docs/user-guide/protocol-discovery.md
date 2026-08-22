# Protocol Discovery

![Protocol Discovery page](assets/protocol-discovery.png)

Protocol Discovery is the first tab of the shared Scanner & Fuzzing page. It finds candidate OT
services and devices. The shortcuts `/scanner`, `/vulnerability-scanner` and `/fuzzing` open the
same page with a different tab selected.

## Module controls

**Enable Scanner & Fuzzing Module** gates vulnerability scanning and fuzzing. **Enable Scheduled
Scans (Cron)** gates the scheduler and is available only while the parent module is enabled.
**Save** applies these feature flags. Discovery remains presented separately, but its actual
availability still depends on the compiled protocol support and network interface.

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
- **Interface** chooses Ethernet, automatic fallback, Wi-Fi STA or Wi-Fi AP.
- Per-host and connection timeouts prevent a slow host from holding the scan indefinitely.
- **Max hosts** bounds the amount of work; keep it small on large or sensitive networks.

Discovery generates network traffic and can trigger OT monitoring. Start with narrow targets,
longer delays and explicit authorization.

[Back to the guide index](README.md)
