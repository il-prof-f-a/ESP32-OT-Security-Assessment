# Network isolation and residual exposure

The firmware treats Ethernet as the OT assessment interface on all four targets. Active assessment sockets resolve `ETH_DEF`, require a valid Ethernet IPv4 address, bind their source address to it and fail closed if that operation fails. Wi-Fi is never an assessment fallback.

| Target | Management policy | Assessment policy | Web transport |
| --- | --- | --- | --- |
| LILYGO T-POE Pro | Wi-Fi only | Ethernet only | HTTP |
| Waveshare ESP32-S3-ETH | Wi-Fi only | Ethernet only | HTTPS |
| Waveshare ESP32-P4-ETH | Ethernet exception | Ethernet only | HTTPS |
| GUITION JC-ESP32P4-M3-DEV | ESP32-C6 remote Wi-Fi only | Ethernet only | HTTPS |

For Wi-Fi-only targets, management is disabled when Wi-Fi is unavailable, its address changes, or its IPv4 subnet overlaps the Ethernet subnet. The server is restarted only after the allowed interface has a valid, non-overlapping address. Status APIs expose the board ID, selected management policy, current state, degraded flag and fixed Ethernet assessment policy without exposing credentials.

## Isolation strength

ESP-IDF's `esp_http_server` opens a wildcard listener. This implementation applies two controls:

1. a connection gate compares the socket's local destination address with the policy-selected address and closes mismatches;
2. every registered HTTP handler repeats the same local-address check before processing the request.

The acceptance boundary is therefore **application-level isolation**: an Ethernet-side client must not complete an HTTP or HTTPS application request on a Wi-Fi-only build. The Ethernet address may still answer a TCP SYN before the connection is closed, and HTTPS rejection occurs after the ESP-IDF TLS accept path invokes the application callback. This is not equivalent to a firewall or listener bound exclusively to one network interface.

Deploy an external firewall or VLAN ACL when TCP-level invisibility is required. The Waveshare ESP32-P4-ETH is an explicit exception: because it has no Wi-Fi, its management UI and assessment traffic share the OT Ethernet subnet.
