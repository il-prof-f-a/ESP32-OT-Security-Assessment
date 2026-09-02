# Configuration Editor

The page is intentionally documented from its controls and API contract because values and
available fields vary with the firmware build.

The **Configuration** page is the authenticated, sectioned editor for the complete device
configuration. It keeps the browser copy as a draft until you explicitly save it to the device.
The page is available from the top navigation as **⚙️ Configuration**.

## Safe workflow

1. **Load current** reads the runtime configuration currently held by the firmware.
2. **Load saved** reads the authoritative `/data/config/config.json` file.
3. **Load defaults** previews the compile-time public configuration without changing the device.
4. **Import JSON** loads a local file into the draft only.
5. **Validate** checks object shape, known paths, value types and finite numeric values.
6. **Save to device** revalidates, checks the revision loaded by the browser and commits the
   transaction through the normal filesystem + CRC path. If another client changed the file, the
   save is rejected and the page asks you to reload.
7. **Save as** downloads the draft locally; it never writes the device.

The editor never returns passwords, tokens, hashes, private keys or other credential material.
Configured secrets are displayed as **Configured** and are preserved when a normal configuration
save is made. Use the dedicated provisioning/security credential workflows to rotate secrets.

## Sections

The sidebar follows the firmware schema: `debug`, `security`, `network`, `ids`, `signatures`,
`plugins`, `reporting`, `scanner`, `watchdog` and `gpio`. Fields that require a reboot are listed
in the save response as `restart_required_paths`; schedule a controlled restart when the page
reports one.

Within each section, fields are grouped into labelled subsections derived from their configuration
path. For example, `network.wifi.ip`, `network.wifi.netmask` and `network.wifi.gateway` appear in
the **Wi-Fi** card, while the corresponding `network.ethernet.*` fields appear in a separate
**Ethernet** card. Fields without a second path component are shown under **General**. The small
technical path displayed in each card makes the mapping to the JSON configuration explicit.

### Watchdog settings

Main-task monitoring reads the `watchdog` section at boot. Saving it does **not** change
that task's active subscription: restart the device to apply the saved settings to it.

The public build default is only used when the device has no valid persisted configuration.
Normally the effective values come from `/data/config/config.json`, so an existing device can
legitimately use a timeout different from the repository default. `GET /api/config/watchdog`
reports the saved value (`timeout_seconds`) separately from the boot-time value actually in use
(`effective_timeout_seconds`, `effective_enabled`, and `requested_timeout_seconds_at_boot`),
plus the recorded configuration source and storage backend. A value saved during the current
session is pending until restart (`configuration_pending_restart: true`); it does not silently
reconfigure the SDK watchdog.

- `enabled`: enables Task Watchdog monitoring of the main application task. When false,
  that task is not subscribed and does not send watchdog heartbeats. Other subscribed
  tasks, the SDK interrupt watchdog, HTTP monitoring and PSRAM monitoring remain independent.
- `timeout_seconds`: defaults to 120 seconds. The main task normally sends a heartbeat
  every 10 seconds; startup enforces a minimum of 60 seconds. Extremely large values are
  capped at 1,073,741 seconds to prevent overflow in the SDK timer conversion. Any adjustment
  is logged at boot and does not rewrite the saved value.
- `panic_on_timeout`: requests a panic on Task Watchdog timeout when enabled.
- `monitor_idle_cores`: includes the idle tasks of both CPU cores when configuring the
  Task Watchdog. These settings belong to the shared SDK Task Watchdog, not just its main
  task subscriber. Disabling main task monitoring does not globally deinitialize it.

Existing discovery helpers may temporarily adjust the shared Task Watchdog timeout during
long operations. Their behavior is separate from the main-task subscription fixed here.

Registration and heartbeat failures are logged explicitly. If removing an unexpected existing
main-task subscription fails, the firmware reports the failure and keeps feeding that subscription
rather than silently abandoning it. This is an error fallback, not successful disconnection.

To check the fix on hardware, save `watchdog.enabled=false`, restart, and observe the serial
monitor longer than the effective timeout (at least 180 seconds with the default 120-second
timeout). Expect `Main task watchdog disabled - task not registered` and no main-task watchdog
reset. Repeat with `enabled=true`; expect `Main task registered with watchdog` and stable operation.
Do not deliberately stall the firmware on a live OT network to test a timeout.

The page is not a replacement for first-boot provisioning. Keep exported drafts private because
non-secret network and security settings can still reveal topology and policy.

[Back to the guide index](README.md)
