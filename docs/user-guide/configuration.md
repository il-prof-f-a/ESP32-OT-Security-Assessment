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

The page is not a replacement for first-boot provisioning. Keep exported drafts private because
non-secret network and security settings can still reveal topology and policy.

[Back to the guide index](README.md)
