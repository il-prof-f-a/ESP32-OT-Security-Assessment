# Log File Management

![Log File Management page](assets/logging.png)

This page shows managed log files, edits rotation limits and streams selected channels in real
time.

## Log File Status

The table reports file name, enabled/disabled state, current size, maximum size, routed channels
and actions. **Refresh** reloads the table. Row actions exposed by the runtime can download a file
or enable/disable it. Logs may contain internal addresses, device identifiers and security events;
redact before sharing.

## Configure File

Select a managed file, then configure:

- **Enabled** to permit writes;
- **Max Size (KB)** before rotation;
- **Max Backup Files** retained after rotation;
- **Channels** as a comma-separated routing list.

**Save** applies the file configuration. **Cancel** closes the modal without applying browser
edits. Small limits can rotate evidence too quickly; large limits consume LittleFS capacity.

## Realtime Stream for Channels

Select a log file and one or more channels. **Start** opens the server-sent-event stream, **Stop**
closes it, **Clear** empties only the browser output, and **Auto-scroll** keeps the newest event in
view. Streaming can be verbose and should not be left open unnecessarily on constrained devices.

[Back to the guide index](README.md)
