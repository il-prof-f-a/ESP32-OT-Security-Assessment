# Reporting Configuration

![Reporting Configuration page](assets/reporting.png)

Reporting Configuration controls how internal events are previewed, queued, formatted, filtered
and delivered to serial, files, MQTT, webhooks, email and other supported channels.

## Live Stream by Reporting Channel

Select one or more channels or **ALL STREAM**, optionally apply channel include/exclude filters,
and add local regular expressions for this browser preview. **Case sensitive** applies to the
local regex. The counters show total events, routed events, ignored events, local include/exclude
matches and regex errors.

**Start Stream** opens the event stream, **Stop Stream** closes it, **Clear** clears the browser
display, and **Collapse** hides the panel without changing reporting configuration. A local preview
filter does not change device-side routing.

## Queue Status

| Metric | Meaning |
| --- | --- |
| **Queued** | Events waiting for a reporter. |
| **Capacity** | Configured queue slots. |
| **Usage %** | Occupied fraction of the queue. |
| **Payload** | Estimated queued data size. |
| **Sync Pending** | Dirty events waiting to be written to persistent backup. |
| **Flush Interval** | Worker flush/reporting interval. |

**Refresh** reloads metrics. **Flush Queue** immediately asks reporters to process queued events;
delivery still depends on endpoint reachability.

## Reporting Channels

**Load Channels** creates a card for every configured channel. Each card can enable the channel,
select JSON/CEE/LEEF/CEF format, select Reports Only or Verbose output, enable filters and choose
case sensitivity. Include filters admit matching events; exclude filters suppress matches. File
reporting also offers log download.

## Reporting Endpoints

**Load** displays endpoint JSON and **Save** validates/applies it. Endpoint data can contain broker
credentials, webhook tokens, SMTP credentials and addresses. Keep exports private and never place
real endpoint secrets in the public repository.

[Back to the guide index](README.md)
