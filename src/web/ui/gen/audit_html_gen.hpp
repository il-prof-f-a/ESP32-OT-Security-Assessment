/* auto-generated from audit.html */
#pragma once
static const char* AUDIT_HTML_GEN = R"HTML(
<!doctype html>
<html><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Audit Manager Configuration</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,"Helvetica Neue",Arial; margin:1rem; background:#f6f6f6; color:#222}
.card{background:#fff; border:1px solid #ddd; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.06); padding:1rem; margin-bottom:1rem}
.btn{background:#007; color:#fff; border:none; padding:.5rem 1rem; border-radius:6px; cursor:pointer; display:inline-block; margin-right:.5rem}
.btn:hover{background:#008}
.btn.danger{background:#c33}
.btn.danger:hover{background:#d44}
.btn.success{background:#28a745}
.btn.success:hover{background:#218838}
.form-group{margin-bottom:.8rem}
label{display:block; margin-bottom:.3rem; font-weight:600}
input,select,textarea{width:100%; padding:.4rem; border:1px solid #ccc; border-radius:4px; box-sizing:border-box}
input[type="checkbox"]{width:auto; margin-right:.5rem}
.status{padding:.5rem; border-radius:4px; margin-bottom:.8rem}
.status.ok{background:#d4edda; color:#155724}
.status.err{background:#f8d7da; color:#721c24}
.status.info{background:#d1ecf1; color:#0c5460}
.tabs{display:flex; gap:.5rem; margin-bottom:1rem}
.tab{padding:.5rem 1rem; background:#ddd; border:none; border-radius:4px; cursor:pointer}
.tab.active{background:#007; color:#fff}
.tab-content{display:none}
.tab-content.active{display:block}
.nav-btn{background:#06a; color:#fff; border:none; padding:.6rem 1rem; border-radius:8px; cursor:pointer; text-decoration:none; display:inline-block}
.nav-btn:hover{background:#07b}
.config-section{background:#f8f9fa; padding:.8rem; border-radius:6px; margin-bottom:.5rem}
.config-label{font-weight:600; color:#495057; margin-bottom:.3rem}
.metrics-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:1rem; margin-top:1rem}
.metric-card{background:#e3f2fd; padding:.8rem; border-radius:6px; text-align:center}
.metric-value{font-size:1.5rem; font-weight:bold; color:#1976d2}
.metric-label{font-size:.9rem; color:#666; margin-top:.3rem}
.log-preview{background:#f8f9fa; border:1px solid #ddd; border-radius:4px; padding:.8rem; max-height:200px; overflow-y:auto; font-family:monospace; font-size:.9rem}
table{width:100%; border-collapse:collapse; margin-top:.5rem}
th,td{padding:.5rem; text-align:left; border-bottom:1px solid #ddd}
th{background:#f8f9fa; font-weight:600}
.event-type{padding:.2rem .5rem; border-radius:12px; font-size:.8rem; font-weight:600}
.event-denied{background:#ffebee; color:#d32f2f}
.event-security{background:#fff3e0; color:#f57c00}
.event-system{background:#e8f5e8; color:#388e3c}
.event-config{background:#f3e5f5; color:#7b1fa2}
</style>

<div class="card">
<h1>🛡️ Audit Manager Configuration</h1>
<a href="/" class="btn nav-btn">← Dashboard</a>
</div>

<div id="status"></div>

<div class="tabs">
<button class="tab active" onclick="showTab('general')">General Settings</button>
<button class="tab" onclick="showTab('logging')">Logging Configuration</button>
<button class="tab" onclick="showTab('filters')">Event Filters</button>
<button class="tab" onclick="showTab('monitoring')">Live Monitoring</button>
<button class="tab" onclick="showTab('analytics')">Analytics</button>
</div>

<!-- General Settings Tab -->
<div class="tab-content active" id="general">
<div class="card">
<h2>⚙️ General Settings</h2>
<div class="form-group">
<label><input type="checkbox" id="audit_enabled"> Enable Audit Manager</label>
</div>
<div class="config-section">
<div class="config-label">Rate Limiting</div>
<div class="form-group">
<label for="max_events_per_second">Maximum Events per Second</label>
<input type="number" id="max_events_per_second" min="1" max="1000" value="50">
<small>Limit the number of audit events processed per second to prevent system overload</small>
</div>
</div>
<button class="btn success" onclick="saveGeneralConfig()">Save General Settings</button>
</div>
</div>

<!-- Logging Configuration Tab -->
<div class="tab-content" id="logging">
<div class="card">
<h2>📝 Logging Configuration</h2>
<p>Configure which types of events should be logged by the audit system:</p>

<div class="config-section">
<div class="config-label">Security Events</div>
<div class="form-group">
<label><input type="checkbox" id="log_denied"> Log Denied Operations</label>
<small>Log when operations are denied due to security policies</small>
</div>
<div class="form-group">
<label><input type="checkbox" id="log_security_events"> Log Security Events</label>
<small>Log authentication, authorization, and security-related events</small>
</div>
</div>

<div class="config-section">
<div class="config-label">System Events</div>
<div class="form-group">
<label><input type="checkbox" id="log_timeouts"> Log Timeout Events</label>
<small>Log when operations timeout or connections are dropped</small>
</div>
<div class="form-group">
<label><input type="checkbox" id="log_ratelimits"> Log Rate Limit Events</label>
<small>Log when rate limiting is applied to prevent abuse</small>
</div>
<div class="form-group">
<label><input type="checkbox" id="log_system_events"> Log System Audit Events</label>
<small>Log general system operations and administrative actions</small>
</div>
</div>

<div class="config-section">
<div class="config-label">Configuration Events</div>
<div class="form-group">
<label><input type="checkbox" id="log_config_changes"> Log Configuration Changes</label>
<small>Log when system configuration is modified</small>
</div>
</div>

<button class="btn success" onclick="saveLoggingConfig()">Save Logging Configuration</button>
</div>
</div>

<!-- Filters Tab -->
<div class="tab-content" id="filters">
<div class="card">
<h2>🔍 Event Filters</h2>
<div class="form-group">
<label><input type="checkbox" id="filters_enabled"> Enable Event Filtering</label>
</div>
<div class="form-group">
<label><input type="checkbox" id="case_sensitive"> Case Sensitive Matching</label>
</div>
<div class="form-group">
<label for="include_patterns">Include Patterns (one per line)</label>
<textarea id="include_patterns" rows="4" placeholder="security_event&#10;denied_access&#10;config_change&#10;system_alert"></textarea>
<small>Only events matching these patterns will be processed</small>
</div>
<div class="form-group">
<label for="exclude_patterns">Exclude Patterns (one per line)</label>
<textarea id="exclude_patterns" rows="4" placeholder="debug&#10;trace&#10;heartbeat"></textarea>
<small>Events matching these patterns will be ignored</small>
</div>
<button class="btn success" onclick="saveFilterConfig()">Save Filter Settings</button>
</div>
</div>

<!-- Live Monitoring Tab -->
<div class="tab-content" id="monitoring">
<div class="card">
<h2>📊 Live Audit Monitoring</h2>
<div class="metrics-grid">
<div class="metric-card">
<div class="metric-value" id="events_today">0</div>
<div class="metric-label">Events Today</div>
</div>
<div class="metric-card">
<div class="metric-value" id="denied_events">0</div>
<div class="metric-label">Denied Operations</div>
</div>
<div class="metric-card">
<div class="metric-value" id="security_events">0</div>
<div class="metric-label">Security Events</div>
</div>
<div class="metric-card">
<div class="metric-value" id="events_per_minute">0</div>
<div class="metric-label">Events/Minute</div>
</div>
</div>

<h3>Recent Audit Events</h3>
<div style="margin-bottom:.5rem;">
<button class="btn" onclick="refreshEvents()">🔄 Refresh</button>
<button class="btn" onclick="clearEventLog()">🗑️ Clear Log</button>
<label><input type="checkbox" id="auto_refresh"> Auto-refresh (5s)</label>
</div>

<table id="events_table">
<thead>
<tr>
<th>Time</th>
<th>Type</th>
<th>Actor</th>
<th>Event</th>
<th>Details</th>
</tr>
</thead>
<tbody id="events_tbody">
<tr><td colspan="5">Loading recent events...</td></tr>
</tbody>
</table>
</div>
</div>

<!-- Analytics Tab -->
<div class="tab-content" id="analytics">
<div class="card">
<h2>📈 Audit Analytics</h2>
<div class="form-group">
<label for="analytics_period">Analysis Period</label>
<select id="analytics_period" onchange="loadAnalytics()">
<option value="1h">Last Hour</option>
<option value="24h" selected>Last 24 Hours</option>
<option value="7d">Last 7 Days</option>
<option value="30d">Last 30 Days</option>
</select>
</div>

<h3>Event Type Distribution</h3>
<div id="event_distribution">Loading analytics...</div>

<h3>Top Security Events</h3>
<div id="top_events">Loading top events...</div>

<h3>Activity Timeline</h3>
<div id="activity_timeline">Loading timeline...</div>

<button class="btn" onclick="exportAuditData()">📁 Export Audit Data</button>
</div>
</div>

<script>
  (function() {
    const urlParams = new URLSearchParams(window.location.search);
    const sessionToken = urlParams.get('sid');

    if (sessionToken) {
        console.log('Session token found');

        // Override fetch to automatically add Bearer token to API calls
        const originalFetch = window.fetch;
        if (!window.__apiFetchQueue) {
            window.__apiFetchQueue = Promise.resolve();
        }
        window.fetch = function(url, options = {}) {
            const isApiCall = typeof url === 'string' && url.startsWith('/api/');
            if (!isApiCall) {
                return originalFetch.call(this, url, options);
            }

            const opts = {...options};
            opts.headers = {...(options && options.headers) || {}};
            opts.headers['Authorization'] = 'Bearer ' + sessionToken;

            const runner = () => originalFetch.call(window, url, opts);
            const queued = window.__apiFetchQueue.then(runner, runner);
            window.__apiFetchQueue = queued.catch(() => {});
            return queued;
        };

        // Update navigation links to include session token
        document.querySelectorAll('.nav-btn').forEach(link => {
            const href = link.getAttribute('href');
            if (href && !href.includes('sid=')) {
                link.setAttribute('href', href + '?sid=' + encodeURIComponent(sessionToken));
            }
        });
    } else {
        console.warn('No session token found in URL - API calls may fail');
    }
})();

let config = {};
let autoRefreshInterval = null;

// Tab management
function showTab(tabName) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
  document.getElementById(tabName).classList.add('active');

  if (tabName === 'monitoring') {
    refreshEvents();
    refreshMetrics();
  } else if (tabName === 'analytics') {
    loadAnalytics();
  }
}

// Load configuration on page load
async function loadConfig(override) {
  try {
    if (override) {
      config = override;
      populateForm();
      showStatus('Configuration loaded successfully', 'ok');
      return;
    }

    const response = await fetch('/api/audit/config', { cache: 'no-store' });
    if (response.ok) {
      config = await response.json();
      populateForm();
      showStatus('Configuration loaded successfully', 'ok');
    } else {
      showStatus('Failed to load configuration', 'err');
    }
  } catch (error) {
    showStatus('Error loading configuration: ' + error.message, 'err');
  }
}

// Populate form fields with current configuration
function populateForm() {
  // General settings
  document.getElementById('audit_enabled').checked = config.enabled || false;

  if (config.rate_limiting) {
    document.getElementById('max_events_per_second').value = config.rate_limiting.max_events_per_second || 50;
  }

  // Logging configuration
  if (config.logging) {
    document.getElementById('log_denied').checked = config.logging.log_denied || false;
    document.getElementById('log_timeouts').checked = config.logging.log_timeouts || false;
    document.getElementById('log_ratelimits').checked = config.logging.log_ratelimits || false;
    document.getElementById('log_system_events').checked = config.logging.log_system_events || false;
    document.getElementById('log_security_events').checked = config.logging.log_security_events || false;
    document.getElementById('log_config_changes').checked = config.logging.log_config_changes || false;
  }

  // Filter settings
  if (config.filters) {
    document.getElementById('filters_enabled').checked = config.filters.enabled || false;
    document.getElementById('case_sensitive').checked = config.filters.case_sensitive || false;
    document.getElementById('include_patterns').value = (config.filters.include || []).join('\n');
    document.getElementById('exclude_patterns').value = (config.filters.exclude || []).join('\n');
  }
}

// Save configuration functions
async function saveGeneralConfig() {
  const newConfig = {
    enabled: document.getElementById('audit_enabled').checked,
    rate_limiting: {
      max_events_per_second: parseInt(document.getElementById('max_events_per_second').value)
    }
  };
  await saveConfig(newConfig, 'General settings saved successfully');
}

async function saveLoggingConfig() {
  const newConfig = {
    logging: {
      log_denied: document.getElementById('log_denied').checked,
      log_timeouts: document.getElementById('log_timeouts').checked,
      log_ratelimits: document.getElementById('log_ratelimits').checked,
      log_system_events: document.getElementById('log_system_events').checked,
      log_security_events: document.getElementById('log_security_events').checked,
      log_config_changes: document.getElementById('log_config_changes').checked
    }
  };
  await saveConfig(newConfig, 'Logging configuration saved successfully');
}

async function saveFilterConfig() {
  const includeText = document.getElementById('include_patterns').value;
  const excludeText = document.getElementById('exclude_patterns').value;

  const newConfig = {
    filters: {
      enabled: document.getElementById('filters_enabled').checked,
      case_sensitive: document.getElementById('case_sensitive').checked,
      include: includeText ? includeText.split('\n').filter(line => line.trim()) : [],
      exclude: excludeText ? excludeText.split('\n').filter(line => line.trim()) : []
    }
  };
  await saveConfig(newConfig, 'Filter settings saved successfully');
}

// Generic save function
async function saveConfig(newConfig, successMessage) {
  try {
    // Merge with existing config
    const mergedConfig = { ...config, ...newConfig };

    const response = await fetch('/api/audit/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(mergedConfig)
    });

    if (response.ok) {
      config = mergedConfig;
      showStatus(successMessage, 'ok');
    } else {
      showStatus('Failed to save configuration', 'err');
    }
  } catch (error) {
    showStatus('Error saving configuration: ' + error.message, 'err');
  }
}

// Monitoring functions
async function refreshEvents() {
  try {
    const response = await fetch('/api/audit/events?limit=50');
    if (response.ok) {
      const events = await response.json();
      updateEventsTable(events);
    } else {
      document.getElementById('events_tbody').innerHTML = '<tr><td colspan="5">Failed to load events</td></tr>';
    }
  } catch (error) {
    document.getElementById('events_tbody').innerHTML = `<tr><td colspan="5">Error: ${error.message}</td></tr>`;
  }
}

function updateEventsTable(events) {
  const tbody = document.getElementById('events_tbody');
  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5">No recent events</td></tr>';
    return;
  }

  const rows = events.map(event => {
    const eventTypeClass = getEventTypeClass(event.type);
    return `
      <tr>
        <td>${new Date(event.timestamp).toLocaleString()}</td>
        <td><span class="event-type ${eventTypeClass}">${event.type}</span></td>
        <td>${event.actor || 'System'}</td>
        <td>${event.event}</td>
        <td>${event.details || ''}</td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rows;
}

function getEventTypeClass(type) {
  if (type.includes('denied') || type.includes('blocked')) return 'event-denied';
  if (type.includes('security') || type.includes('auth')) return 'event-security';
  if (type.includes('config') || type.includes('change')) return 'event-config';
  return 'event-system';
}

async function refreshMetrics(override) {
  try {
    const metrics = override || await (async () => {
      const response = await fetch('/api/audit/metrics', { cache: 'no-store' });
      if (!response.ok) return null;
      return await response.json();
    })();

    if (!metrics) return;

    // Backward/forward compatibility with different schemas.
    const m = metrics.metrics ? metrics.metrics : metrics;
    document.getElementById('events_today').textContent = m.events_today || m.total_events || 0;
    document.getElementById('denied_events').textContent = m.denied_events || m.denied || 0;
    document.getElementById('security_events').textContent = m.security_events || 0;
    document.getElementById('events_per_minute').textContent = m.events_per_minute || 0;
  } catch (error) {
    console.error('Error loading metrics:', error);
  }
}

async function clearEventLog() {
  if (confirm('Are you sure you want to clear the audit event log?')) {
    try {
      const response = await fetch('/api/audit/events', { method: 'DELETE' });
      if (response.ok) {
        refreshEvents();
        showStatus('Event log cleared successfully', 'ok');
      } else {
        showStatus('Failed to clear event log', 'err');
      }
    } catch (error) {
      showStatus('Error clearing event log: ' + error.message, 'err');
    }
  }
}

// Analytics functions
async function loadAnalytics() {
  const period = document.getElementById('analytics_period').value;
  try {
    const response = await fetch(`/api/audit/analytics?period=${period}`);
    if (response.ok) {
      const analytics = await response.json();
      updateAnalytics(analytics);
    } else {
      showAnalyticsError('Failed to load analytics');
    }
  } catch (error) {
    showAnalyticsError('Error loading analytics: ' + error.message);
  }
}

function updateAnalytics(analytics) {
  // Event distribution
  if (analytics.distribution) {
    let distributionHtml = '<div style="margin-top:.5rem;">';
    Object.entries(analytics.distribution).forEach(([type, count]) => {
      const percentage = ((count / analytics.total_events) * 100).toFixed(1);
      distributionHtml += `<div style="margin-bottom:.3rem;"><strong>${type}:</strong> ${count} (${percentage}%)</div>`;
    });
    distributionHtml += '</div>';
    document.getElementById('event_distribution').innerHTML = distributionHtml;
  }

  // Top events
  if (analytics.top_events) {
    let topEventsHtml = '<table style="margin-top:.5rem;"><thead><tr><th>Event</th><th>Count</th></tr></thead><tbody>';
    analytics.top_events.forEach(event => {
      topEventsHtml += `<tr><td>${event.event}</td><td>${event.count}</td></tr>`;
    });
    topEventsHtml += '</tbody></table>';
    document.getElementById('top_events').innerHTML = topEventsHtml;
  }

  // Activity timeline would require a chart library - for now show simple summary
  if (analytics.timeline) {
    let timelineHtml = '<div style="margin-top:.5rem;">Activity peaks:<br>';
    analytics.timeline.forEach(peak => {
      timelineHtml += `<div>${peak.hour}:00 - ${peak.events} events</div>`;
    });
    timelineHtml += '</div>';
    document.getElementById('activity_timeline').innerHTML = timelineHtml;
  }
}

function showAnalyticsError(message) {
  document.getElementById('event_distribution').innerHTML = `<div class="status err">${message}</div>`;
  document.getElementById('top_events').innerHTML = '';
  document.getElementById('activity_timeline').innerHTML = '';
}

async function exportAuditData() {
  try {
    const period = document.getElementById('analytics_period').value;
    const response = await fetch(`/api/audit/export?period=${period}`);

    if (response.ok) {
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_data_${period}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      showStatus('Audit data exported successfully', 'ok');
    } else {
      showStatus('Failed to export audit data', 'err');
    }
  } catch (error) {
    showStatus('Error exporting audit data: ' + error.message, 'err');
  }
}

// Auto-refresh handling
document.getElementById('auto_refresh').addEventListener('change', function() {
  if (this.checked) {
    autoRefreshInterval = setInterval(() => {
      refreshEvents();
      refreshMetrics();
    }, 5000);
  } else {
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
    }
  }
});

// Utility function
function showStatus(message, type) {
  const statusDiv = document.getElementById('status');
  statusDiv.innerHTML = `<div class="status ${type}">${message}</div>`;
  setTimeout(() => statusDiv.innerHTML = '', 5000);
}

// Initialize page
document.addEventListener('DOMContentLoaded', () => {
  (async () => {
    try {
      let boot = null;
      try {
        const r = await fetch('/api/page/bootstrap?name=audit', { cache: 'no-store' });
        if (r && r.ok) boot = await r.json();
      } catch (e) { boot = null; }

      if (boot && boot.data) {
        await loadConfig(boot.data.audit_config || null);
        await refreshMetrics(boot.data.audit_metrics || null);
      } else {
        await loadConfig();
        await refreshMetrics();
      }
    } catch (err) {
      console.error('Audit page initial load failed:', err);
    }
  })();
});
</script>
</html>

)HTML";

// Compile-time size constant (actual content length)
static constexpr size_t AUDIT_HTML_GEN_SIZE = 22060;
