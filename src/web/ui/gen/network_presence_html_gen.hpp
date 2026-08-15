/* auto-generated from network_presence.html */
#pragma once
static const char* NETWORK_PRESENCE_HTML_GEN = R"HTML(
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NetworkPresence • Device Learning & Trust</title>
 <style>
/* Baseline “GIUSTO” */
:root{
  --ok:#268c2f;
  --warn:#d29922;
  --danger:#c33;
  --muted:#666;
}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,"Helvetica Neue",Arial; margin:1rem; background:#f6f6f6; color:#222}
.container{max-width:1100px;margin:0 auto}

/* Card / layout */
.card{background:#fff; border:1px solid #ddd; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.06); padding:1rem; margin-bottom:1rem}
.full-width{grid-column:1 / -1}
.grid{display:grid; gap:16px}
.row{display:flex; gap:12px; flex-wrap:wrap; align-items:center}

/* Tipografia */
h1{font-size:1.4rem;margin:0 0 1rem 0}
h2{font-size:1.15rem;margin:0 0 .5rem 0}
label{display:block;margin-bottom:.3rem;font-weight:600;color:#333}
.muted{color:var(--muted)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,Monaco,monospace; font-size:12px; background:#f8f9fa; padding:.1rem .3rem; border-radius:4px; color:#222}

/* Form */
.form-group{margin-bottom:.8rem}
input,select,textarea{width:100%; padding:.45rem .6rem; border:1px solid #ccc; border-radius:4px; background:#fff; color:#222}
.switch{display:inline-flex; align-items:center; gap:.5rem}

/* Bottoni */
.btn{background:#007; color:#fff; border:none; padding:.5rem 1rem; border-radius:6px; cursor:pointer; display:inline-block; margin-right:.5rem}
.btn:hover{background:#008}
.btn.small{font-size:.9rem; padding:.35rem .7rem}
.btn.ghost{background:transparent; color:#333; border:1px solid #bbb}
.btn.danger{background:#c33}
.btn.danger:hover{background:#d44}
/* Varianti utili già usate nello script */
.btn.primary{background:#06a}
.btn.primary:hover{background:#07b}
.btn.success{background:#268c2f}
.btn.success:hover{background:#2fa73a}

/* Tabelle */
table{width:100%; border-collapse:collapse}
th,td{padding:.5rem; text-align:left; border-bottom:1px solid #eee}
th{background:#f8f9fa; color:#333}

/* Indicatori / badge */
.pill,.tag{display:inline-flex; gap:.5rem; align-items:center; padding:.25rem .5rem; border-radius:999px; background:#eef5ff; border:1px solid #cfe8ff; color:#113}
.tag.trusted{background:#d4edda;border-color:#b6dfc1;color:#155724}
.tag.learned{background:#fff3cd;border-color:#f0de9b;color:#856404}
.tag.untrusted{background:#f8d7da;border-color:#efb8bf;color:#721c24}
.tag.role-reader{background:#e7f3ff;border-color:#b8dbff;color:#114a7a}
.tag.role-writer{background:#ffe8e8;border-color:#f2bcbc;color:#7a1111}
.tag.role-rw{background:#efe6ff;border-color:#d7c3ff;color:#3f1c7a}
.tag.role-sender{background:#e8f7ef;border-color:#bee8cf;color:#12522f}
.tag.role-unknown{background:#f0f0f0;border-color:#ddd;color:#555}
.success{background:#d4edda !important; color:#155724 !important}
.warning{background:#fff3cd !important; color:#856404 !important}
.danger{background:#f8d7da !important; color:#721c24 !important}
.device-active{color:#155724}
.device-inactive{color:#721c24}

/* Blocchi statistiche (se presenti) */
.stats{display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px}
.stat{background:#f8f9fa; border:1px solid #e6e6e6; border-radius:8px; padding:.6rem .8rem}
.stat-number{font-weight:700; font-size:1.2rem}

/* Toast */
.toast{position:fixed; right:16px; bottom:16px; background:#fff; color:#222; border:1px solid #ddd; border-radius:10px; padding:10px 12px; box-shadow:0 10px 20px rgba(0,0,0,.08); display:none}
.toast.show{display:block}

/* Pulsanti per "Device per Protocollo" (senza modificare l'HTML) */
.card h2 + .row a,
.card h2 + .row button,
.card h2 + .row .clickable {
  appearance: none;
  display: inline-flex;
  align-items: center;
  gap: .4rem;
  padding: .38rem .72rem;
  margin: 0 .5rem .5rem 0;
  border-radius: 6px;
  background: #007;
  color: #fff;
  border: 1px solid #006;
  text-decoration: none;
  cursor: pointer;
  line-height: 1.2;
  box-shadow: 0 1px 2px rgba(0,0,0,.06);
  transition: background .15s ease, border-color .15s ease, transform .02s;
}
.card h2 + .row a:hover,
.card h2 + .row button:hover,
.card h2 + .row .clickable:hover {
  background: #008;
  border-color: #007;
}
.card h2 + .row a:active,
.card h2 + .row button:active,
.card h2 + .row .clickable:active {
  transform: translateY(1px);
}
/* Stato attivo/selezionato opzionale */
.card h2 + .row a.is-active,
.card h2 + .row .clickable.is-active {
  background: #06a;
  border-color: #06a;
}
/* Variante "ghost" opzionale (bordo grigio) */
.card h2 + .row a.btn-ghost,
.card h2 + .row .clickable.btn-ghost {
  background: transparent;
  color: #333;
  border: 1px solid #bbb;
}
/* Accessibilità: focus visibile con tastiera */
.card h2 + .row a:focus-visible,
.card h2 + .row button:focus-visible,
.card h2 + .row .clickable:focus-visible {
  outline: 2px solid #58a6ff;
  outline-offset: 2px;
}

/* === PROTOCOL TABS come pulsanti === */
.protocol-tabs{
  display:flex;
  flex-wrap:wrap;
  gap:.5rem;
  margin:.25rem 0 .75rem 0;
}
.protocol-tab{
  appearance:none;
  display:inline-flex;
  align-items:center;
  gap:.4rem;
  padding:.42rem .78rem;
  border-radius:999px;            /* pill */
  background:#007;
  color:#fff;
  border:1px solid #006;
  cursor:pointer;
  user-select:none;
  line-height:1.1;
  text-decoration:none;
  box-shadow:0 1px 2px rgba(0,0,0,.06);
  transition:background .15s ease, border-color .15s ease, transform .02s, box-shadow .15s ease;
}
.protocol-tab:hover{
  background:#008;
  border-color:#007;
}
.protocol-tab:active{
  transform:translateY(1px);
}
.protocol-tab:focus-visible{
  outline:2px solid #58a6ff;
  outline-offset:2px;
}
/* attivo/selezionato */
.protocol-tab.active{
  background:#06a;
  border-color:#06a;
  box-shadow:0 0 0 2px rgba(6,170,255,.12);
}

/* Stato disabilitato (se mai usato) */
.protocol-tab[aria-disabled="true"],
.protocol-tab.disabled{
  opacity:.6;
  cursor:not-allowed;
  pointer-events:none;
}

/* Lista device: minime rifiniture (facoltative ma utili) */
.device-list .device-row{
  display:grid;
  grid-template-columns: 1.2fr auto 1fr auto auto auto;
  gap:.6rem;
  align-items:center;
  padding:.6rem .75rem;
  border:1px solid #e9ecef;
  border-radius:8px;
  background:#fff;
  margin-bottom:.5rem;
}
.device-ip{font-weight:600}
.device-mac{font-size:12px; color:var(--muted)}
.score-bar{width:140px; height:8px; background:#eef2f7; border-radius:999px; overflow:hidden; border:1px solid #e1e6ee}
.score-fill{height:100%; width:0%}

/* Empty state */
.empty-state{padding:1rem; color:#555; text-align:center}
</style>

</head>
<body>

 <div class="card">
<h1>🔍 NetworkPresence • Device Learning & Trust</h1>
<a href="/" class="btn nav-btn">← Dashboard</a>
</div>

  <main>
    <!-- Configuration Panel -->
    <div class="grid">
      <div class="card">
        <h2>⚙️ Configurazione Learning</h2>
        <div class="flex" style="margin-bottom:12px">
          <div class="switch">
            <input type="checkbox" id="enabled">
            <label for="enabled">Sistema Abilitato</label>
          </div>
          <div class="switch">
            <input type="checkbox" id="learning_mode">
            <label for="learning_mode">Modalità Learning</label>
          </div>
        </div>
        
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:12px 0">
          <div>
            <label>Delay Attivazione (min)</label>
            <input type="number" id="activation_delay" min="1" max="60">
          </div>
          <div>
            <label>Retention (giorni)</label>
            <input type="number" id="retention_days" min="1" max="365">
          </div>
          <div>
            <label>Soglia Trust (0-1)</label>
            <input type="number" id="trust_threshold" min="0" max="1" step="0.1">
          </div>
          <div>
            <label>Periodo Osservazione (ore)</label>
            <input type="number" id="observation_hours" min="1" max="168">
          </div>
        </div>
        
        <div class="row">
          <button class="btn primary" onclick="saveConfig()">💾 Salva Configurazione</button>
          <button class="btn danger" onclick="clearAllLearning()" title="Elimina tutti i device appresi">🗑️ Reset Learning</button>
        </div>
      </div>

      <!-- Statistics -->
      <div class="card">
        <h2>📊 Statistiche Globali</h2>
        <div id="globalStats" class="stats">
          <div class="stat">
            <div class="stat-number" id="totalDevices">-</div>
            <div class="stat-label">Device Totali</div>
          </div>
          <div class="stat">
            <div class="stat-number" id="trustedDevices">-</div>
            <div class="stat-label">Trusted</div>
          </div>
          <div class="stat">
            <div class="stat-number" id="learnedDevices">-</div>
            <div class="stat-label">Appresi</div>
          </div>
          <div class="stat">
            <div class="stat-number" id="untrustedDevices">-</div>
            <div class="stat-label">Non Trusted</div>
          </div>
        </div>
        
        <div class="row">
          <button class="btn" onclick="refreshStats()">🔄 Aggiorna</button>
          <button class="btn ghost" onclick="exportData()">📥 Esporta Dati</button>
        </div>
      </div>
    </div>

    <!-- Protocol Devices -->
    <div class="card full-width">
      <div class="section-header">
        <h2>🔌 Device per Protocollo</h2>
        <div class="row">
          <button class="btn ghost small" onclick="refreshDevices()">🔄 Aggiorna</button>
          <button class="btn ghost small" onclick="toggleAutoRefresh()" id="autoRefreshBtn">⏱️ Auto Refresh</button>
        </div>
      </div>

      <!-- Protocol Tabs -->
      <div class="protocol-tabs" id="protocolTabs">
        <div class="protocol-tab active" data-protocol="all">🌐 Tutti</div>
        <div class="protocol-tab" data-protocol="modbus">🔧 Modbus</div>
        <div class="protocol-tab" data-protocol="s7">🏭 S7</div>
        <div class="protocol-tab" data-protocol="opcua">📡 OPC-UA</div>
        <div class="protocol-tab" data-protocol="profinet">🔗 Profinet</div>
        <div class="protocol-tab" data-protocol="ethernetip">🌐 EtherNet/IP</div>
      </div>

      <!-- Device List -->
      <div id="deviceList" class="device-list">
        <div class="empty-state" id="emptyState">
          <div>🔍 Caricamento device in corso...</div>
        </div>
      </div>
    </div>
  </main>

  <!-- Toast notifications -->
  <div id="toast" class="toast"></div>

  <script>

    // Extract session token from URL and add to all API calls
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

    let currentProtocol = 'all';
    let autoRefreshTimer = null;
    let devices = [];
    let presenceClockMs = 0;
    let config = {};

    async function loadBootstrap() {
      try {
        const r = await fetch('/api/page/bootstrap?name=network_presence', { cache: 'no-store' });
        if (!r.ok) return null;
        return await r.json();
      } catch (_) {
        return null;
      }
    }

    function applyBootstrapConfig(cfg) {
      config = cfg || {};
      document.getElementById('enabled').checked = config.enabled || false;
      document.getElementById('learning_mode').checked = config.learning_mode || false;
      document.getElementById('activation_delay').value = config.activation_delay_minutes || 10;
      document.getElementById('retention_days').value = config.retention_days || 30;
      document.getElementById('trust_threshold').value = config.trust_threshold_score || 0.75;
      document.getElementById('observation_hours').value = config.min_observation_period_hours || 24;
    }

    function applyBootstrapStats(data) {
      const deviceArray = Array.isArray(data && data.devices) ? data.devices : [];
      const totalDevices = (data && typeof data.total_devices === 'number') ? data.total_devices : deviceArray.length;

      presenceClockMs = (data && typeof data.current_time_ms === 'number') ? data.current_time_ms : presenceClockMs;

      let trustedDevices = 0;
      let learnedDevices = 0;

      deviceArray.forEach(device => {
        const isLearned = isLearnedTrustDevice(device);
        const isTrusted = isTrustedSenderDevice(device) || isTrustedWriterDevice(device);
        if (isTrusted) trustedDevices++;
        if (isLearned) learnedDevices++;
      });

      const untrustedDevices = Math.max(0, totalDevices - trustedDevices);

      document.getElementById('totalDevices').textContent = totalDevices;
      document.getElementById('trustedDevices').textContent = trustedDevices;
      document.getElementById('learnedDevices').textContent = learnedDevices;
      document.getElementById('untrustedDevices').textContent = untrustedDevices;
    }

    function isTrustedSenderDevice(device) {
      return Boolean(device && (device.is_trusted_sender || device.is_whitelisted || device.is_learned_sender || device.is_persistent));
    }

    function isTrustedWriterDevice(device) {
      return Boolean(device && (device.is_trusted_writer || device.is_whitelisted || device.is_learned_writer));
    }

    function isLearnedTrustDevice(device) {
      return Boolean(device && (device.is_learned_sender || device.is_learned_writer));
    }

    function getDeviceOperationRole(device) {
      if (!device || typeof device !== 'object') {
        return { key: 'unknown', label: 'Unknown', css: 'role-unknown' };
      }

      const explicitRole = typeof device.operation_role === 'string' ? device.operation_role : '';
      if (explicitRole === 'reader_writer') return { key: explicitRole, label: 'Reader+Writer', css: 'role-rw' };
      if (explicitRole === 'reader_only') return { key: explicitRole, label: 'Reader', css: 'role-reader' };
      if (explicitRole === 'writer_only') return { key: explicitRole, label: 'Writer', css: 'role-writer' };
      if (explicitRole === 'sender_only') return { key: explicitRole, label: 'Sender only', css: 'role-sender' };

      const readPackets = Number(device.total_read_packets || 0);
      const writePackets = Number(device.total_write_packets || 0);
      const totalPackets = Number(device.total_packets || 0);
      if (writePackets > 0 && readPackets > 0) return { key: 'reader_writer', label: 'Reader+Writer', css: 'role-rw' };
      if (writePackets > 0) return { key: 'writer_only', label: 'Writer', css: 'role-writer' };
      if (readPackets > 0) return { key: 'reader_only', label: 'Reader', css: 'role-reader' };
      if (totalPackets > 0) return { key: 'sender_only', label: 'Sender only', css: 'role-sender' };
      return { key: 'unknown', label: 'Unknown', css: 'role-unknown' };
    }

    // Load initial data
    window.addEventListener('DOMContentLoaded', function() {
      (async () => {
        try {
          const boot = await loadBootstrap();
          if (boot && boot.data) {
            if (boot.data.presence_config) {
              applyBootstrapConfig(boot.data.presence_config);
            }
            if (boot.data.presence_stats) {
              applyBootstrapStats(boot.data.presence_stats);
            }
            if (boot.data.presence_devices) {
              const d = boot.data.presence_devices;
              presenceClockMs = typeof d.current_time_ms === 'number' ? d.current_time_ms : presenceClockMs;
              devices = Array.isArray(d.devices) ? d.devices : [];
              renderDevices();
            }
            setupProtocolTabs();
            return;
          }
          await loadConfig();
          await refreshStats();
          await refreshDevices();
          setupProtocolTabs();
        } catch (err) {
          console.error('Network presence initial load failed:', err);
        }
      })();
    });

    function setupProtocolTabs() {
      document.querySelectorAll('.protocol-tab').forEach(tab => {
        tab.addEventListener('click', function() {
          document.querySelectorAll('.protocol-tab').forEach(t => t.classList.remove('active'));
          this.classList.add('active');
          currentProtocol = this.dataset.protocol;
          renderDevices();
        });
      });
    }

    async function loadConfig() {
      try {
        const response = await fetch('/api/ids/presence/config');
        config = await response.json();
        
        document.getElementById('enabled').checked = config.enabled || false;
        document.getElementById('learning_mode').checked = config.learning_mode || false;
        document.getElementById('activation_delay').value = config.activation_delay_minutes || 10;
        document.getElementById('retention_days').value = config.retention_days || 30;
        document.getElementById('trust_threshold').value = config.trust_threshold_score || 0.75;
        document.getElementById('observation_hours').value = config.min_observation_period_hours || 24;
      } catch (error) {
        showToast('❌ Errore caricamento configurazione', 'error');
      }
    }

    async function saveConfig() {
      const newConfig = {
        enabled: document.getElementById('enabled').checked,
        learning_mode: document.getElementById('learning_mode').checked,
        activation_delay_minutes: parseInt(document.getElementById('activation_delay').value),
        retention_days: parseInt(document.getElementById('retention_days').value),
        trust_threshold_score: parseFloat(document.getElementById('trust_threshold').value),
        min_observation_period_hours: parseInt(document.getElementById('observation_hours').value)
      };

      try {
        const response = await fetch('/api/ids/presence/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(newConfig)
        });

        if (response.ok) {
          showToast('✅ Configurazione salvata', 'success');
          config = newConfig;
        } else {
          throw new Error('Errore salvataggio');
        }
      } catch (error) {
        showToast('❌ Errore salvataggio configurazione', 'error');
      }
    }

    async function refreshStats() {
      try {
        const response = await fetch('/api/ids/presence/stats');
        const data = await response.json();

        const deviceArray = Array.isArray(data.devices) ? data.devices : [];
        const totalDevices = typeof data.total_devices === 'number' ? data.total_devices : deviceArray.length;

        presenceClockMs = typeof data.current_time_ms === 'number' ? data.current_time_ms : presenceClockMs;

        let trustedDevices = 0;
        let learnedDevices = 0;

        deviceArray.forEach(device => {
          const isLearned = isLearnedTrustDevice(device);
          const isTrusted = isTrustedSenderDevice(device) || isTrustedWriterDevice(device);

          if (isTrusted) trustedDevices++;
          if (isLearned) learnedDevices++;
        });

        const untrustedDevices = Math.max(0, totalDevices - trustedDevices);

        document.getElementById('totalDevices').textContent = totalDevices;
        document.getElementById('trustedDevices').textContent = trustedDevices;
        document.getElementById('learnedDevices').textContent = learnedDevices;
        document.getElementById('untrustedDevices').textContent = untrustedDevices;
      } catch (error) {
        showToast('Errore caricamento statistiche', 'error');
      }
    }

    async function refreshDevices() {
      const deviceListElement = document.getElementById('deviceList');
      deviceListElement.classList.add('loading');

      try {
        const response = await fetch('/api/ids/presence/devices');
        const data = await response.json();

        presenceClockMs = typeof data.current_time_ms === 'number' ? data.current_time_ms : presenceClockMs;
        devices = Array.isArray(data.devices) ? data.devices : [];

        renderDevices();
      } catch (error) {
        showToast('Errore caricamento device', 'error');
      } finally {
        deviceListElement.classList.remove('loading');
      }
    }

    function normalizeProtocolKey(label) {
      return typeof label === 'string'
        ? label.toLowerCase().replace(/[^a-z0-9]/g, '')
        : '';
    }

    function extractProtocolLabels(device) {
      if (!device || typeof device !== 'object') return [];
      const labels = [];

      if (Array.isArray(device.protocols)) {
        device.protocols.forEach(proto => {
          if (typeof proto === 'string' && proto) {
            labels.push(proto);
          } else if (proto && typeof proto === 'object' && typeof proto.name === 'string') {
            labels.push(proto.name);
          }
        });
      }

      if (device.protocol_counts && typeof device.protocol_counts === 'object') {
        Object.keys(device.protocol_counts).forEach(key => {
          if (key) labels.push(key);
        });
      }

      if (typeof device.protocol === 'string' && device.protocol) {
        labels.push(device.protocol);
      }

      if (typeof device.primary_protocol === 'string' && device.primary_protocol) {
        labels.push(device.primary_protocol);
      }

      return labels;
    }

    function deviceMatchesProtocol(device, selectedProtocol) {
      if (selectedProtocol === 'all') return true;
      const labels = extractProtocolLabels(device);
      if (labels.length === 0) return false;
      const normalizedSelected = normalizeProtocolKey(selectedProtocol);
      return labels.some(label => normalizeProtocolKey(label).includes(normalizedSelected));
    }

    function renderDevices() {
      const deviceListElement = document.getElementById('deviceList');
      const deviceArray = Array.isArray(devices) ? devices : [];
      const filteredDevices = deviceArray.filter(device => deviceMatchesProtocol(device, currentProtocol));

      if (filteredDevices.length === 0) {
        deviceListElement.innerHTML = '<div class="empty-state">Nessun device trovato per questo protocollo</div>';
        return;
      }

      filteredDevices.sort((a, b) => (b.presence_score || 0) - (a.presence_score || 0));

      let html = '';
      filteredDevices.forEach(device => {
        const ip = device.ip_address || device.ip || '';
        const mac = device.mac_address || device.mac || 'N/A';
        const isLearned = isLearnedTrustDevice(device);
        const trustedSender = isTrustedSenderDevice(device);
        const trustedWriter = isTrustedWriterDevice(device);
        const isTrusted = trustedSender || trustedWriter;
        const role = getDeviceOperationRole(device);
        const protocols = extractProtocolLabels(device);
        const protocolLabel = protocols.length > 0 ? protocols[0] : 'n/d';
        const displayIp = ip || 'N/A';
        const scorePercent = Math.round((device.presence_score || 0) * 100);
        const scoreColor = scorePercent >= 75 ? 'var(--ok)' : scorePercent >= 50 ? 'var(--warn)' : 'var(--danger)';

        let trustTagClass = 'untrusted';
        let trustText = 'Non trusted';
        if (isTrusted) {
          trustTagClass = 'trusted';
          trustText = trustedSender && trustedWriter ? 'Trusted S+W' : (trustedWriter ? 'Trusted Writer' : 'Trusted Sender');
          if (device.is_whitelisted) {
            trustText = 'Whitelist';
          } else if (isLearned) {
            trustTagClass = 'learned';
            trustText = trustedSender && trustedWriter ? 'Appreso S+W' : (trustedWriter ? 'Appreso Writer' : 'Appreso Sender');
          }
        }

        const canManageTrust = Boolean(ip);
        const promoteLabel = trustedSender && !trustedWriter ? 'Trust writer' : 'Promuovi';
        const promoteTitle = trustedSender && !trustedWriter ? 'Promuovi anche come writer trusted' : 'Promuovi a trusted';

        html += `
          <div class="device-row">
            <div>
              <div class="device-ip">${displayIp}</div>
              <div class="device-mac">${mac}</div>
            </div>
            <div>
              <div class="tag ${trustTagClass}">${trustText}</div>
              <div style="font-size:11px;color:var(--muted);margin-top:4px">Sender:${trustedSender ? 'Y' : 'N'} | Writer:${trustedWriter ? 'Y' : 'N'}</div>
            </div>
            <div>
              <div class="score-bar">
                <div class="score-fill" style="width:${scorePercent}%;background:${scoreColor}"></div>
              </div>
              <div style="font-size:11px;color:var(--muted);text-align:center">${scorePercent}%</div>
            </div>
            <div class="mono" style="font-size:12px">
              <div>${device.total_packets || 0} pkt</div>
              <div style="color:var(--muted)">${formatTime(device.last_seen_ms)}</div>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              <div class="tag">${protocolLabel}</div>
              <div class="tag ${role.css}">${role.label}</div>
            </div>
            <div class="device-actions">
              ${canManageTrust
                ? (!isTrusted
                  ? `<button class="btn success small" onclick="promoteDevice('${ip}')" title="${promoteTitle}">${promoteLabel}</button>`
                  : (trustedSender && !trustedWriter && !device.is_whitelisted
                    ? `<button class="btn success small" onclick="promoteDevice('${ip}')" title="${promoteTitle}">${promoteLabel}</button><button class="btn danger small" onclick="demoteDevice('${ip}')" title="Rimuovi dal trust">Rimuovi</button>`
                    : `<button class="btn danger small" onclick="demoteDevice('${ip}')" title="Rimuovi dal trust">Rimuovi</button>`))
                : '<span class="muted">IP assente</span>'}
            </div>
          </div>
        `;
      });

      deviceListElement.innerHTML = html;
    }

    async function promoteDevice(ip) {
      if (!ip) {
        showToast('IP non valido per la promozione', 'error');
        return;
      }

      try {
        const response = await fetch('/api/ids/presence/promote', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip })
        });

        if (response.ok) {
          showToast(`Device ${ip} promosso a trusted`, 'success');
          await refreshDevices();
          await refreshStats();
        } else {
          throw new Error('Errore promozione');
        }
      } catch (error) {
        showToast('Errore promozione device', 'error');
      }
    }

    async function demoteDevice(ip) {
      if (!ip) {
        showToast('IP non valido per la rimozione del trust', 'error');
        return;
      }

      try {
        const response = await fetch('/api/ids/presence/demote', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip })
        });

        if (response.ok) {
          showToast(`Device ${ip} rimosso da trusted`, 'success');
          await refreshDevices();
          await refreshStats();
        } else {
          throw new Error('Errore demozione');
        }
      } catch (error) {
        showToast('Errore demozione device', 'error');
      }
    }

    async function clearAllLearning() {
      if (!confirm('⚠️ Sei sicuro di voler eliminare tutti i device appresi? Questa azione non può essere annullata.')) {
        return;
      }

      try {
        const response = await fetch('/api/ids/presence/clear', { method: 'POST' });
        
        if (response.ok) {
          showToast('🗑️ Tutti i device appresi sono stati eliminati', 'success');
          await refreshDevices();
          await refreshStats();
        } else {
          throw new Error('Errore reset');
        }
      } catch (error) {
        showToast('❌ Errore reset learning data', 'error');
      }
    }

    function toggleAutoRefresh() {
      const btn = document.getElementById('autoRefreshBtn');
      if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
        btn.textContent = '⏱️ Auto Refresh';
        btn.classList.remove('primary');
      } else {
        autoRefreshTimer = setInterval(() => {
          refreshStats();
          refreshDevices();
        }, 30000); // 30 seconds
        btn.textContent = '⏸️ Stop Auto';
        btn.classList.add('primary');
      }
    }

    function exportData() {
      const dataStr = JSON.stringify({
        config,
        devices,
        presence_clock_ms: presenceClockMs,
        timestamp: new Date().toISOString()
      }, null, 2);
      
      const blob = new Blob([dataStr], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `network-presence-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      showToast('Dati esportati', 'success');
    }

    function formatTime(timestamp) {
      if (typeof timestamp !== 'number' || timestamp <= 0) return 'N/A';
      const baseClock = presenceClockMs > 0 ? presenceClockMs : Date.now();
      const diff = Math.max(0, baseClock - timestamp);
      const seconds = Math.floor(diff / 1000);

      if (seconds < 60) return seconds === 0 ? 'ora' : `${seconds}s fa`;
      const minutes = Math.floor(seconds / 60);
      if (minutes < 60) return `${minutes}m fa`;
      const hours = Math.floor(minutes / 60);
      if (hours < 24) return `${hours}h fa`;
      const days = Math.floor(hours / 24);
      return `${days}d fa`;
    }

    function showToast(message, type = 'info') {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.classList.add('show');
      
      setTimeout(() => {
        toast.classList.remove('show');
      }, 3000);
    }

    // Cleanup on page unload
    window.addEventListener('beforeunload', function() {
      if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
      }
    });
  </script>
</body>
</html>

)HTML";

// Compile-time size constant (actual content length)
static constexpr size_t NETWORK_PRESENCE_HTML_GEN_SIZE = 31799;
