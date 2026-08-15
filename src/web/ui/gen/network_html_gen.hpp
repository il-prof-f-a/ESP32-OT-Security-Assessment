/* auto-generated from network.html */
#pragma once
static const char* NETWORK_HTML_GEN = R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Diagnostics - ESP32 OT Security</title>
    <style>
        /* Baseline “GIUSTO” */
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,"Helvetica Neue",Arial; margin:1rem; background:#f6f6f6; color:#222}
.container{max-width:1100px;margin:0 auto}

/* Navbar */
.navbar{display:flex; align-items:center; justify-content:space-between; margin:0 0 1rem 0; padding:0}
.nav-brand{font-weight:700;color:#111}
.nav-btn{background:#06a; color:#fff; border:none; padding:.6rem 1rem; border-radius:8px; text-decoration:none; display:inline-block}
.nav-btn:hover{background:#07b}

/* Card / layout */
.card{background:#fff; border:1px solid #ddd; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,.06); padding:1rem; margin-bottom:1rem}

/* Tipografia */
h1{font-size:1.4rem;margin:0 0 1rem 0}
h2{font-size:1.15rem;margin:0 0 .5rem 0}
label{display:block;margin-bottom:.3rem;font-weight:600;color:#333}

/* Form */
.form-group{margin-bottom:.8rem}
input,select,textarea{width:100%; padding:.45rem .6rem; border:1px solid #ccc; border-radius:4px; background:#fff; color:#222}

/* Bottoni */
.btn,.btn-primary,.btn-secondary{background:#007; color:#fff; border:none; padding:.5rem 1rem; border-radius:6px; cursor:pointer; display:inline-block; margin-right:.5rem}
.btn:hover,.btn-primary:hover{background:#008}
.btn-secondary{background:#555}

/* Tabelle / pre */
table{width:100%; border-collapse:collapse}
th,td{padding:.5rem; text-align:left; border-bottom:1px solid #eee}
th{background:#f8f9fa; color:#333}
pre{background:#f8f9fa; padding:.5rem; border-radius:4px; overflow:auto}

/* Stati */
.status-success,.success{background:#d4edda; color:#155724}
.status-error,.error{background:#f8d7da; color:#721c24}
.status-warning,.warning{background:#fff3cd; color:#664d03}

/* Checkbox row (do not force 100% width like normal inputs) */
.checkbox-row{display:flex; align-items:center; gap:.55rem}
.checkbox-row input[type="checkbox"]{width:auto}
.checkbox-row label{display:inline; margin:0; font-weight:600}
</style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">ESP32 OT Security - Network</div>
        <div class="nav-links">
            <a href="/" class="btn nav-btn">← Dashboard</a>
        </div>
    </nav>

    <div class="container">
        <h1>🌐 Network Diagnostics</h1>
        
        <div class="card">
            <h2>Network Interfaces</h2>
            <div id="interfaces-info">Loading...</div>
            <p><strong>⚠️ Important:</strong> All security attacks use <strong>Ethernet only</strong>. WiFi is for management access only.</p>
        </div>
        
        <div class="card">
            <h2>🔌 Ethernet Configuration</h2>
            <p>Configure Ethernet interface used for all security attacks and fuzzing operations.</p>
            
            <div id="ethernet-config">Loading...</div>

            <div class="form-group">
                <div class="checkbox-row">
                    <input type="checkbox" id="eth-enabled">
                    <label for="eth-enabled">Enable Ethernet (required for attacks)</label>
                </div>
            </div>

            <div class="form-group">
                <div class="checkbox-row">
                    <input type="checkbox" id="eth-promiscuous">
                    <label for="eth-promiscuous">Enable promiscuous mode (L2 capture)</label>
                </div>
            </div>
            
            <div class="form-group">
                <label for="eth-mode">IP Configuration:</label>
                <select id="eth-mode">
                    <option value="dhcp">DHCP (Automatic)</option>
                    <option value="static">Static IP</option>
                </select>
            </div>
            
            <div id="static-config" style="display: none;">
                <div class="form-group">
                    <label for="static-ip">IP Address:</label>
                    <input type="text" id="static-ip" placeholder="192.168.1.100">
                </div>
                <div class="form-group">
                    <label for="static-netmask">Netmask:</label>
                    <input type="text" id="static-netmask" placeholder="255.255.255.0">
                </div>
                <div class="form-group">
                    <label for="static-gateway">Gateway:</label>
                    <input type="text" id="static-gateway" placeholder="192.168.1.1">
                </div>
                <div class="form-group">
                    <label for="static-dns">DNS Server:</label>
                    <input type="text" id="static-dns" placeholder="8.8.8.8">
                </div>
            </div>
            
            <button id="save-ethernet-btn" class="btn btn-primary">Save Ethernet Configuration</button>
            
            <div id="ethernet-result" style="margin-top: 10px;"></div>
        </div>
        
        <div class="card">
            <h2>WiFi Management</h2>
            <p>Configura la rete WiFi per l'accesso alla console di gestione.</p>
            <div class="form-group">
                <label>Reti disponibili</label>
                <button id="wifi-scan-btn" class="btn btn-secondary">Scansiona reti</button>
                <div id="wifi-scan-status" style="margin-top:8px;"></div>
                <div id="wifi-network-list" style="margin-top:8px;"></div>
            </div>
            <div class="form-group">
                <label for="wifi-ssid">SSID</label>
                <input type="text" id="wifi-ssid" placeholder="Nome rete WiFi">
            </div>
            <div class="form-group">
                <label for="wifi-password">Password</label>
                <input type="password" id="wifi-password" placeholder="Password WiFi">
            </div>
            <button id="wifi-save-btn" class="btn btn-primary">Salva configurazione WiFi</button>
            <div id="wifi-connect-status" style="margin-top:10px;"></div>
        </div>

        <div class="card">
            <h2>Ping Tool</h2>
            <div class="form-group">
                <label for="ping-target">Target IP Address:</label>
                <input type="text" id="ping-target" placeholder="192.168.1.1" value="192.168.1.12">
            </div>
            <div class="form-group">
                <label for="ping-count">Count:</label>
                <input type="number" id="ping-count" min="1" max="10" value="4">
            </div>
            <button id="ping-btn" class="btn btn-primary">Run Ping</button>
            
            <div id="ping-results" style="margin-top: 20px;"></div>
        </div>
    </div>

    <script>
        (function() {
            const urlParams = new URLSearchParams(window.location.search);
            const sessionToken = urlParams.get('sid');
            window.sessionToken = sessionToken || null;

            if (sessionToken) {
                console.log('Session token found');

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

        const WIFI_CONNECT_TIMEOUT = 30;
        let wifiScanInterval = null;
        let wifiConnectInterval = null;
        let wifiConnectInProgress = false;

        async function loadEthernetConfig(override) {
            try {
                const data = override || await (await fetch('/api/ethernet/config', { cache: 'no-store' })).json();

                let html = '<h3>Current Configuration</h3>';
                const enabled = (data.enabled !== false);
                const promisc = !!data.promiscuous;

                // Sync UI toggles
                const enabledEl = document.getElementById('eth-enabled');
                const promEl = document.getElementById('eth-promiscuous');
                if (enabledEl) enabledEl.checked = enabled;
                if (promEl) promEl.checked = promisc;

                html += `<p><strong>Enabled:</strong> ${enabled ? '<span class=\"status-success\">Yes</span>' : '<span class=\"status-warning\">No</span>'}</p>`;
                html += `<p><strong>Promiscuous:</strong> ${promisc ? '<span class=\"status-warning\">ON</span>' : 'OFF'}</p>`;

                if (!enabled) {
                    html += `<p><strong>Status:</strong> <span class="status-warning">Disabled</span></p>`;
                    html += `<p>Ethernet is disabled by configuration. Enable it and restart the device.</p>`;
                } else if (data.interface_up) {
                    html += `<p><strong>Status:</strong> <span class="status-success">Connected</span></p>`;
                    html += `<p><strong>Current IP:</strong> ${data.current_ip}</p>`;
                    html += `<p><strong>Gateway:</strong> ${data.current_gateway}</p>`;
                    html += `<p><strong>Netmask:</strong> ${data.current_netmask}</p>`;
                } else {
                    html += `<p><strong>Status:</strong> <span class="status-error">Disconnected</span></p>`;
                    html += `<p>Check Ethernet cable connection</p>`;
                }

                html += `<p><strong>Configuration Mode:</strong> ${data.mode.toUpperCase()}</p>`;
                document.getElementById('ethernet-config').innerHTML = html;

                document.getElementById('eth-mode').value = data.mode || 'dhcp';
                document.getElementById('static-config').style.display = data.mode === 'static' ? 'block' : 'none';

                if (data.mode === 'static') {
                    document.getElementById('static-ip').value = data.static_ip || '';
                    document.getElementById('static-netmask').value = data.static_netmask || '';
                    document.getElementById('static-gateway').value = data.static_gateway || '';
                    document.getElementById('static-dns').value = data.static_dns || '';
                }
            } catch (error) {
                document.getElementById('ethernet-config').innerHTML = '<div class="error">Failed to load Ethernet configuration</div>';
            }
        }

        function toggleStaticConfig() {
            const mode = document.getElementById('eth-mode').value;
            document.getElementById('static-config').style.display = mode === 'static' ? 'block' : 'none';
        }

        async function saveEthernetConfig() {
            const mode = document.getElementById('eth-mode').value;
            const saveBtn = document.getElementById('save-ethernet-btn');
            const resultDiv = document.getElementById('ethernet-result');

            saveBtn.disabled = true;
            saveBtn.textContent = 'Saving...';
            resultDiv.innerHTML = '';

            const config = { mode };

            // Optional toggles
            const enabledEl = document.getElementById('eth-enabled');
            const promEl = document.getElementById('eth-promiscuous');
            if (enabledEl) config.enabled = !!enabledEl.checked;
            if (promEl) config.promiscuous = !!promEl.checked;
            if (mode === 'static') {
                config.static_ip = document.getElementById('static-ip').value.trim();
                config.static_netmask = document.getElementById('static-netmask').value.trim();
                config.static_gateway = document.getElementById('static-gateway').value.trim();
                config.static_dns = document.getElementById('static-dns').value.trim();

                if (!config.static_ip || !config.static_netmask || !config.static_gateway) {
                    resultDiv.innerHTML = '<div class="error">Please fill in all required static IP fields</div>';
                    saveBtn.disabled = false;
                    saveBtn.textContent = 'Save Ethernet Configuration';
                    return;
                }
            }

            try {
                const response = await fetch('/api/ethernet/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                const data = await response.json();

                if (response.ok) {
                    resultDiv.innerHTML = `<div class="success">${data.message}</div>`;
                    if (data.restart_required) {
                        resultDiv.innerHTML += '<div class="warning">⚠️ Device restart required to apply changes</div>';
                    }
                    setTimeout(loadEthernetConfig, 1000);
                } else {
                    resultDiv.innerHTML = `<div class="error">Failed to save configuration: ${data.message || 'Unknown error'}</div>`;
                }
            } catch (error) {
                resultDiv.innerHTML = '<div class="error">Failed to save Ethernet configuration</div>';
            } finally {
                saveBtn.disabled = false;
                saveBtn.textContent = 'Save Ethernet Configuration';
            }
        }

        async function loadNetworkInfo(override) {
            try {
                const data = override || await (await fetch('/api/network/status', { cache: 'no-store' })).json();

                let html = '<table class="table"><tr><th>Interface</th><th>IP</th><th>Gateway</th><th>Netmask</th><th>Status</th></tr>';

                data.interfaces.forEach(iface => {
                    const statusClass = iface.connected ? 'status-success' : 'status-error';
                    const statusText = iface.connected ? 'Connected' : 'Disconnected';

                    html += `<tr>
                        <td>${iface.name}</td>
                        <td>${iface.ip || 'N/A'}</td>
                        <td>${iface.gateway || 'N/A'}</td>
                        <td>${iface.netmask || 'N/A'}</td>
                        <td><span class="${statusClass}">${statusText}</span></td>
                    </tr>`;
                });

                html += '</table>';
                if (data.primary_ip) {
                    html += `<p><strong>Primary IP:</strong> ${data.primary_ip}</p>`;
                }

                document.getElementById('interfaces-info').innerHTML = html;
            } catch (error) {
                document.getElementById('interfaces-info').innerHTML = '<div class="error">Failed to load network information</div>';
            }
        }

        async function runPing() {
            const target = document.getElementById('ping-target').value.trim();
            const count = parseInt(document.getElementById('ping-count').value);
            const resultsDiv = document.getElementById('ping-results');
            const pingBtn = document.getElementById('ping-btn');

            if (!target) {
                alert('Please enter a target IP address');
                return;
            }

            pingBtn.disabled = true;
            pingBtn.textContent = 'Pinging...';
            resultsDiv.innerHTML = '<div class="loading">Running ping...</div>';

            try {
                const response = await fetch('/api/network/ping', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, count })
                });
                const data = await response.json();

                let html = `<h3>Ping Results for ${data.target}</h3>`;
                if (data.error) {
                    html += `<div class="error">${data.error}</div>`;
                } else {
                    if (data.source_ip) {
                        html += `<p><strong>Source IP:</strong> ${data.source_ip}</p>`;
                    }
                    html += '<table class="table"><tr><th>Seq</th><th>Status</th><th>Time (ms)</th><th>Details</th></tr>';

                    let successCount = 0;
                    data.results.forEach(result => {
                        const statusClass = (result.status === 'success' || result.status === 'host_up_port_closed') ? 'status-success' : 'status-error';
                        const timeText = result.time_ms >= 0 ? result.time_ms : 'N/A';
                        if (result.status === 'success' || result.status === 'host_up_port_closed') {
                            successCount++;
                        }
                        html += `<tr>
                            <td>${result.sequence}</td>
                            <td><span class="${statusClass}">${result.status}</span></td>
                            <td>${timeText}</td>
                            <td>${result.errno ? `errno: ${result.errno}` : ''}</td>
                        </tr>`;
                    });
                    html += '</table>';
                    html += `<p><strong>Summary:</strong> ${successCount}/${data.count} responses received</p>`;
                }

                resultsDiv.innerHTML = html;
            } catch (error) {
                resultsDiv.innerHTML = '<div class="error">Failed to run ping</div>';
            } finally {
                pingBtn.disabled = false;
                pingBtn.textContent = 'Run Ping';
            }
        }

        function clearWifiScanInterval() {
            if (wifiScanInterval) {
                clearInterval(wifiScanInterval);
                wifiScanInterval = null;
            }
        }

        function clearWifiConnectInterval() {
            if (wifiConnectInterval) {
                clearInterval(wifiConnectInterval);
                wifiConnectInterval = null;
            }
        }

        async function startWifiScan() {
            const scanBtn = document.getElementById('wifi-scan-btn');
            const statusDiv = document.getElementById('wifi-scan-status');
            const listDiv = document.getElementById('wifi-network-list');

            clearWifiScanInterval();
            statusDiv.innerHTML = '<div class="status-warning">Avvio scansione WiFi...</div>';
            listDiv.innerHTML = '';
            scanBtn.disabled = true;
            scanBtn.textContent = 'Scansione in corso...';

            try {
                const response = await fetch('/api/wifi/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const data = await response.json();
                if (data.started) {
                    statusDiv.innerHTML = '<div class="status-warning">Scansione avviata... aggiornamento automatico ogni secondo</div>';
                } else {
                    statusDiv.innerHTML = '<div class="status-error">Impossibile avviare la scansione (già in corso?)</div>';
                    scanBtn.disabled = false;
                    scanBtn.textContent = 'Scansiona reti';
                    return;
                }
            } catch (error) {
                console.error(error);
                statusDiv.innerHTML = `<div class="status-error">Errore nell'avvio della scansione</div>`;
                scanBtn.disabled = false;
                scanBtn.textContent = 'Scansiona reti';
                return;
            }

            await pollWifiScanStatus();
            wifiScanInterval = setInterval(pollWifiScanStatus, 1000);
        }

        async function pollWifiScanStatus() {
            const statusDiv = document.getElementById('wifi-scan-status');
            const scanBtn = document.getElementById('wifi-scan-btn');

            try {
                const response = await fetch('/api/wifi/scan/status');
                const data = await response.json();

                if (!data.available) {
                    statusDiv.innerHTML = '<div class="status-warning">Nessuna scansione attiva</div>';
                    clearWifiScanInterval();
                    scanBtn.disabled = false;
                    scanBtn.textContent = 'Scansiona reti';
                    renderWifiNetworkList([]);
                    return;
                }

                if (data.scanning) {
                    statusDiv.innerHTML = '<div class="status-warning">Scansione in corso... reti trovate: ' + data.cached + '</div>';
                } else if (data.completed) {
                    statusDiv.innerHTML = '<div class="status-success">Scansione completata. Reti trovate: ' + data.cached + '</div>';
                    clearWifiScanInterval();
                    scanBtn.disabled = false;
                    scanBtn.textContent = 'Scansiona reti';
                }

                renderWifiNetworkList(data.networks || []);
            } catch (error) {
                console.error(error);
                statusDiv.innerHTML = '<div class="status-error">Errore nel recupero delle reti WiFi</div>';
                clearWifiScanInterval();
                scanBtn.disabled = false;
                scanBtn.textContent = 'Scansiona reti';
            }
        }

        function renderWifiNetworkList(networks) {
            const container = document.getElementById('wifi-network-list');
            container.innerHTML = '';

            if (!networks || networks.length === 0) {
                container.innerHTML = '<div class="status-warning">Nessuna rete rilevata finora</div>';
                return;
            }

            networks.forEach(net => {
                const row = document.createElement('div');
                row.style.display = 'flex';
                row.style.alignItems = 'center';
                row.style.justifyContent = 'space-between';
                row.style.marginBottom = '6px';
                row.style.gap = '12px';

                const info = document.createElement('div');
                const ssidLabel = net.ssid && net.ssid.length ? net.ssid : '(SSID nascosto)';
                const securityLabel = net.secure ? 'Protetta' : 'Open';
                const authLabel = net.auth_mode || 'N/A';
                info.innerHTML = `<strong>${ssidLabel}</strong> <span style="color:#555;">RSSI: ${net.rssi}</span> <span style="color:#555;">Canale: ${net.channel}</span> <span style="color:#777;">${securityLabel} (${authLabel})</span>`;

                const btn = document.createElement('button');
                btn.className = 'btn btn-secondary';
                btn.textContent = 'Usa';
                btn.addEventListener('click', () => selectWifiNetwork(net.ssid || ''));

                row.appendChild(info);
                row.appendChild(btn);
                container.appendChild(row);
            });
        }

        function selectWifiNetwork(ssid) {
            document.getElementById('wifi-ssid').value = ssid;
            document.getElementById('wifi-password').focus();
        }

        async function submitWifiConfig() {
            const ssidField = document.getElementById('wifi-ssid');
            const passwordField = document.getElementById('wifi-password');
            const statusDiv = document.getElementById('wifi-connect-status');
            const saveBtn = document.getElementById('wifi-save-btn');
            const ssid = ssidField.value.trim();
            const password = passwordField.value;

            if (!ssid) {
                alert('Inserire il nome della rete WiFi (SSID).');
                return;
            }

            if (!confirm(`Connettere il dispositivo alla rete "${ssid}"?`)) {
                return;
            }

            saveBtn.disabled = true;
            saveBtn.textContent = 'Connessione in corso...';
            wifiConnectInProgress = true;
            statusDiv.innerHTML = '<div class="status-warning">Connessione WiFi in corso...</div>';
            clearWifiConnectInterval();

            try {
                const response = await fetch('/api/wifi/connect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ssid, password, timeout: WIFI_CONNECT_TIMEOUT })
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || 'Errore salvataggio credenziali');
                }

                const data = await response.json();

                // Se il salvataggio è andato a buon fine, il dispositivo si riavvierà
                if (data.success && data.message === 'wifi_credentials_saved_rebooting') {
                    statusDiv.innerHTML = `
                        <div class="status-success">
                            <strong>✓ Credenziali WiFi salvate!</strong><br>
                            Il dispositivo si sta riavviando...<br><br>
                            <strong>Istruzioni:</strong><br>
                            1. Il dispositivo si connetterà alla rete "${ssid}"<br>
                            2. Connettiti alla stessa rete WiFi<br>
                            3. Trova l'indirizzo IP del dispositivo (controlla il router o usa uno scanner di rete)<br>
                            4. Accedi al web server all'indirizzo: http://[IP_DISPOSITIVO]/<br><br>
                            <em>Il riavvio richiederà circa 10-15 secondi.</em>
                        </div>
                    `;
                    saveBtn.textContent = 'Credenziali salvate - Riavvio in corso';
                    wifiConnectInProgress = false;
                    return;
                }
            } catch (error) {
                console.error(error);
                statusDiv.innerHTML = `<div class="status-error">Errore nel salvataggio delle credenziali WiFi: ${error.message}</div>`;
                saveBtn.disabled = false;
                saveBtn.textContent = 'Salva configurazione WiFi';
                wifiConnectInProgress = false;
                return;
            }
        }

        async function pollWifiConnectResult() {
            const statusDiv = document.getElementById('wifi-connect-status');
            const saveBtn = document.getElementById('wifi-save-btn');

            try {
                const response = await fetch('/api/wifi/connect/result');
                const data = await response.json();
                updateWifiConnectStatus(data);

                if (data.result_ready) {
                    if (!data.success || !data.ap_pending) {
                        clearWifiConnectInterval();
                        wifiConnectInProgress = false;
                        saveBtn.disabled = false;
                        saveBtn.textContent = 'Salva configurazione WiFi';
                    }
                } else if (!data.in_progress && !data.ap_pending) {
                    clearWifiConnectInterval();
                    wifiConnectInProgress = false;
                    saveBtn.disabled = false;
                    saveBtn.textContent = 'Salva configurazione WiFi';
                }
            } catch (error) {
                console.error(error);
                statusDiv.innerHTML = '<div class="status-error">Errore durante il controllo dello stato WiFi</div>';
                clearWifiConnectInterval();
                wifiConnectInProgress = false;
                saveBtn.disabled = false;
                saveBtn.textContent = 'Salva configurazione WiFi';
            }
        }

        function updateWifiConnectStatus(state) {
            const statusDiv = document.getElementById('wifi-connect-status');
            if (!state) {
                statusDiv.innerHTML = '';
                return;
            }

            if (state.result_ready) {
                if (state.success) {
                    const ipText = state.ip ? state.ip : 'N/D';
                    if (state.ap_pending) {
                        statusDiv.innerHTML = `<div class="status-warning">Connessione completata su ${ipText}. In attesa di disattivare l'AP...</div>`;
                    } else {
                        statusDiv.innerHTML = `<div class="status-success">Connessione completata. Nuovo IP: ${ipText}</div>`;
                        if (state.ip) {
                            const redirectBtn = document.createElement('button');
                            redirectBtn.className = 'btn btn-secondary';
                            redirectBtn.style.marginTop = '8px';
                            redirectBtn.textContent = 'Apri nuova interfaccia';
                            redirectBtn.addEventListener('click', () => redirectToWifiIP(state.ip));
                            statusDiv.appendChild(redirectBtn);
                        }
                    }
                } else {
                    const errMsg = state.error || 'Connessione fallita';
                    statusDiv.innerHTML = `<div class="status-error">${errMsg}</div>`;
                }
            } else if (state.in_progress || state.ap_pending) {
                statusDiv.innerHTML = '<div class="status-warning">Connessione WiFi in corso...</div>';
            } else {
                statusDiv.innerHTML = '';
            }
        }

        function redirectToWifiIP(ip) {
            if (!ip) return;
            let target = "http://" + ip + "/network";
            const sid = window.sessionToken;
            if (sid) {
                try {
                    const url = new URL(target, window.location.href);
                    url.searchParams.set('sid', sid);
                    target = url.toString();
                } catch (err) {
                    target += target.includes('?') ? '&' : '?';
                    target += 'sid=' + encodeURIComponent(sid);
                }
            }
            if (confirm("Aprire la pagina di gestione sul nuovo indirizzo?")) {
                window.location.href = target;
            }
        }

        async function initializeWifiStatus() {
            try {
                const response = await fetch('/api/wifi/connect/result');
                const data = await response.json();
                updateWifiConnectStatus(data);

                const saveBtn = document.getElementById('wifi-save-btn');
                if (data.in_progress || data.ap_pending) {
                    wifiConnectInProgress = true;
                    saveBtn.disabled = true;
                    saveBtn.textContent = 'Connessione in corso...';
                    clearWifiConnectInterval();
                    wifiConnectInterval = setInterval(pollWifiConnectResult, 1000);
                } else {
                    wifiConnectInProgress = false;
                    saveBtn.disabled = false;
                    saveBtn.textContent = 'Salva configurazione WiFi';
                }
            } catch (error) {
                console.warn('Impossibile inizializzare lo stato WiFi', error);
            }
        }

        document.getElementById('ping-btn').addEventListener('click', runPing);
        document.getElementById('eth-mode').addEventListener('change', toggleStaticConfig);
        document.getElementById('save-ethernet-btn').addEventListener('click', saveEthernetConfig);
        document.getElementById('wifi-scan-btn').addEventListener('click', startWifiScan);
        document.getElementById('wifi-save-btn').addEventListener('click', submitWifiConfig);

        (async () => {
            try {
                let boot = null;
                try {
                    const r = await fetch('/api/page/bootstrap?name=network', { cache: 'no-store' });
                    if (r && r.ok) boot = await r.json();
                } catch (e) { boot = null; }

                if (boot && boot.data) {
                    await loadNetworkInfo(boot.data.network_status || null);
                    await loadEthernetConfig(boot.data.ethernet_config || null);
                    // Evita fan-out: lo stato di connessione WiFi e' secondario e puo' essere caricato su richiesta.
                } else {
                    await loadNetworkInfo();
                    await loadEthernetConfig();
                    await initializeWifiStatus();
                }
            } catch (err) {
                console.error('Network page initial load failed:', err);
            }
        })();

        setInterval(loadNetworkInfo, 30000);
    </script>
</body>
</html>

)HTML";

// Compile-time size constant (actual content length)
static constexpr size_t NETWORK_HTML_GEN_SIZE = 33722;
