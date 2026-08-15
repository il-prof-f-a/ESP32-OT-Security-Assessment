/* auto-generated from logging.html */
#pragma once
static const char* LOGGING_HTML_GEN = R"HTML(
<!doctype html>
<html><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Gestione File Logging</title>
<style>
body{font-family:system-ui;margin:1rem;background:#f6f6f6}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:1rem;margin-bottom:1rem}
.btn{background:#007;color:#fff;border:none;padding:.5rem 1rem;border-radius:6px;cursor:pointer;margin-right:.5rem}
.btn:hover{background:#008}
.btn.danger{background:#c00}
.btn.danger:hover{background:#d00}
.btn.secondary{background:#666}
.btn.secondary:hover{background:#777}
.form-group{margin-bottom:.8rem}
label{display:block;margin-bottom:.3rem;font-weight:600}
input,select{width:100%;padding:.4rem;border:1px solid #ccc;border-radius:4px}
.status{padding:.5rem;border-radius:4px;margin-bottom:.8rem}
.status.ok{background:#d4edda;color:#155724}
.status.err{background:#f8d7da;color:#721c24}
.nav-btn{
    background:#06a;
    color:#fff;
    border:none;
    padding:.6rem 1rem;
    border-radius:8px;
    cursor:pointer;
    text-decoration:none;
    display:inline-block;
    margin-right:.5rem;
    margin-bottom:.5rem;
}
.nav-btn:hover{background:#0a5aa8}
.file-table{width:100%;border-collapse:collapse;margin-top:1rem}
.file-table th,.file-table td{border:1px solid #ddd;padding:.5rem;text-align:left}
.file-table th{background:#f5f5f5}
.file-enabled{color:#155724;font-weight:bold}
.file-disabled{color:#721c24;font-weight:bold}
.file-size{font-family:monospace}
.channel-list{font-size:.9em;color:#666}
.toggle-switch{position:relative;width:50px;height:24px;background:#ccc;border-radius:12px;cursor:pointer}
.toggle-switch input{display:none}
.toggle-switch .slider{position:absolute;top:2px;left:2px;width:20px;height:20px;background:#fff;border-radius:50%;transition:.2s}
.toggle-switch input:checked ~ .slider{left:26px}
.toggle-switch input:checked + .slider{background:#007}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:1000}
.modal-content{background:#fff;margin:5% auto;padding:1rem;width:80%;max-width:600px;border-radius:8px}
.close{float:right;font-size:1.5rem;cursor:pointer}
.stream-grid{display:grid;grid-template-columns:1fr 1fr;gap:.8rem}
.stream-actions{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.stream-output{width:100%;height:320px;resize:vertical;font-family:Consolas,monospace;font-size:.82rem;white-space:pre;overflow:auto}
.stream-hint{font-size:.9rem;color:#555;margin:.3rem 0 .8rem}
select[multiple]{min-height:120px}
</style>
<body>

<div class="card">
<h1>🗂️ Gestione File di Logging</h1>
<a href="/" class="btn nav-btn">← Dashboard</a>
</div>

<div class="card">
    <h2>📋 Stato File di Log</h2>
    <div id="status-msg" class="status" style="display:none;"></div>

    <button class="btn" onclick="refreshFileStatus()">🔄 Aggiorna</button>
    <button class="btn secondary" onclick="showConfigModal()">⚙️ Configura File</button>

    <table class="file-table" id="files-table">
        <thead>
            <tr>
                <th>File</th>
                <th>Stato</th>
                <th>Dimensione</th>
                <th>Dimensione Max</th>
                <th>Canali</th>
                <th>Azioni</th>
            </tr>
        </thead>
        <tbody id="files-table-body">
            <tr><td colspan="6">Caricamento...</td></tr>
        </tbody>
    </table>
</div>

<div class="card">
    <h2>Stream Realtime per Canali</h2>
    <div class="stream-hint">Seleziona file e canali, poi avvia/ferma lo stream SSE.</div>
    <div class="stream-grid">
        <div class="form-group">
            <label for="stream-file">File di log:</label>
            <select id="stream-file"></select>
        </div>
        <div class="form-group">
            <label for="stream-channels">Canali (multi-selezione):</label>
            <select id="stream-channels" multiple></select>
        </div>
    </div>
    <div class="stream-actions">
        <button id="stream-start" class="btn" onclick="startLiveStream()">Avvia</button>
        <button id="stream-stop" class="btn secondary" onclick="stopLiveStream()" disabled>Stop</button>
        <button class="btn secondary" onclick="clearLiveStream()">Pulisci</button>
        <label><input type="checkbox" id="stream-autoscroll" checked> Auto-scroll</label>
    </div>
    <textarea id="stream-output" class="stream-output" readonly></textarea>
</div>

<!-- Configuration Modal -->
<div id="config-modal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeConfigModal()">&times;</span>
        <h3>⚙️ Configurazione File</h3>
        <form id="config-form">
            <div class="form-group">
                <label>File:</label>
                <select id="config-file" onchange="loadFileConfig()">
                    <option value="">Seleziona un file...</option>
                </select>
            </div>
            <div class="form-group">
                <label>Abilitato:</label>
                <label class="toggle-switch">
                    <input type="checkbox" id="config-enabled">
                    <span class="slider"></span>
                </label>
            </div>
            <div class="form-group">
                <label>Dimensione Max (KB):</label>
                <input type="number" id="config-size" min="64" max="10240" value="1024">
            </div>
            <div class="form-group">
                <label>Max File di Backup:</label>
                <input type="number" id="config-files" min="1" max="10" value="3">
            </div>
            <div class="form-group">
                <label>Canali (separati da virgola):</label>
                <input type="text" id="config-channels" placeholder="app,general,system">
            </div>
            <button type="button" class="btn" onclick="saveFileConfig()">💾 Salva</button>
            <button type="button" class="btn secondary" onclick="closeConfigModal()">❌ Annulla</button>
        </form>
    </div>
</div>

<script>
        // Extract session token from URL and add to all API calls
(function() {
    const urlParams = new URLSearchParams(window.location.search);
    const sessionToken = urlParams.get('sid');

    if (sessionToken) {
        console.log('Session token found');
        window.__sidToken = sessionToken;

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

let files_data = [];
let streamSource = null;
const STREAM_MAX_CHARS = 180000;

// Load file status on page load
document.addEventListener('DOMContentLoaded', function() {
    (async () => {
        try {
            let boot = null;
            try {
                const r = await fetch('/api/page/bootstrap?name=logging', { cache: 'no-store' });
                if (r && r.ok) boot = await r.json();
            } catch (e) { boot = null; }

            if (boot && boot.data && boot.data.files) {
                await refreshFileStatus(boot.data.files);
                await loadFileList(boot.data.files);
            } else {
                await refreshFileStatus();
                await loadFileList();
            }
        } catch (err) {
            console.error('Logging page initial load failed:', err);
        }
    })();
});

async function refreshFileStatus(override) {
    try {
        const data = override || await (async () => {
            const response = await fetch('/api/logging/files', { cache: 'no-store' });
            return await response.json();
        })();

        if (data.files) {
            files_data = data.files;
            updateFilesTable(data.files);
            updateStreamSelectors(data.files);
            showStatus('✅ Stato file aggiornato', 'ok');
        } else {
            throw new Error('Formato risposta non valido');
        }
    } catch (error) {
        showStatus('❌ Errore nel caricamento: ' + error.message, 'err');
    }
}

function updateFilesTable(files) {
    const tbody = document.getElementById('files-table-body');
    tbody.innerHTML = '';

    files.forEach(file => {
        const row = tbody.insertRow();
        row.innerHTML = `
            <td><strong>${file.filename}</strong><br><small>${file.path}</small></td>
            <td><span class="${file.enabled ? 'file-enabled' : 'file-disabled'}">
                ${file.enabled ? '✅ Abilitato' : '❌ Disabilitato'}</span></td>
            <td class="file-size">${file.current_size_formatted}</td>
            <td class="file-size">${file.max_size_kb} KB</td>
            <td class="channel-list">${file.channels.join(', ')}</td>
            <td>
                <button class="btn ${file.enabled ? 'danger' : ''}"
                        onclick="toggleFile('${file.filename}', ${!file.enabled})">
                    ${file.enabled ? '❌ Disabilita' : '✅ Abilita'}
                </button>
            </td>
        `;
    });
}

async function toggleFile(filename, enable) {
    try {
        const response = await fetch('/api/logging/files', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'toggle',
                filename: filename,
                enabled: enable
            })
        });

        if (response.ok) {
            showStatus(`✅ File ${filename} ${enable ? 'abilitato' : 'disabilitato'}`, 'ok');
            refreshFileStatus();
        } else {
            throw new Error('Errore del server');
        }
    } catch (error) {
        showStatus('❌ Errore nell\'operazione: ' + error.message, 'err');
    }
}

async function loadFileList(override) {
    try {
        const data = override || await (async () => {
            const response = await fetch('/api/logging/files', { cache: 'no-store' });
            return await response.json();
        })();

        const select = document.getElementById('config-file');
        select.innerHTML = '<option value="">Seleziona un file...</option>';

        if (data.files) {
            data.files.forEach(file => {
                const option = document.createElement('option');
                option.value = file.filename;
                option.textContent = file.filename;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Errore nel caricamento lista file:', error);
    }
}

function updateStreamSelectors(files) {
    const fileSelect = document.getElementById('stream-file');
    const channelSelect = document.getElementById('stream-channels');
    if (!fileSelect || !channelSelect) return;

    const prevFile = fileSelect.value;
    const prevChannels = new Set(Array.from(channelSelect.selectedOptions).map(o => o.value));

    fileSelect.innerHTML = '';
    channelSelect.innerHTML = '';

    const uniqueChannels = new Set();
    (files || []).forEach(file => {
        const opt = document.createElement('option');
        opt.value = file.filename;
        opt.textContent = file.filename;
        fileSelect.appendChild(opt);
        (file.channels || []).forEach(ch => uniqueChannels.add(ch));
    });

    Array.from(uniqueChannels).sort().forEach(ch => {
        const opt = document.createElement('option');
        opt.value = ch;
        opt.textContent = ch;
        if (prevChannels.has(ch)) opt.selected = true;
        channelSelect.appendChild(opt);
    });

    if (prevFile && Array.from(fileSelect.options).some(o => o.value === prevFile)) {
        fileSelect.value = prevFile;
    } else if (fileSelect.options.length > 0) {
        fileSelect.selectedIndex = 0;
    }
}

function getSelectedChannelsCSV() {
    const sel = document.getElementById('stream-channels');
    if (!sel) return '';
    return Array.from(sel.selectedOptions).map(o => o.value).join(',');
}

function appendLiveLine(line) {
    const out = document.getElementById('stream-output');
    if (!out) return;
    out.value += line + '\n';
    if (out.value.length > STREAM_MAX_CHARS) {
        out.value = out.value.slice(out.value.length - STREAM_MAX_CHARS);
    }
    const autoScroll = document.getElementById('stream-autoscroll');
    if (!autoScroll || autoScroll.checked) {
        out.scrollTop = out.scrollHeight;
    }
}

function startLiveStream() {
    if (streamSource) stopLiveStream();

    const sid = window.__sidToken;
    if (!sid) {
        showStatus('Errore: sessione non disponibile (sid assente)', 'err');
        return;
    }

    const file = document.getElementById('stream-file')?.value || 'app.log';
    const channels = getSelectedChannelsCSV();
    const url = `/api/logs/sse?sid=${encodeURIComponent(sid)}&name=${encodeURIComponent(file)}&channels=${encodeURIComponent(channels)}&tail=80`;

    streamSource = new EventSource(url);
    streamSource.addEventListener('ready', () => appendLiveLine('[SSE] stream avviato'));
    streamSource.addEventListener('log', ev => appendLiveLine(ev.data || ''));
    streamSource.addEventListener('error', ev => {
        if (ev && ev.data) appendLiveLine('[SSE][ERROR] ' + ev.data);
    });
    streamSource.onerror = () => {
        appendLiveLine('[SSE] connessione chiusa');
        stopLiveStream();
    };

    document.getElementById('stream-start').disabled = true;
    document.getElementById('stream-stop').disabled = false;
    showStatus('Stream realtime avviato', 'ok');
}

function stopLiveStream() {
    if (streamSource) {
        streamSource.close();
        streamSource = null;
    }
    document.getElementById('stream-start').disabled = false;
    document.getElementById('stream-stop').disabled = true;
}

function clearLiveStream() {
    const out = document.getElementById('stream-output');
    if (out) out.value = '';
}

async function loadFileConfig() {
    const filename = document.getElementById('config-file').value;
    if (!filename) return;

    try {
        const response = await fetch(`/api/logging/file/config?filename=${encodeURIComponent(filename)}`);
        const data = await response.json();

        if (data.config) {
            const config = data.config;
            document.getElementById('config-enabled').checked = config.enabled;
            document.getElementById('config-size').value = config.max_size_kb;
            document.getElementById('config-files').value = config.max_files;
            document.getElementById('config-channels').value = config.channels.join(', ');
        }
    } catch (error) {
        showStatus('❌ Errore nel caricamento configurazione: ' + error.message, 'err');
    }
}

async function saveFileConfig() {
    const filename = document.getElementById('config-file').value;
    if (!filename) {
        showStatus('❌ Seleziona un file da configurare', 'err');
        return;
    }

    const config = {
        enabled: document.getElementById('config-enabled').checked,
        max_size_kb: parseInt(document.getElementById('config-size').value),
        max_files: parseInt(document.getElementById('config-files').value),
        channels: document.getElementById('config-channels').value
            .split(',').map(c => c.trim()).filter(c => c)
    };

    try {
        const response = await fetch('/api/logging/file/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename: filename, config: config })
        });

        if (response.ok) {
            showStatus('✅ Configurazione salvata', 'ok');
            closeConfigModal();
            refreshFileStatus();
        } else {
            throw new Error('Errore del server');
        }
    } catch (error) {
        showStatus('❌ Errore nel salvataggio: ' + error.message, 'err');
    }
}

function showConfigModal() {
    document.getElementById('config-modal').style.display = 'block';
}

function closeConfigModal() {
    document.getElementById('config-modal').style.display = 'none';
}

function showStatus(message, type) {
    const statusDiv = document.getElementById('status-msg');
    statusDiv.textContent = message;
    statusDiv.className = `status ${type}`;
    statusDiv.style.display = 'block';

    setTimeout(() => {
        statusDiv.style.display = 'none';
    }, 5000);
}

window.addEventListener('beforeunload', () => stopLiveStream());
</script>

</body></html>

)HTML";

// Compile-time size constant (actual content length)
static constexpr size_t LOGGING_HTML_GEN_SIZE = 17638;
