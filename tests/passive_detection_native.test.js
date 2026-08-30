/* Native DOM integration checks loaded only by the local browser fixture. */
(async () => {
  const checks = [];
  const check = (condition, message) => {if (!condition) throw new Error(message); checks.push(message);};
  const byId = id => document.getElementById(id);
  const wait = async predicate => {
    for (let i = 0; i < 300; i++) {if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 10));}
    throw new Error('Timed out waiting for fixture UI');
  };
  const click = (root, text) => {
    const button = [...root.querySelectorAll('button')].find(button => button.textContent.includes(text));
    if (!button) throw new Error('Missing button: ' + text);
    button.click(); return button;
  };
  const panel = name => byId('panel-' + name);
  try {
    await wait(() => !byId('passive-save').disabled && panel('ids').getAttribute('aria-busy') === 'false');
    check(byId('ids-statAllowed').textContent === '7', 'IDS bootstrap statistics render');
    check(byId('ids-ip-Modbus TCP')?.querySelector('input').value === '192.0.2.1', 'protocol names with spaces preserve allowlist DOM wiring');
    click(panel('ids'), '+ Add IP/CIDR');
    check(byId('ids-ipGlobalTbody').querySelectorAll('input').length === 2, 'IDS Add IP action remains wired');
    const added = byId('ids-ipGlobalTbody').querySelectorAll('input')[1];
    added.value = '198.51.100.8'; added.dispatchEvent(new Event('input'));
    await PassivePanels.ids.saveToDevice();
    check(!byId('ids-dirtyMark').textContent.includes('unsaved'), 'IDS save clears dirty state after response');
    await PassivePanels.ids.refreshStats();
    check(byId('ids-statAllowed').textContent === '8', 'IDS refresh fetches current stats rather than stale bootstrap');
    byId('ids-testValue').value = '10.0.0.5'; click(panel('ids'), 'Run test');
    check(byId('ids-testResult').textContent === 'ALLOW', 'allowlist quick test works');
    await PassivePanels.ids.saveProtocolSettings();
    await PassivePanels.ids.makeDevicePermanent('192.0.2.30');
    await PassivePanels.ids.removeLearnedDevice('192.0.2.30');
    await PassivePanels.ids.clearAllLearned();
    await PassivePanels.ids.saveToDevice();

    byId('tab-presence').click();
    await wait(() => panel('network-presence').getAttribute('aria-busy') === 'false');
    check(byId('presence-totalDevices').textContent === '2', 'presence statistics render');
    check(byId('presence-trustedDevices').textContent === '1', 'presence sender/writer trust statistics preserved');
    byId('presence-protocolTabs').querySelector('[data-protocol="s7"]').click();
    check(byId('presence-deviceList').textContent.includes('192.0.2.20') && !byId('presence-deviceList').textContent.includes('192.0.2.10'), 'presence protocol filtering is scoped');
    byId('presence-protocolTabs').querySelector('[data-protocol="all"]').click();
    check(!byId('presence-deviceList').textContent.includes('Unknown'), 'known protocol suppresses Unknown duplicate label');
    await PassivePanels.presence.saveConfig();
    await PassivePanels.presence.promoteDevice('192.0.2.20');
    await PassivePanels.presence.demoteDevice('192.0.2.20');
    await PassivePanels.presence.clearAllLearning();
    click(panel('network-presence'), 'Auto Refresh');
    check(window.__fixtureIntervals.size === 1, 'presence polling can start');

    byId('tab-signatures').click();
    await wait(() => panel('signatures').getAttribute('aria-busy') === 'false');
    check(window.__fixtureIntervals.size === 0, 'switching away cancels presence polling');
    check(byId('signatures-signatureList').textContent.includes('CVE-2024-12345'), 'signature list renders with existing data');
    click(byId('signatures-signatureList'), 'Edit');
    check(byId('signatures-editModal').classList.contains('show') && byId('signatures-editCVE').value === 'CVE-2024-12345', 'generated signature Edit button opens populated modal');
    check(document.activeElement === byId('signatures-editCVE'), 'signature editor receives keyboard focus');
    byId('signatures-editName').value = 'Edited fixture';
    await PassivePanels.signatures.saveSignatureEdit();
    await wait(() => byId('signatures-signatureList').textContent.includes('Edited fixture'));
    check(!byId('signatures-editModal').classList.contains('show'), 'signature save closes modal after response');
    click(panel('signatures'), 'Edit JSON');
    check(byId('signatures-jsonEditor').style.display === 'block', 'raw JSON editor action remains wired');
    const payload = JSON.parse(byId('signatures-jsonEditor').value);
    payload['Modbus TCP'].Vulnerabilities[0].Name = 'Raw fixture';
    byId('signatures-jsonEditor').value = JSON.stringify(payload);
    await PassivePanels.signatures.saveRawJSON();
    await wait(() => byId('signatures-signatureList').textContent.includes('Raw fixture'));
    check(true, 'raw JSON save updates signature list');
    click(panel('signatures'), 'Add New');
    byId('signatures-editCVE').value = 'CVE-2024-67890';
    byId('signatures-editBytes').value = '03 04';
    await PassivePanels.signatures.saveSignatureEdit();
    await wait(() => byId('signatures-signatureList').textContent.includes('CVE-2024-67890'));
    check(true, 'Add New signature action preserves modal save');
    await PassivePanels.signatures.deleteSignature('Modbus TCP_1');
    await wait(() => !byId('signatures-signatureList').textContent.includes('CVE-2024-67890'));
    check(true, 'individual signature deletion persists and refreshes');
    await PassivePanels.signatures.clearSignatures();
    await wait(() => byId('signatures-signatureList').textContent.includes('No signatures loaded'));
    check(true, 'Delete All signature action remains wired');
    const upload = new DataTransfer();
    upload.items.add(new File([JSON.stringify(payload)], 'fixture.json', {type: 'application/json'}));
    byId('signatures-fileInput').files = upload.files;
    await PassivePanels.signatures.uploadSignatures();
    check(byId('signatures-fileInput').value === '', 'signature JSON file import clears selection after success');
    let downloads = 0;
    const oldClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function() {if (this.download) downloads++; else oldClick.call(this);};
    await PassivePanels.signatures.downloadSignatures();
    PassivePanels.presence.exportData();
    HTMLAnchorElement.prototype.click = oldClick;
    check(downloads === 2, 'signature and presence exports create downloadable files');

    byId('signatures_enabled').click(); byId('passive-save').click();
    await wait(() => !byId('passive-save').disabled);
    check(!panel('signatures').hidden && panel('signatures').classList.contains('module-disabled'), 'disabled active signature panel remains visible and gray');
    check([...panel('signatures').querySelectorAll('button,input,textarea,select')].every(control => control.disabled), 'all signature editor controls are actually disabled');
    check(!byId('ids_enabled').disabled && !byId('network_presence_enabled').disabled && !byId('tab-presence').disabled, 'shared independent toggles and tab navigation remain available');
    byId('tab-presence').click();
    check(window.__fixtureIntervals.size === 1, 'returning resumes requested presence polling');
    byId('network_presence_enabled').click(); byId('passive-save').click();
    await wait(() => !byId('passive-save').disabled);
    check(window.__fixtureIntervals.size === 0, 'disabling presence cancels its polling');
    check(byId('ids_enabled').checked, 'disabling other modules never changes IDS flag');

    const requests = await (await fetch('/fixture/requests')).json();
    check(requests.filter(r => r.path === '/api/config').length === 0, 'bootstraps avoid redundant all-config reads');
    for (const endpoint of ['/api/whitelist','/api/config/update','/api/network-presence/make-permanent','/api/network-presence/remove','/api/network-presence/clear','/api/ids/presence/config','/api/ids/presence/promote','/api/ids/presence/demote','/api/ids/presence/clear','/api/signatures/save','/api/signatures/upload','/api/signatures/download','/api/signatures/clear','/api/signatures/reload']) {
      check(requests.some(request => request.path === endpoint), 'preserved API action: ' + endpoint);
    }
    const result = document.createElement('pre'); result.id = 'ui-test-results'; result.textContent = JSON.stringify({passed: checks.length, checks}, null, 2); document.body.prepend(result);
  } catch (error) {
    const result = document.createElement('pre'); result.id = 'ui-test-results'; result.textContent = JSON.stringify({failed: error.message, passed: checks.length, checks}, null, 2); document.body.prepend(result);
    console.error(error);
  }
})();
