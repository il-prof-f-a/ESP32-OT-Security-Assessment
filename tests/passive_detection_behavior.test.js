// No npm dependencies: execute the actual shared controller with DOM/event doubles.
// The browser fixture complements these checks with native DOM/editor integration.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../src/web/ui/passive_detection.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
const controller = script.slice(0, script.indexOf('PassivePanels.ids ='));

class Element {
  constructor(id = '') {
    this.id = id;
    this.disabled = false;
    this.checked = false;
    this.hidden = false;
    this.attributes = {};
    this.listeners = {};
    this.classes = new Set();
    this.classList = {toggle: (key, on) => on ? this.classes.add(key) : this.classes.delete(key)};
    this.controls = [];
  }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(key, callback) { (this.listeners[key] ||= []).push(callback); }
  async emit(key, extra = {}) {
    const event = {target: this, preventDefault() {}, ...extra};
    for (const callback of this.listeners[key] || []) await callback(event);
  }
  focus() { this.focused = true; }
  querySelector(selector) { return selector === '.panel-controls' ? this.fieldset : this.note; }
  querySelectorAll() { return this.controls; }
}

async function fixture(url, initial = {}, initialMode = 'success') {
  const keys = ['ids_enabled', 'network_presence_enabled', 'signatures_enabled'];
  const flags = {ids_enabled: true, network_presence_enabled: false, signatures_enabled: true, ...initial};
  const elements = {};
  for (const id of [...keys, 'passive-status', 'passive-save', 'passive-reload', 'passive-dashboard', 'tab-ids', 'tab-presence', 'tab-signatures']) elements[id] = new Element(id);
  const names = ['ids', 'presence', 'signatures'];
  names.forEach(name => {
    const id = name === 'presence' ? 'panel-network-presence' : 'panel-' + name;
    const root = elements[id] = new Element(id);
    root.fieldset = new Element(); root.note = new Element();
    root.controls = [new Element(), new Element()];
    root.controls[1].disabled = true; // Preserve a module's own disabled controls.
  });
  const document = new Element();
  document.getElementById = id => elements[id];
  document.hidden = false;
  const window = new Element();
  window.location = new URL(url);
  let responseMode = initialMode;
  let release = null;
  const requests = [], observers = [], initialized = [], activity = [];
  window.fetch = async (url, options = {}) => {
    requests.push({url, options});
    if (options.method === 'POST') {
      if (responseMode === 'pending') await new Promise(resolve => { release = resolve; });
      if (responseMode === 'error') return new Response(JSON.stringify({error: 'test failure'}), {status: 503});
      if (responseMode === 'invalid') return new Response('{}');
      const desired = JSON.parse(options.body);
      Object.assign(flags, desired);
      return new Response(JSON.stringify({...flags, ...(responseMode === 'runtime' ? {runtime: {...flags, signatures_enabled: !flags.signatures_enabled}} : {})}));
    }
    if (responseMode === 'get-error') return new Response('{}', {status: 503});
    return new Response(JSON.stringify(flags));
  };
  const context = vm.createContext({window, document, URL, Headers, Response, CSS: {escape: value => value}, console,
    history: {pushState: (_, __, url) => { window.location = new URL(url); }},
    MutationObserver: class {constructor(callback) {observers.push(callback);} observe() {}},
    initialized, activity,
  });
  vm.runInContext(controller + `
    for (const name of ['ids', 'presence', 'signatures']) PassivePanels[name] = {
      init: async () => initialized.push(name), activeChanged: enabled => activity.push([name, enabled])
    };
    PassiveDetection.init();`, context);
  async function settle() { for (let i = 0; i < 15; i++) await new Promise(resolve => setImmediate(resolve)); }
  await settle();
  return {elements, window, document, requests, observers, initialized, activity, settle,
    mode: value => {responseMode = value;}, release: () => release(), context};
}

(async () => {
  for (let mask = 0; mask < 8; mask++) {
    const f = await fixture('http://device.test/ids', {ids_enabled: Boolean(mask & 1), network_presence_enabled: Boolean(mask & 2), signatures_enabled: Boolean(mask & 4)});
    for (const [index, panel] of ['panel-ids', 'panel-network-presence', 'panel-signatures'].entries()) {
      assert.equal(f.elements[panel].controls[0].disabled, !(mask & (1 << index)), 'all eight independent enablement combinations');
    }
  }
  const failedLoad = await fixture('http://device.test/ids', {}, 'get-error');
  assert.equal(failedLoad.elements['passive-save'].disabled, true);
  assert.equal(failedLoad.elements['panel-ids'].controls[0].disabled, true);
  failedLoad.mode('success'); await failedLoad.elements['passive-reload'].emit('click'); await failedLoad.settle();
  assert.equal(failedLoad.elements['passive-save'].disabled, false, 'failed initial load can be retried');
  for (const [route, expected] of [['/ids', 'ids'], ['/network-presence', 'presence'], ['/signatures', 'signatures'], ['/ids?panel=signatures', 'signatures'], ['/network-presence?panel=bogus', 'presence']]) {
    const f = await fixture('http://device.test' + route);
    assert.deepEqual(f.initialized, [expected], 'only requested panel initializes');
    assert.equal(f.elements['tab-' + expected].attributes['aria-selected'], 'true');
  }
  const f = await fixture('http://device.test/ids?sid=sample-session&keep=value#anchor');
  const e = f.elements;
  assert.equal(f.requests[0].url, '/api/passive-detection/config');
  assert.equal(f.requests[0].options.headers.get('Authorization'), 'Bearer sample-session');
  assert.equal(e['passive-dashboard'].href, '/?sid=sample-session');
  assert.equal(e['panel-ids'].controls[0].disabled, false);
  assert.equal(e['panel-ids'].controls[1].disabled, true);
  assert.equal(e['panel-network-presence'].controls[0].disabled, true);
  assert.equal(e['tab-presence'].disabled, false);

  await e['tab-presence'].emit('click'); await f.settle();
  assert.equal(e['panel-network-presence'].hidden, false, 'disabled active panel stays visible');
  assert.equal(e['panel-ids'].hidden, true);
  assert.equal(f.window.location.searchParams.get('sid'), 'sample-session');
  assert.equal(f.window.location.searchParams.get('keep'), 'value');
  assert.equal(f.window.location.hash, '#anchor');
  assert.equal(f.window.location.searchParams.get('panel'), 'presence');
  await e['tab-signatures'].emit('keydown', {key: 'Home'}); await f.settle();
  assert.equal(e['tab-ids'].focused, true);
  assert.equal(f.initialized.filter(name => name === 'ids').length, 1);
  f.window.location = new URL('http://device.test/signatures?sid=sample-session');
  await f.window.emit('popstate'); await f.settle();
  assert.equal(e['panel-signatures'].hidden, false);

  e.ids_enabled.checked = false;
  e.network_presence_enabled.checked = true;
  e.signatures_enabled.checked = true;
  f.mode('pending');
  const pending = e['passive-save'].emit('click'); await f.settle();
  assert.equal(e['panel-ids'].controls[0].disabled, false, 'no optimistic panel update');
  assert.equal(e['passive-save'].disabled, true);
  assert.deepEqual(JSON.parse(f.requests.at(-1).options.body), {ids_enabled: false, network_presence_enabled: true, signatures_enabled: true});
  f.release(); await pending; await f.settle();
  assert.equal(e['panel-ids'].controls[0].disabled, true);
  assert.equal(e['panel-network-presence'].controls[0].disabled, false);
  assert.equal(e['panel-signatures'].controls[0].disabled, false);

  const added = new Element(); e['panel-ids'].controls.push(added); f.observers[0]();
  assert.equal(added.disabled, true, 'new rows are disabled too');
  f.mode('error'); e.ids_enabled.checked = true;
  await e['passive-save'].emit('click'); await f.settle();
  assert.equal(e['panel-ids'].controls[0].disabled, true);
  assert.equal(e.ids_enabled.checked, true, 'failed save retains unsaved choices');
  assert.match(e['passive-status'].textContent, /not saved/);
  f.mode('invalid'); await e['passive-save'].emit('click'); await f.settle();
  assert.match(e['passive-status'].textContent, /not saved/);
  f.mode('runtime'); await e['passive-save'].emit('click'); await f.settle();
  assert.match(e['passive-status'].textContent, /not fully applied/);
  assert.equal(e['panel-signatures'].controls[0].disabled, true);
  f.mode('success'); await e['passive-save'].emit('click'); await f.settle();
  assert.equal(added.disabled, false);
  assert.equal(e['panel-ids'].controls[1].disabled, true);
  f.document.hidden = true; await f.document.emit('visibilitychange');
  assert.equal(f.activity.at(-1)[1], false, 'hidden document pauses active module');
  console.log('passive detection behavioral checks passed');
})().catch(error => {console.error(error); process.exitCode = 1;});
