/* Race-card pages (PAGES.md): fetch the encrypted day payload, decrypt it in the browser (AES-256-GCM with a key from PBKDF2-SHA256
   of the passphrase, then gunzip) and show the page in a full-screen frame.  The same functions run in Node 22 for the tests
   (decrypt_check.mjs): globalThis.crypto, atob/btoa, Blob, Response and DecompressionStream exist there too. */
(function (root) {
  const enc = new TextEncoder();
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64e = (buf) => {
    const a = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
    return btoa(s);
  };

  async function deriveKey(pass, saltB64, iter) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64d(saltB64), iterations: iter, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function exportKey(key) { return b64e(await crypto.subtle.exportKey('raw', key)); }
  async function importKey(raw) { return crypto.subtle.importKey('raw', b64d(raw), { name: 'AES-GCM' }, true, ['decrypt']); }
  async function decryptPayload(key, p) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(p.iv) }, key, b64d(p.ct));
    if (!p.gz) return new TextDecoder().decode(pt);
    return new Response(new Blob([pt]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  }
  root.KP = { deriveKey, exportKey, importKey, decryptPayload, b64d, b64e };

  if (typeof document === 'undefined') return;

  const LS = 'keiba_pages_key_v1';
  const $ = (id) => document.getElementById(id);
  const state = { key: null, date: null, shown: null, pending: null };
  const store = {
    get() { try { return JSON.parse(localStorage.getItem(LS) || 'null'); } catch (e) { return null; } },
    set(v) { try { localStorage.setItem(LS, JSON.stringify(v)); } catch (e) { /* private mode: ask every time */ } },
    clear() { try { localStorage.removeItem(LS); } catch (e) { /* nothing stored */ } },
  };
  const hhmm = (iso) => (iso || '').slice(11, 16);

  async function getJSON(path) {
    const r = await fetch(`${path}?t=${Date.now()}`, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${path} ${r.status}`);
    return r.json();
  }

  async function show(date, p) {
    const html = await KP.decryptPayload(state.key, p);
    $('frame').srcdoc = html;
    state.date = date;
    state.shown = p.built_at;
    state.pending = null;
    $('status').textContent = `${date.slice(5)} 更新 ${hhmm(p.built_at)}`;
    $('newer').hidden = true;
    $('date').value = date;
  }

  function ask(date, p, msg) {
    $('lock').hidden = false;
    $('msg').textContent = msg || '';
    $('form').onsubmit = async (ev) => {
      ev.preventDefault();
      $('msg').textContent = '確認中…';
      try {
        state.key = await KP.deriveKey($('pass').value, p.salt, p.iter);
        await show(date, p);
        if ($('remember').checked) store.set({ salt: p.salt, iter: p.iter, raw: await KP.exportKey(state.key) });
        $('lock').hidden = true;
        $('pass').value = '';
      } catch (e) {
        state.key = null;
        $('msg').textContent = '合言葉が違います。';
      }
    };
    $('pass').focus();
  }

  async function load(date) {
    const p = await getJSON(`cards/${date}.json`);
    if (!state.key) {
      const saved = store.get();
      if (saved && saved.salt === p.salt && saved.iter === p.iter) {
        try { state.key = await KP.importKey(saved.raw); } catch (e) { state.key = null; }
      }
    }
    if (!state.key) return ask(date, p);
    try {
      await show(date, p);
    } catch (e) {
      state.key = null;
      store.clear();
      ask(date, p, '合言葉が変わりました。もう一度入れてください。');
    }
  }

  function fillDates(ix) {
    const sel = $('date');
    const dates = (ix.dates || []).slice(0, 14);
    if (sel.options.length !== dates.length) sel.innerHTML = dates.map((d) => `<option value="${d}">${d}</option>`).join('');
    sel.value = state.date || ix.latest;
  }

  async function poll() {
    try {
      const ix = await getJSON('cards/index.json');
      fillDates(ix);
      const meta = (ix.days || {})[state.date];
      if (state.key && meta && meta.built_at !== state.shown) {
        state.pending = state.date;
        $('newer').textContent = `新しい版 ${hhmm(meta.built_at)}`;
        $('newer').hidden = false;
      }
    } catch (e) { /* offline: keep the page that is shown */ }
  }

  const fail = (e) => { $('status').textContent = '読み込めません'; console.error(e); };

  async function init() {
    $('date').onchange = () => load($('date').value).catch(fail);
    $('newer').onclick = () => load(state.pending || state.date).catch(fail);
    $('forget').onclick = () => { store.clear(); location.reload(); };
    const ix = await getJSON('cards/index.json');
    fillDates(ix);
    const q = new URLSearchParams(location.search).get('d');
    await load(q && (ix.dates || []).includes(q) ? q : ix.latest);
    setInterval(poll, 60000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  }
  init().catch(fail);
})(globalThis);
