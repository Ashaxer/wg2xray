/* ============================================================
   WireGuard ⇄ Xray WireGuard-outbound converter
   Pure client-side. No dependencies, no network calls.
   ============================================================ */
(function () {
  'use strict';

  /* ---------------- DOM ---------------- */

  const $ = (id) => document.getElementById(id);

  const srcEl   = $('source');
  const outEl   = $('output');
  const notesEl = $('notes');

  /* ---------------- small helpers ---------------- */

  /** Split a comma separated list into trimmed, non-empty items. */
  function splitList(v) {
    return String(v == null ? '' : v)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  /** Coerce string | array | undefined into a clean array of strings. */
  function toArray(v) {
    if (v == null) return [];
    if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
    if (typeof v === 'string') return splitList(v);
    return [];
  }

  /** Add /32 or /128 when the address has no prefix. */
  function normalizeCidr(addr) {
    const a = String(addr).trim();
    if (!a) return '';
    if (a.includes('/')) return a;
    return a.includes(':') ? a + '/128' : a + '/32';
  }

  function looksLikeJson(t) {
    const s = t.trim();
    return s.startsWith('{') || s.startsWith('[');
  }

  function looksLikeWg(t) {
    return /^\s*\[(Interface|Peer)\]/im.test(t);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  function showNotes(list) {
    const items = (list || []).filter(Boolean);
    if (!items.length) {
      notesEl.hidden = true;
      notesEl.innerHTML = '';
      return;
    }
    notesEl.hidden = false;
    notesEl.innerHTML =
      '<strong>Notes</strong><ul>' +
      items.map((n) => '<li>' + escapeHtml(n) + '</li>').join('') +
      '</ul>';
  }

  function setOutput(text) {
    outEl.value = text || '';
  }

  /* ---------------- WireGuard parsing ---------------- */

  /**
   * Parse a wg-quick / WireGuard .conf file.
   * Returns { iface: {key: value}, peers: [{key: value}, ...] }
   * Keys are lower-cased; comments (# and ;) are stripped.
   */
  function parseWg(text) {
    const conf = { iface: {}, peers: [] };
    let section = null;
    let peer = null;

    for (const rawLine of String(text).split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line) continue;
      if (line.startsWith('#') || line.startsWith(';')) continue;

      // Section header, e.g. [Interface] / [Peer]
      const head = line.match(/^\[([^\]]+)\]\s*$/);
      if (head) {
        const name = head[1].trim().toLowerCase();
        if (name === 'interface') {
          section = 'iface';
          peer = null;
        } else if (name === 'peer') {
          section = 'peer';
          peer = {};
          conf.peers.push(peer);
        } else {
          section = null;
          peer = null;
        }
        continue;
      }

      const eq = line.indexOf('=');
      if (eq === -1) continue;

      const key = line.slice(0, eq).trim().toLowerCase();
      let val = line.slice(eq + 1).trim();
      if (!key) continue;

      // strip trailing inline comment (values never legitimately contain '#')
      const hash = val.indexOf('#');
      if (hash > -1) val = val.slice(0, hash).trim();

      if (section === 'iface') conf.iface[key] = val;
      else if (section === 'peer' && peer) peer[key] = val;
    }

    return conf;
  }

  /** "1, 2, 3" -> [1,2,3] (only when exactly 3 numbers, WARP style) */
  function parseReserved(v) {
    if (!v) return null;
    const parts = String(v)
      .split(/[,\s]+/)
      .map((n) => parseInt(n, 10))
      .filter((n) => Number.isFinite(n));
    return parts.length === 3 ? parts : null;
  }

  /* ---------------- WireGuard -> Xray ---------------- */

  function wgToXray(text, opts) {
    const conf  = parseWg(text);
    const iface = conf.iface;
    const notes = [];

    const secretKey = iface.privatekey || '';
    if (!secretKey) throw new Error('No "PrivateKey" found under [Interface].');

    const address = splitList(iface.address).map(normalizeCidr).filter(Boolean);
    if (!address.length) {
      notes.push('No "Address" found — Xray needs at least one entry in settings.address.');
    }

    const settings = { address: address };

    // ✅ FIX: actually put the private key into the output JSON
    settings.secretKey = secretKey;

    // MTU
    let mtu = parseInt(iface.mtu, 10);
    if (!Number.isFinite(mtu) || mtu <= 0) {
      mtu = opts.defaultMtu;
      notes.push('No "MTU" in the config — defaulted to ' + mtu + '.');
    }
    settings.mtu = mtu;

    // Fields that cannot travel to Xray
    if (iface.dns) {
      notes.push('"DNS" is not part of an Xray WireGuard outbound — set DNS in the Xray "dns" block or a routing rule instead.');
    }
    if (iface.table) {
      notes.push('"Table" only affects wg-quick routing and has no Xray equivalent.');
    }
    if (iface.listenport) {
      notes.push('"ListenPort" is not supported by the Xray WireGuard outbound — dropped.');
    }
    if (iface.preup || iface.postup || iface.predown || iface.postdown || iface.saveconfig) {
      notes.push('wg-quick hook lines (PreUp/PostUp/PreDown/PostDown/SaveConfig) are not transferable to Xray.');
    }

    // WARP reserved (only meaningful if you already have a WARP keypair)
    const reserved = parseReserved(iface.reserved);
    if (reserved) {
      settings.reserved = reserved;
      notes.push('WARP "Reserved" detected and kept in the JSON.');
    }

    settings.peers = conf.peers.map((p, i) => {
      const n    = i + 1;
      const peer = {};

      const pub = p.publickey || '';
      if (!pub) notes.push('Peer #' + n + ' has no "PublicKey".');
      peer.publicKey = pub;

      if (p.presharedkey && p.presharedkey !== '(none)') {
        peer.preSharedKey = p.presharedkey;
      }

      const endpoint = p.endpoint || '';
      if (!endpoint) notes.push('Peer #' + n + ' has no "Endpoint" — Xray needs one to dial out.');
      if (endpoint) peer.endpoint = endpoint;

      const allowed = splitList(p.allowedips).map(normalizeCidr).filter(Boolean);
      if (allowed.length) peer.allowedIPs = allowed;
      else notes.push('Peer #' + n + ' has no "AllowedIPs".');

      const ka = parseInt(p.persistentkeepalive, 10);
      if (Number.isFinite(ka) && ka > 0) peer.keepAlive = ka;

      return peer;
    });

    if (!settings.peers.length) throw new Error('No [Peer] section found in the WireGuard config.');

    const outbound = {
      tag: opts.tag,
      protocol: 'wireguard',
      settings: settings
    };

    if (opts.extras) {
      outbound.streamSettings = { network: 'raw' };
      outbound.mux = { enabled: false };
    }

    const result = opts.wrap ? { outbounds: [outbound] } : outbound;

    return { text: JSON.stringify(result, null, 2), notes: notes };
  }

  /* ---------------- Xray -> WireGuard ---------------- */

  function pickOutbound(data) {
    if (Array.isArray(data)) {
      return data.find((o) => o && o.protocol === 'wireguard') || data[0] || null;
    }
    if (Array.isArray(data.outbounds)) {
      return data.outbounds.find((o) => o && o.protocol === 'wireguard') || data.outbounds[0] || null;
    }
    if (data.outbound && typeof data.outbound === 'object') return data.outbound;
    if (data.settings || data.protocol) return data;
    return null;
  }

  function xrayToWg(text) {
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      throw new Error('Invalid JSON: ' + e.message);
    }

    const notes = [];
    const ob = pickOutbound(data);
    if (!ob || typeof ob !== 'object') {
      throw new Error('Could not find a WireGuard outbound in this JSON.');
    }
    if (ob.protocol && ob.protocol !== 'wireguard') {
      notes.push('Outbound protocol is "' + ob.protocol + '" — parsing it as WireGuard anyway.');
    }

    const s = ob.settings || {};

    const secret = s.secretKey || s.privateKey || s.secret_key || '';
    if (!secret) throw new Error('No "secretKey" in settings.');

    const address = toArray(s.address).map(normalizeCidr).filter(Boolean);
    const mtu     = parseInt(s.mtu, 10);
    const hasMtu  = Number.isFinite(mtu) && mtu > 0;

    const lines = [];
    lines.push('[Interface]');
    lines.push('PrivateKey = ' + secret);

    if (address.length) {
      lines.push('Address = ' + address.join(', '));
    } else {
      notes.push('No "address" in the JSON — WireGuard requires one (e.g. 10.0.0.2/32).');
    }

    if (hasMtu) lines.push('MTU = ' + mtu);
    lines.push('Table = off');

    notes.push('Xray outbounds carry no DNS setting — add a "DNS =" line for your resolver (e.g. 10.0.0.1).');

    if (Array.isArray(s.reserved)) {
      notes.push('"reserved" (WARP) has no wg-quick equivalent — it only exists in the Xray JSON.');
    }
    if (s.domainStrategy) {
      notes.push('"domainStrategy" has no WireGuard equivalent — dropped.');
    }

    const peers = Array.isArray(s.peers) ? s.peers : [];
    if (!peers.length) notes.push('No "peers" found in the JSON.');

    peers.forEach((p, i) => {
      const n = i + 1;

      lines.push('');
      lines.push('[Peer]');

      const pub = p.publicKey || p.public_key || p.publickey || '';
      if (!pub) notes.push('Peer #' + n + ' has no "publicKey".');
      lines.push('PublicKey = ' + pub);

      const psk = p.preSharedKey || p.presharedKey || p.pre_shared_key || p.presharedkey;
      if (psk) lines.push('PresharedKey = ' + psk);

      const allowed = toArray(p.allowedIPs || p.allowedIps || p.allowed_ips || p.allowedips)
        .map(normalizeCidr)
        .filter(Boolean);
      lines.push('AllowedIPs = ' + (allowed.length ? allowed.join(', ') : '0.0.0.0/0, ::/0'));

      if (p.endpoint) {
        lines.push('Endpoint = ' + p.endpoint);
      } else {
        notes.push('Peer #' + n + ' has no "endpoint" — WireGuard cannot connect without it.');
      }

      const kaRaw = (p.keepAlive !== undefined && p.keepAlive !== null)
        ? p.keepAlive
        : (p.persistentKeepalive !== undefined ? p.persistentKeepalive : p.persistent_keepalive);
      const ka = parseInt(kaRaw, 10);
      if (Number.isFinite(ka) && ka > 0) lines.push('PersistentKeepalive = ' + ka);
    });

    return { text: lines.join('\n') + '\n', notes: notes };
  }

  /* ---------------- runner ---------------- */

  function readOptions() {
    return {
      tag: ($('opt-tag').value || 'wireguard-outbound').trim() || 'wireguard-outbound',
      extras: $('opt-extras').checked,
      wrap: $('opt-wrap').checked,
      defaultMtu: 1280
    };
  }

  function run(direction) {
    const raw = srcEl.value.trim();

    if (!raw) {
      setOutput('');
      showNotes(['Paste a WireGuard config or an Xray outbound JSON into the source box first.']);
      srcEl.focus();
      return;
    }

    const opts   = readOptions();
    const isJson = looksLikeJson(raw);
    const isWg   = looksLikeWg(raw);

    let dir = direction;
    let flip = '';

    if (dir === 'wg2xray' && isJson && !isWg) {
      dir = 'xray2wg';
      flip = 'Input looked like JSON, so it was converted Xray → WireGuard instead.';
    } else if (dir === 'xray2wg' && isWg && !isJson) {
      dir = 'wg2xray';
      flip = 'Input looked like a WireGuard config, so it was converted WireGuard → Xray instead.';
    }

    try {
      const res = (dir === 'wg2xray') ? wgToXray(raw, opts) : xrayToWg(raw, opts);
      setOutput(res.text);
      showNotes(flip ? [flip].concat(res.notes) : res.notes);
    } catch (err) {
      setOutput('');
      showNotes([flip, '❌ ' + (err && err.message ? err.message : String(err))]);
    }
  }

  /* ---------------- events ---------------- */

  $('btn-wg2xray').addEventListener('click', () => run('wg2xray'));
  $('btn-xray2wg').addEventListener('click', () => run('xray2wg'));

  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const el = btn.getAttribute('data-copy') === 'source' ? srcEl : outEl;
      if (!el.value) return;
      const original = btn.textContent;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(el.value);
        } else {
          const prevRO = el.readOnly;
          el.readOnly = false;
          el.select();
          document.execCommand('copy');
          el.readOnly = prevRO;
          el.setSelectionRange(0, 0);
        }
        btn.textContent = 'Copied';
      } catch (e) {
        btn.textContent = 'Failed';
      }
      setTimeout(() => { btn.textContent = original; }, 1200);
    });
  });

  document.querySelectorAll('[data-clear]').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (btn.getAttribute('data-clear') === 'source') {
        srcEl.value = '';
        srcEl.focus();
      } else {
        outEl.value = '';
      }
      showNotes([]);
    });
  });

  // Ctrl/Cmd + Enter  =>  WireGuard -> Xray
  srcEl.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      run('wg2xray');
    }
  });

  /* ---------------- demo content ---------------- */

  srcEl.value =
`[Interface]
PrivateKey = *****
Address = 10.2.0.2/32, 2a07:b944::2:2/128
DNS = 10.2.0.1, 2a07:b944::2:1
Table = off

[Peer]
PublicKey = 8jEgre7McUnWFLvjlQSenvYJgUGISWeNyLonrEupuDA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 146.70.230.114:51820
PersistentKeepalive = 25
`;

  // run once so the output box isn't empty on first load
  try {
    const demo = wgToXray(srcEl.value, readOptions());
    setOutput(demo.text);
    showNotes(demo.notes);
  } catch (e) {
    setOutput('');
  }

})();
