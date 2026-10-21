// FoxyVPN Windows frontend
if (!window.__TAURI__) {
  document.body.innerHTML = '<div style="padding:20px;color:#ef5350;font-family:sans-serif">Tauri API failed to load (withGlobalTauri). Please reinstall.</div>';
  throw new Error('no tauri');
}
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = id => document.getElementById(id);
let state = 'DISCONNECTED';
let elapsedTimer = null;
let countries = [];
let selected = { code: '', city: '' };

function fmtDur(s) {
  const h = String(Math.floor(s / 3600)).padStart(2, '0');
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const x = String(s % 60).padStart(2, '0');
  return `${h}:${m}:${x}`;
}

function setStatus(s) {
  state = s;
  const ring = $('powerBtn');
  ring.classList.toggle('connected', s === 'CONNECTED');
  ring.classList.toggle('connecting', s === 'CONNECTING');
  $('statusText').textContent = s === 'CONNECTED' ? 'Connected' : s === 'CONNECTING' ? 'Connecting…' : 'Disconnected';
  if (s === 'CONNECTED') startElapsed();
  else { stopElapsed(); if (s === 'DISCONNECTED') { $('elapsedText').textContent = '00:00:00'; markIp(false); } }
}

let t0 = 0;
function startElapsed() {
  stopElapsed();
  invoke('get_state').then(st => {
    t0 = st.connectedSince || Math.floor(Date.now() / 1000);
    elapsedTimer = setInterval(() => {
      $('elapsedText').textContent = fmtDur(Math.floor(Date.now() / 1000) - t0);
    }, 1000);
  }).catch(() => {});
}
function stopElapsed() { if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; } }

function markIp(protectedNow, ip, country) {
  const b = $('ipBadge');
  if (protectedNow) { b.textContent = 'Protected'; b.className = 'badge ok'; }
  else { b.textContent = 'Exposed'; b.className = 'badge bad'; }
  if (ip) {
    const flag = country ? flagOf(country) : '';
    $('ipText').textContent = flag ? `${flag} ${ip} • ${country}` : ip;
  }
}

function flagOf(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

async function refreshIp() {
  try {
    const st = await invoke('get_state');
    if (st.connected) {
      try {
        const r = await invoke('fetch_exit_info');
        markIp(true, r.ip, r.country);
      } catch { markIp(true); }
    } else {
      const r = await invoke('fetch_exit_info');
      markIp(false, r.ip, r.country);
    }
  } catch (e) { $('ipText').textContent = 'Checking…'; }
}

// ---- power button ----
$('powerBtn').onclick = async () => {
  if (state === 'DISCONNECTED') {
    setStatus('CONNECTING');
    $('errorText').classList.add('hidden');
    try {
      await invoke('connect', { countryCode: selected.code || null, cityCode: selected.city || null });
      setStatus('CONNECTED');
      updateLocationCard();
      refreshIp();
      refreshQuota();
    } catch (e) {
      setStatus('DISCONNECTED');
      $('errorText').textContent = String(e).slice(0, 300);
      $('errorText').classList.remove('hidden');
    }
  } else if (state === 'CONNECTED') {
    await invoke('disconnect').catch(() => {});
    setStatus('DISCONNECTED');
    refreshIp();
  } else {
    // cancel connecting
    await invoke('disconnect').catch(() => {});
    setStatus('DISCONNECTED');
  }
};

// ---- login ----
let pending2fa = false;
$('loginBtn').onclick = async () => {
  const btn = $('loginBtn');
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  $('loginErr').textContent = '';
  try {
  try {
    if (pending2fa) {
      await invoke('submit_2fa', { code: $('codeInp').value.trim() });
      await invoke('complete_2fa');
      pending2fa = false;
    } else {
      const r = await invoke('login', { email: $('emailInp').value.trim(), password: $('pwInp').value });
      if (r.needs2fa) {
        pending2fa = true;
        $('twofaRow').classList.remove('hidden');
        $('codeInp').focus();
        btn.textContent = 'Verify code';
        btn.disabled = false;
        return;
      }
    }
    $('loginOverlay').classList.remove('show');
    await afterLogin();
  } catch (e) {
    $('loginErr').textContent = String(e).slice(0, 250);
    btn.textContent = 'Sign in';
  }
  btn.disabled = false;
};

async function afterLogin() {
  await refreshCountries();
  await refreshQuota();
}

// ---- servers ----
$('locationCard').onclick = async () => {
  $('serversOverlay').classList.add('show');
  if (!countries.length) await refreshCountries();
};
$('closeServers').onclick = () => $('serversOverlay').classList.remove('show');

async function refreshCountries() {
  try {
    countries = await invoke('fetch_countries');
  } catch (e) {
    $('countryList').innerHTML = `<p style="color:var(--red);font-size:12px;padding:8px">${String(e).slice(0, 150)}</p>`;
    return;
  }
  const list = $('countryList');
  list.innerHTML = '';
  const rec = document.createElement('div');
  rec.className = 'country' + (!selected.code ? ' sel' : '');
  rec.innerHTML = `<span>🌐</span><span>Recommended</span>`;
  rec.onclick = () => { selected = { code: '', city: '' }; pickDone(); };
  list.appendChild(rec);
  for (const c of countries) {
    const el = document.createElement('div');
    el.className = 'country' + (selected.code === c.code ? ' sel' : '');
    el.innerHTML = `<span>${flagOf(c.code)}</span><span>${c.name}</span>`;
    el.onclick = () => { selected = { code: c.code, city: '' }; pickDone(); };
    list.appendChild(el);
  }
}
function pickDone() { updateLocationCard(); $('serversOverlay').classList.remove('show'); invoke('save_settings', { settings: { socks_port: 1080, http_port: 8080, selected_code: selected.code, selected_city: selected.city, full_tunnel: $('fullTunnelChk').checked } }).catch(() => {}); }

function updateLocationCard() {
  const c = countries.find(x => x.code === selected.code);
  if (c) { $('locFlag').textContent = flagOf(c.code); $('locName').textContent = c.name; }
  else { $('locFlag').textContent = '🌐'; $('locName').textContent = 'Recommended'; }
}

// ---- quota ----
async function refreshQuota() {
  try {
    const ent = await invoke('get_entitlement');
    const card = $('quotaCard');
    if (!ent.limited_bandwidth) {
      $('quotaText').textContent = 'Unlimited';
      $('quotaFill').style.width = '100%';
      card.classList.remove('hidden');
      return;
    }
    if (ent.quota_remaining != null && ent.quota_max) {
      $('quotaText').textContent = `${fmtGB(ent.quota_remaining)} / ${fmtGB(ent.quota_max)} left`;
      $('quotaFill').style.width = Math.max(2, Math.min(100, 100 * ent.quota_remaining / ent.quota_max)) + '%';
      card.classList.remove('hidden');
    }
  } catch (e) { /* ignore */ }
}
function fmtGB(b) { return b > 1e9 ? (b / 1e9).toFixed(1) + ' GB' : Math.round(b / 1e6) + ' MB'; }

// ---- settings / logs / theme ----
$('settingsBtn').onclick = async () => {
  const s = await invoke('load_settings').catch(() => ({ socks_port: 1080, http_port: 8080 }));
  $('socksPortInp').value = s.socks_port;
  $('httpPortInp').value = s.http_port;
  $('fullTunnelChk').checked = s.full_tunnel !== false;
  $('settingsOverlay').classList.add('show');
};
$('closeSettings').onclick = () => $('settingsOverlay').classList.remove('show');
$('saveSettings').onclick = async () => {
  await invoke('save_settings', { settings: { socks_port: +$('socksPortInp').value || 1080, http_port: +$('httpPortInp').value || 0, selected_code: selected.code, selected_city: selected.city, full_tunnel: $('fullTunnelChk').checked } });
  $('settingsOverlay').classList.remove('show');
};
$('logoutBtn').onclick = async () => {
  await invoke('disconnect').catch(() => {});
  await invoke('logout').catch(() => {});
  $('settingsOverlay').classList.remove('show');
  $('loginOverlay').classList.add('show');
  pending2fa = false;
  $('twofaRow').classList.add('hidden');
  $('loginBtn').textContent = 'Sign in';
};

$('logsBtn').onclick = async () => {
  const logs = await invoke('get_logs').catch(() => []);
  $('logsBody').textContent = logs.length ? logs.join('\n') : 'No logs yet';
  $('logsOverlay').classList.add('show');
};
$('closeLogs').onclick = () => $('logsOverlay').classList.remove('show');

$('themeBtn').onclick = () => {
  const light = document.documentElement.classList.toggle('light');
  $('themeBtn').textContent = light ? '☀️' : '🌙';
};

listen('vpn-edge-ip', (e) => {
  const { ip, country } = e.payload;
  markIp(true, ip, country);
});
listen('vpn-state', (e) => setStatus(e.payload));

// ---- init ----
(async () => {
  const auth = await invoke('get_auth_state').catch(() => ({ signedIn: false }));
  if (auth.signedIn) {
    $('loginOverlay').classList.remove('show');
    await afterLogin();
  } else if (auth.has2faPending) {
    pending2fa = true;
    $('twofaRow').classList.remove('hidden');
    $('loginBtn').textContent = 'Verify code';
  }
  const st = await invoke('get_state').catch(() => null);
  if (st && st.connected) setStatus('CONNECTED');
  updateLocationCard();
  refreshIp();
})();
