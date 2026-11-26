import { seal, open, needsPassword } from './crypto.js';

const $ = (s) => document.querySelector(s);
const M = JSON.parse(document.body.dataset.msg || '{}');

function showError(msg) {
  const el = $('#error');
  el.textContent = msg;
  el.hidden = !msg;
}

// Przełącznik języka przeładowuje stronę - chowany, gdy na stronie jest coś, czego przeładowanie by nie odtworzyło
const lockLanguage = () => { const seg = $('.seg'); if (seg) seg.hidden = true; };

const postJson = (url, body) => fetch(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

// Przycisk w stanie ładowania na czas szyfrowania/żądania
function busy(button, on) {
  button.disabled = on;
  button.classList.toggle('busy', on);
}

async function copy(field, button) {
  const status = $('#copy-status');
  const label = button.querySelector('span');
  try {
    await navigator.clipboard.writeText(field.value);
    const text = label.textContent;
    label.textContent = M.copied;
    button.classList.add('done');
    setTimeout(() => { label.textContent = text; button.classList.remove('done'); }, 1800);
  } catch {
    field.select();
    status.textContent = M.copy_manual;
  }
}

function initCreate(form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('');
    const button = form.querySelector('button[type=submit]');
    busy(button, true);
    try {
      const password = $('#password').value;
      const { blob, key } = await seal($('#text').value, password);
      const ttl = Number(form.querySelector('input[name=ttl]:checked').value);
      const res = await postJson('/api/messages', { blob, ttl });
      // bez przeładowania - wpisana treść zostaje w polu
      if (res.status === 401) { showError(M.session_expired); busy(button, false); return; }
      if (res.status !== 201) throw new Error(String(res.status));
      const { id, expires } = await res.json();
      $('#link').value = `${location.origin}/m/${id}#${key}`;
      const when = new Intl.DateTimeFormat(document.documentElement.lang, { dateStyle: 'medium', timeStyle: 'short' });
      $('#expires').textContent = `${M.expires} ${when.format(new Date(expires * 1000))}.`;
      $('#result-note').hidden = !password;
      form.reset();
      lockLanguage();
      form.hidden = true;
      $('#result').hidden = false;
      $('#link').select();
    } catch {
      showError(M.create_failed);
      busy(button, false);
    }
  });
  const text = $('#text');
  const count = () => {
    const n = text.value.length;
    $('#count').textContent = n ? `${n.toLocaleString(document.documentElement.lang)} / ${text.maxLength.toLocaleString(document.documentElement.lang)}` : '';
    $('#count').classList.toggle('near', n > text.maxLength * 0.9);
  };
  text.addEventListener('input', count);
  $('#copy').addEventListener('click', (e) => copy($('#link'), e.currentTarget));
  $('#logout').addEventListener('click', async () => {
    try {
      const res = await postJson('/api/logout', {});
      if (res.ok) { location.reload(); return; }
    } catch { /* komunikat niżej */ }
    if ($('#result').hidden) showError(M.logout_failed);
    else $('#copy-status').textContent = M.logout_failed;
  });
}

function initLogin(form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('');
    const button = form.querySelector('button[type=submit]');
    busy(button, true);
    try {
      const res = await postJson('/api/login', { password: $('#login-password').value });
      if (res.ok) { location.reload(); return; }
      showError(res.status === 401 ? M.bad_password : res.status === 429 ? M.too_many : M.server_error);
    } catch {
      showError(M.network);
    }
    busy(button, false);
  });
}

function initSetup(form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('');
    const button = form.querySelector('button[type=submit]');
    busy(button, true);
    try {
      const res = await postJson('/api/setup', { password: $('#setup-password').value });
      // 404/409 = hasło jest już ustawione (np. w drugiej karcie) - po przeładowaniu pokaże się logowanie
      if (res.ok || res.status === 404 || res.status === 409) { location.reload(); return; }
      showError(res.status === 400 ? M.setup_short : M.setup_failed);
    } catch {
      showError(M.network);
    }
    busy(button, false);
  });
}

function initRead() {
  const key = location.hash.slice(1);
  const id = location.pathname.split('/').pop();
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) {
    $('#step-reveal').hidden = true;
    showError(M.link_incomplete);
    return;
  }
  if (!globalThis.crypto?.subtle) {
    $('#step-reveal').hidden = true;
    showError(M.no_crypto);
    return;
  }

  let blob = '';
  const show = (text) => {
    $('#step-password').hidden = true;
    $('#pw').value = '';
    $('#message').value = text;
    $('#step-message').hidden = false;
    $('#message').focus();
  };
  // Po wyjściu ze strony nic nie zostaje w polach (także w kopii strony z pamięci podręcznej przycisku Wstecz)
  addEventListener('pagehide', () => {
    blob = '';
    $('#message').value = '';
    $('#pw').value = '';
  });

  $('#reveal').addEventListener('click', async (e) => {
    const button = e.currentTarget;
    busy(button, true);
    showError('');
    try {
      const res = await postJson(`/api/messages/${id}/open`, {});
      if (res.status === 404) {
        $('#step-reveal').hidden = true;
        showError(M.gone);
        return;
      }
      if (!res.ok) throw new Error(String(res.status));
      ({ blob } = await res.json());
      lockLanguage();
      // klucz zostaje tylko w pamięci strony, znika z paska adresu i historii
      history.replaceState(null, '', location.pathname);
      $('#step-reveal').hidden = true;
      if (needsPassword(blob)) {
        $('#step-password').hidden = false;
        $('#pw').focus();
      } else {
        show(await open(blob, key));
      }
    } catch {
      showError(blob ? M.broken : M.network);
      if (!blob) busy(button, false);
    }
  });

  $('#step-password').addEventListener('submit', async (e) => {
    e.preventDefault();
    showError('');
    const button = e.currentTarget.querySelector('button[type=submit]');
    busy(button, true);
    try {
      show(await open(blob, key, $('#pw').value));
    } catch {
      showError(M.bad_password_read);
      $('#pw').select();
    }
    busy(button, false);
  });
  $('#copy').addEventListener('click', (e) => copy($('#message'), e.currentTarget));
}

// Przełącznik języka: ciasteczko + przeładowanie (zachowuje #klucz w linku do wiadomości)
for (const b of document.querySelectorAll('[data-lang]')) {
  b.setAttribute('aria-pressed', String(b.dataset.lang === document.documentElement.lang));
  b.addEventListener('click', () => {
    document.cookie = `bl_lang=${b.dataset.lang}; path=/; max-age=31536000; samesite=lax`;
    location.reload();
  });
}

for (const eye of document.querySelectorAll('[data-eye]')) {
  const input = eye.previousElementSibling;
  const sync = () => {
    const shown = input.type === 'text';
    eye.setAttribute('aria-pressed', String(shown));
    eye.setAttribute('aria-label', shown ? M.hide_password : M.show_password);
  };
  sync();
  eye.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
    sync();
    input.focus();
  });
}

if ($('#create')) initCreate($('#create'));
else if ($('#login')) initLogin($('#login'));
else if ($('#setup')) initSetup($('#setup'));
else if ($('#read')) initRead();
