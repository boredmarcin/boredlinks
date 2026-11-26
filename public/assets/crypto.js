// Szyfrowanie wiadomości w przeglądarce (WebCrypto). Serwer dostaje tylko blob.
// Blob (base64url): [wersja=1][flagi: bit0 = hasło][sól 16 B, gdy hasło][IV 12 B][szyfrogram AES-256-GCM + tag].
// Nagłówek (wersja, flagi, sól) jest danymi uwierzytelnionymi (AAD), więc nie da się zdjąć flagi hasła.
// Klucz AES: 32 losowe bajty z #fragmentu linku; z hasłem SHA-256(klucz || PBKDF2(hasło, sól)).

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const VERSION = 1;
const FLAG_PASSWORD = 1;
const PBKDF2_ITERATIONS = 600000;

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

export function toB64u(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64u(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function aesKey(raw, password, salt) {
  let material = raw;
  if (password) {
    const pw = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, pw, 256);
    material = new Uint8Array(await crypto.subtle.digest('SHA-256', concat(raw, new Uint8Array(bits))));
  }
  return crypto.subtle.importKey('raw', material, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** @returns {Promise<{blob: string, key: string}>} */
export async function seal(text, password = '') {
  const raw = random(32);
  const salt = password ? random(16) : new Uint8Array(0);
  const header = concat(Uint8Array.of(VERSION, password ? FLAG_PASSWORD : 0), salt);
  const iv = random(12);
  const key = await aesKey(raw, password, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header }, key, enc.encode(text)));
  return { blob: toB64u(concat(header, iv, ct)), key: toB64u(raw) };
}

export function needsPassword(blob) {
  return (fromB64u(blob)[1] & FLAG_PASSWORD) !== 0;
}

/** Rzuca wyjątek przy złym kluczu, haśle albo uszkodzonym blobie. */
export async function open(blob, keyStr, password = '') {
  const bytes = fromB64u(blob);
  if (bytes[0] !== VERSION || (bytes[1] & ~FLAG_PASSWORD) !== 0) throw new Error('unsupported format');
  const headerLen = 2 + (bytes[1] & FLAG_PASSWORD ? 16 : 0);
  if (bytes.length < headerLen + 12 + 16) throw new Error('truncated');
  const header = bytes.subarray(0, headerLen);
  const iv = bytes.subarray(headerLen, headerLen + 12);
  const key = await aesKey(fromB64u(keyStr), password, header.subarray(2));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header }, key, bytes.subarray(headerLen + 12));
  return dec.decode(pt);
}
