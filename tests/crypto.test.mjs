import assert from 'node:assert/strict';
import { seal, open, needsPassword, toB64u, fromB64u } from '../public/assets/crypto.js';

const text = 'Zażółć gęślą jaźń 🔑\nlinia 2';

const a = await seal(text);
assert.match(a.blob, /^[A-Za-z0-9_-]+$/);
assert.equal(a.key.length, 43);
assert.equal(needsPassword(a.blob), false);
assert.equal(await open(a.blob, a.key), text);
await assert.rejects(open(a.blob, (await seal('x')).key), 'inny klucz');

const b = await seal(text, 'tajne');
assert.equal(needsPassword(b.blob), true);
assert.equal(await open(b.blob, b.key, 'tajne'), text);
await assert.rejects(open(b.blob, b.key, 'zle'), 'złe hasło');
await assert.rejects(open(b.blob, b.key), 'brak hasła');

const tampered = fromB64u(b.blob);
tampered[1] = 0;
await assert.rejects(open(toB64u(tampered), b.key), 'zdjęta flaga hasła');
const unknownFlag = fromB64u(a.blob);
unknownFlag[1] = 2;
await assert.rejects(open(toB64u(unknownFlag), a.key), /unsupported/, 'nieznana flaga');
await assert.rejects(open(toB64u(fromB64u(a.blob).subarray(0, 20)), a.key), /truncated/, 'ucięty blob');

const bom = '﻿zaczyna się od BOM';
const c = await seal(bom);
assert.equal(await open(c.blob, c.key), bom, 'BOM na początku zachowany');

const big = 'x'.repeat(10000 * 4);
const d = await seal(big);
assert.ok(d.blob.length < 100000, 'maks. treść mieści się w limicie serwera');
assert.equal(await open(d.blob, d.key), big);

// Stałe wektory formatu v1 - zmiana KDF albo układu blobu zepsuje istniejące linki
assert.equal(await open(
  'AQGLOMoVvF70yDkGHApAwYIcTGfwRe-2r_7L-WRcZNZoPhVCiJqk30z8PecO9_8Fb2y0HSJVEX3rO0mlyZmv6c-ZQNM',
  'xRmc-hS-u9qcnMYxIcQrsdlwT4ULYY71SLxMyXTeO3w',
  'haslo-wektora',
), 'wektor v1 - zażółć', 'wektor v1 z hasłem');
assert.equal(await open(
  'AQDD_T16_PVg9i5VERc54WT0UBDiY66I0MVXR9W2XtjJuf6t6gUwWOAesQ',
  '3d1HuM8Wr5OB6dMybM-6dbfGWpwpKajKC7uP1yh2TwM',
), '﻿bez hasła', 'wektor v1 bez hasła (z BOM)');

console.log('crypto: wszystkie testy OK');
