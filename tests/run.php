<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Store.php';

function check(bool $ok, string $what): void
{
    echo ($ok ? 'ok   ' : 'FAIL ') . $what . "\n";
    if (!$ok) {
        exit(1);
    }
}

$db = tempnam(sys_get_temp_dir(), 'bl');
$s = new Store($db);
$now = 1_000_000;

$blob = str_repeat('A', Store::MIN_BLOB) . '_-';
$m = $s->create($blob, 3600, $now);
check(strlen($m['id']) === 32 && $m['expires'] === $now + 3600, 'create zwraca id i expires');
check($s->take($m['id'], $now) === $blob, 'pierwszy odczyt zwraca szyfrogram');
check($s->take($m['id'], $now) === null, 'drugi odczyt = brak');

$m = $s->create($blob, 3600, $now);
check($s->take($m['id'], $now + 3600) === null, 'wygasła = brak');

$m = $s->create($blob, 3600, $now);
check($s->purge($now + 3601) === 1 && $s->take($m['id'], $now) === null, 'purge usuwa wygasłe');

$m = $s->create($blob, 3600, $now);
$other = new Store($db);
$s2 = new Store($db);
check($other->take($m['id'], $now) === $blob && $s2->take($m['id'], $now) === null, 'osobne połączenia do bazy: wiadomość dostaje tylko pierwsze');

foreach ([[$blob, 60], ['a b' . $blob, 3600], ['<x>' . $blob, 3600], [str_repeat('a', Store::MIN_BLOB - 1), 3600], [str_repeat('a', Store::MAX_BLOB + 1), 3600]] as [$b, $t]) {
    try {
        $s->create($b, $t, $now);
        check(false, 'odrzuca blob/ttl: ' . substr($b, 0, 10) . ' (' . strlen($b) . ") $t");
    } catch (InvalidArgumentException) {
        check(true, 'odrzuca blob/ttl: ' . substr($b, 0, 10) . ' (' . strlen($b) . ") $t");
    }
}

$s->addSession('h1', $now + 100);
check($s->sessionValid('h1', $now) && !$s->sessionValid('h2', $now), 'sesja: ważna tylko zapisana');
check(!$s->sessionValid('h1', $now + 100), 'sesja: wygasa');
$s->deleteSession('h1');
check(!$s->sessionValid('h1', $now), 'sesja: usunięta po wylogowaniu');

$first = $s->loginAttempt('k', $now);
check($first !== null, 'logowanie: brak blokady na start');
$s->loginSucceeded($first);
for ($i = 0; $i < Store::LOGIN_MAX_FAILURES; $i++) {
    check($s->loginAttempt('k', $now) !== null, 'logowanie: próba ' . ($i + 1) . ' w limicie (udane logowanie się nie liczy)');
}
check($s->loginAttempt('k', $now) === null, 'logowanie: blokada po limicie prób');
check($s->loginAttempt('inny', $now) !== null, 'logowanie: blokada tylko dla tego klucza');
check($s->loginAttempt('k', $now + Store::LOGIN_WINDOW) !== null, 'logowanie: blokada mija po oknie');

require dirname(__DIR__) . '/src/Auth.php';
$a = new Auth(str_repeat('s', 64));
$t = Auth::newToken();
check(preg_match('/^[0-9a-f]{64}$/', $t) === 1 && $t !== Auth::newToken(), 'token losowy, 64 hex');
check($a->hash($t) !== null && $a->hash($t) === $a->hash($t), 'hash tokenu stały dla sekretu');
check($a->hash($t) !== (new Auth(str_repeat('x', 64)))->hash($t), 'nowy sekret = inne hashe (wylogowanie wszędzie)');
check(Auth::inRanges('104.16.1.2', ['104.16.0.0/13']) && !Auth::inRanges('104.24.0.1', ['104.16.0.0/13']), 'CIDR v4');
check(Auth::inRanges('2a06:98c7::1', ['2a06:98c0::/29']) && !Auth::inRanges('2a06:98c8::1', ['2a06:98c0::/29']), 'CIDR v6 (granica /29)');
check(!Auth::inRanges('104.16.1.2', ['2400:cb00::/32']) && !Auth::inRanges('śmieci', ['104.16.0.0/13']), 'CIDR: inna rodzina adresów, śmieci');
check(Auth::clientIp(['REMOTE_ADDR' => '172.70.1.1', 'HTTP_CF_CONNECTING_IP' => '83.1.2.3']) === '83.1.2.3', 'IP: za Cloudflare bierze CF-Connecting-IP');
check(Auth::clientIp(['REMOTE_ADDR' => '83.9.9.9', 'HTTP_CF_CONNECTING_IP' => '1.1.1.1']) === '83.9.9.9', 'IP: podrobiony nagłówek spoza Cloudflare ignorowany');
check(Auth::clientIp(['REMOTE_ADDR' => '172.70.1.1', 'HTTP_CF_CONNECTING_IP' => 'x']) === '172.70.1.1', 'IP: śmieci w nagłówku ignorowane');
check($a->clientKey('2001:db8:1:2::1') === $a->clientKey('2001:db8:1:2:ffff::9') && $a->clientKey('2001:db8:1:2::1') !== $a->clientKey('2001:db8:1:3::1'), 'limit: IPv6 liczony podsiecią /64');
check($a->clientKey('83.1.2.3') !== $a->clientKey('83.1.2.4'), 'limit: IPv4 liczony pełnym adresem');
check($a->hash(null) === null && $a->hash('abc') === null && $a->hash(strtoupper($t)) === null, 'śmieci zamiast tokenu odrzucone');

require dirname(__DIR__) . '/src/Lang.php';
check(Lang::pick(null, 'pl-PL,pl;q=0.9') === 'pl' && Lang::pick(null, 'de-DE') === 'en' && Lang::pick(null, '') === 'en', 'język z przeglądarki');
check(Lang::pick('pl', 'en-US') === 'pl' && Lang::pick('xx', 'pl') === 'pl', 'ciasteczko wygrywa, śmieci ignorowane');
check(Lang::pick(null, 'de-DE,de;q=0.9,pl;q=0.8,en;q=0.5') === 'pl' && Lang::pick(null, 'pl;q=0.3, en-GB;q=0.7') === 'en', 'język: wagi q');
$langDir = dirname(__DIR__) . '/lang';
check(array_keys(require "$langDir/pl.php") === array_keys(require "$langDir/en.php"), 'pl i en mają te same klucze');
foreach (glob(dirname(__DIR__) . '/pages/*.html') as $tpl) {
    foreach (Lang::SUPPORTED as $l) {
        $html = Lang::render((string) file_get_contents($tpl), $l, $langDir);
        check(!str_contains($html, '{{'), basename($tpl) . " ($l): brak niewypełnionych {{kluczy}}");
    }
}

unlink($db);
echo "Store, Auth, Lang: wszystkie testy OK\n";
