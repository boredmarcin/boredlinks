<?php
declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/src/Store.php';
require $root . '/src/Auth.php';
require $root . '/src/Lang.php';

// shortcut: X-Forwarded-Proto jest brany na wiarę; poprawne za proxy hostingu, do zmiany przy hostingu bez proxy z TLS
function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
}

function common_headers(): void
{
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000');
    }
}

function json_out(int $status, array $body = []): never
{
    http_response_code($status);
    common_headers();
    header('Content-Type: application/json');
    echo json_encode($body ?: new stdClass());
    exit;
}

function page(string $file): never
{
    $lang = Lang::pick($_COOKIE[Lang::COOKIE] ?? null, $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '');
    common_headers();
    header('Content-Type: text/html; charset=utf-8');
    header("Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    header('Vary: Accept-Language, Cookie');
    echo Lang::render((string) file_get_contents($file), $lang, dirname(__DIR__) . '/lang');
    exit;
}

/** POST tylko z naszej strony: dokładnie application/json (wymusza preflight CORS) i Origin równy naszemu adresowi, jeśli jest. */
function same_origin_json(): void
{
    $type = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    $self = (is_https() ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? '');
    if ($type !== 'application/json' || ($origin !== null && strtolower($origin) !== strtolower($self))) {
        json_out(403, ['error' => 'forbidden']);
    }
}

function json_input(): array
{
    $input = json_decode((string) file_get_contents('php://input', false, null, 0, Store::MAX_BLOB + 1000), true);
    return is_array($input) ? $input : [];
}

function set_auth_cookie(string $value, int $expires): void
{
    setcookie(Auth::COOKIE, $value, [
        'expires' => $expires,
        'path' => '/',
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

// HEAD obsługiwany jak GET (PHP sam pomija treść odpowiedzi)
$method = ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD' ? 'GET' : ($_SERVER['REQUEST_METHOD'] ?? 'GET');
// shortcut: aplikacja zakłada, że stoi w katalogu głównym domeny; podkatalog wymaga zdjęcia prefiksu ścieżki
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// wbudowany serwer PHP (lokalnie) sam podaje pliki statyczne z public/
if (PHP_SAPI === 'cli-server' && $path !== '/' && !str_ends_with($path, '.php') && is_file(__DIR__ . $path)) {
    return false;
}

if ($method === 'GET' && preg_match('#^/m/[0-9a-f]{32}$#', $path)) {
    // GET tylko pokazuje stronę; wiadomość zużywa POST /api/messages/{id}/open
    page($root . '/pages/read.html');
}

$isApi = str_starts_with($path, '/api/');
if (!$isApi && !($method === 'GET' && $path === '/')) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Nie znaleziono');
}

try {
    $configPath = getenv('BOREDLINKS_CONFIG') ?: $root . '/config.php';
    if (!is_file($configPath)) {
        // Pierwsze uruchomienie: dopóki nie ma config.php, hasło ustawia się w przeglądarce
        if (!$isApi) {
            page($root . '/pages/setup.html');
        }
        if ($path === '/api/setup' && $method === 'POST') {
            same_origin_json();
            $password = json_input()['password'] ?? null;
            if (!is_string($password) || mb_strlen($password, 'UTF-8') < Auth::MIN_PASSWORD) {
                json_out(400, ['error' => 'password_too_short']);
            }
            // tryb 'x' tworzy plik tylko wtedy, gdy go nie ma - z dwóch równoczesnych instalacji wygrywa jedna
            $old = umask(0077);
            $file = @fopen($configPath, 'x');
            umask($old);
            if ($file === false) {
                is_file($configPath) ? json_out(409, ['error' => 'already_configured']) : json_out(500, ['error' => 'config_not_writable']);
            }
            fwrite($file, Auth::configFile($password));
            fclose($file);
            json_out(200);
        }
        throw new LogicException('missing config.php');
    }
    $config = require $configPath;
    if (!is_array($config) || !is_string($config['password_hash'] ?? null) || !is_string($config['secret'] ?? null)) {
        throw new LogicException('invalid config.php');
    }

    $dbPath = getenv('BOREDLINKS_DB') ?: $root . '/data/boredlinks.sqlite';
    if (!is_dir(dirname($dbPath))) {
        mkdir(dirname($dbPath), 0700, true);
    }
    $store = new Store($dbPath);
    $auth = new Auth($config['secret']);
    $now = time();
    $sessionHash = $auth->hash($_COOKIE[Auth::COOKIE] ?? null);
    $loggedIn = $sessionHash !== null && $store->sessionValid($sessionHash, $now);

    if (!$isApi) {
        page($root . ($loggedIn ? '/pages/create.html' : '/pages/login.html'));
    }

    if (preg_match('#^/api/messages/([0-9a-f]{32})/open$#', $path, $m) && $method === 'POST') {
        same_origin_json();
        $blob = $store->take($m[1]);
        $blob === null ? json_out(404, ['error' => 'gone']) : json_out(200, ['blob' => $blob]);
    }

    if ($path === '/api/login' && $method === 'POST') {
        same_origin_json();
        $key = $auth->clientKey(Auth::clientIp($_SERVER));
        $attempt = $store->loginAttempt($key, $now);
        if ($attempt === null) {
            json_out(429, ['error' => 'too_many_attempts']);
        }
        $password = json_input()['password'] ?? null;
        if (!is_string($password) || !password_verify($password, $config['password_hash'])) {
            json_out(401, ['error' => 'bad_password']);
        }
        $store->loginSucceeded($attempt);
        $token = Auth::newToken();
        $store->addSession((string) $auth->hash($token), $now + Auth::TTL);
        set_auth_cookie($token, $now + Auth::TTL);
        json_out(200);
    }

    if ($path === '/api/logout' && $method === 'POST') {
        same_origin_json();
        if ($sessionHash !== null) {
            $store->deleteSession($sessionHash);
        }
        set_auth_cookie('', 1);
        json_out(200);
    }

    if ($path === '/api/messages' && $method === 'POST') {
        same_origin_json();
        if (!$loggedIn) {
            json_out(401, ['error' => 'login_required']);
        }
        $input = json_input();
        $blob = $input['blob'] ?? null;
        $ttl = $input['ttl'] ?? null;
        if (!Store::validBlob($blob) || !in_array($ttl, Store::TTLS, true)) {
            json_out(400, ['error' => 'invalid_input']);
        }
        json_out(201, $store->create($blob, $ttl, $now));
    }

    json_out(404, ['error' => 'not_found']);
} catch (Throwable $e) {
    error_log('[BoredLinks] ' . $e->getMessage());
    $setup = $e instanceof LogicException;
    if ($isApi) {
        json_out(500, ['error' => $setup ? 'setup_required' : 'server_error']);
    }
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    exit($setup ? 'Błędny config.php - usuń go i otwórz stronę ponownie albo uruchom: php bin/setup.php' : 'Błąd serwera / Server error');
}
