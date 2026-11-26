<?php
declare(strict_types=1);

/**
 * Logowanie jedynego użytkownika. Ciasteczko niesie losowy token; w bazie leży tylko HMAC tokenu z sekretem z config.php,
 * więc wylogowanie usuwa sesję, a nowy sekret (bin/setup.php) unieważnia wszystkie sesje naraz.
 */
final class Auth
{
    public const COOKIE = 'bl_auth';
    public const TTL = 30 * 86400;
    public const MIN_PASSWORD = 12;

    public function __construct(private string $secret)
    {
    }

    /** Treść config.php: hash hasła i losowy sekret (podpisuje sesje i klucze limitu logowania). */
    public static function configFile(string $password): string
    {
        return "<?php\nreturn " . var_export([
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            'secret' => bin2hex(random_bytes(32)),
        ], true) . ";\n";
    }

    public static function newToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /** Skrót tokenu do zapisu w bazie; null dla wartości, która nie jest tokenem. */
    public function hash(?string $token): ?string
    {
        if ($token === null || !preg_match('/^[0-9a-f]{64}$/', $token)) {
            return null;
        }
        return hash_hmac('sha256', 'session|' . $token, $this->secret);
    }

    // shortcut: lista z cloudflare.com/ips-v4 i ips-v6 z 2026-11-25; Cloudflare zmienia ją rzadko - sprawdzić przy problemach z limitem logowania
    private const CLOUDFLARE = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
        '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    /** IP odwiedzającego: CF-Connecting-IP tylko wtedy, gdy połączenie przyszło z adresu Cloudflare. */
    public static function clientIp(array $server): string
    {
        $remote = (string) ($server['REMOTE_ADDR'] ?? '');
        $forwarded = (string) ($server['HTTP_CF_CONNECTING_IP'] ?? '');
        if ($forwarded !== '' && filter_var($forwarded, FILTER_VALIDATE_IP) && self::inRanges($remote, self::CLOUDFLARE)) {
            return $forwarded;
        }
        return $remote;
    }

    /** @param list<string> $cidrs */
    public static function inRanges(string $ip, array $cidrs): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        foreach ($cidrs as $cidr) {
            [$net, $bits] = explode('/', $cidr);
            $netBin = inet_pton($net);
            if (strlen($netBin) !== strlen($bin)) {
                continue;
            }
            $bytes = intdiv((int) $bits, 8);
            $rest = (int) $bits % 8;
            if (substr($bin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
                continue;
            }
            $mask = $rest === 0 ? 0 : (0xFF << (8 - $rest)) & 0xFF;
            if ($rest === 0 || (ord($bin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask)) {
                return true;
            }
        }
        return false;
    }

    /** Klucz limitu prób logowania - IP nie jest zapisywane wprost. IPv6 liczy się całą podsiecią /64 (jeden abonent). */
    public function clientKey(string $ip): string
    {
        $bin = @inet_pton($ip);
        if ($bin !== false && strlen($bin) === 16) {
            $ip = inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8));
        }
        return hash_hmac('sha256', 'ip|' . $ip, $this->secret);
    }
}
