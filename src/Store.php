<?php
declare(strict_types=1);

/** SQLite: szyfrogramy (jednorazowy odczyt = usunięcie), sesje logowania, nieudane logowania, sprzątanie wygasłych. */
final class Store
{
    public const TTLS = [3600, 86400, 604800];
    public const MAX_BLOB = 100000;
    // nagłówek 2 B + IV 12 B + tag GCM 16 B = 30 B = 40 znaków base64url
    public const MIN_BLOB = 40;
    public const LOGIN_MAX_FAILURES = 10;
    public const LOGIN_WINDOW = 900;

    private PDO $db;

    public function __construct(string $path)
    {
        $this->db = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => 5,
        ]);
        // secure_delete nadpisuje zerami usunięte dane w pliku bazy
        $this->db->exec('PRAGMA secure_delete = ON');
        $this->db->exec('CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, blob TEXT NOT NULL, expires INTEGER NOT NULL)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS messages_expires ON messages (expires)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS login_failures (key TEXT NOT NULL, at INTEGER NOT NULL)');
        $this->db->exec('CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, expires INTEGER NOT NULL)');
    }

    public static function validBlob(mixed $blob): bool
    {
        return is_string($blob)
            && strlen($blob) >= self::MIN_BLOB
            && strlen($blob) <= self::MAX_BLOB
            && preg_match('/^[A-Za-z0-9_-]+$/', $blob) === 1;
    }

    /** @return array{id: string, expires: int} */
    public function create(string $blob, int $ttl, ?int $now = null): array
    {
        if (!self::validBlob($blob) || !in_array($ttl, self::TTLS, true)) {
            throw new InvalidArgumentException('invalid blob or ttl');
        }
        $now ??= time();
        $this->purge($now);
        $id = bin2hex(random_bytes(16));
        $this->db->prepare('INSERT INTO messages (id, blob, expires) VALUES (?, ?, ?)')
            ->execute([$id, $blob, $now + $ttl]);
        return ['id' => $id, 'expires' => $now + $ttl];
    }

    /** Zwraca szyfrogram i usuwa wiadomość; null gdy nie ma albo wygasła. */
    public function take(string $id, ?int $now = null): ?string
    {
        // IMMEDIATE blokuje zapis od początku, więc dwa równoległe odczyty nie dostaną tej samej wiadomości
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $now ??= time();
            $q = $this->db->prepare('SELECT blob FROM messages WHERE id = ? AND expires > ?');
            $q->execute([$id, $now]);
            $blob = $q->fetchColumn();
            $this->db->prepare('DELETE FROM messages WHERE id = ? OR expires <= ?')->execute([$id, $now]);
            $this->db->exec('COMMIT');
        } catch (Throwable $e) {
            $this->db->exec('ROLLBACK');
            throw $e;
        }
        return $blob === false ? null : $blob;
    }

    public function addSession(string $hash, int $expires): void
    {
        $this->db->prepare('INSERT INTO sessions (hash, expires) VALUES (?, ?)')->execute([$hash, $expires]);
    }

    public function sessionValid(string $hash, int $now): bool
    {
        $q = $this->db->prepare('SELECT 1 FROM sessions WHERE hash = ? AND expires > ?');
        $q->execute([$hash, $now]);
        return $q->fetchColumn() !== false;
    }

    public function deleteSession(string $hash): void
    {
        $this->db->prepare('DELETE FROM sessions WHERE hash = ?')->execute([$hash]);
    }

    /**
     * Zapisuje próbę logowania jako nieudaną, zanim hasło zostanie sprawdzone; null, gdy limit jest wyczerpany.
     * Licznik i zapis są w jednej transakcji, więc równoległe żądania nie przekroczą limitu.
     * Zwrócony numer wpisu trafia do loginSucceeded() po dobrym haśle.
     */
    public function loginAttempt(string $key, int $now): ?int
    {
        $this->db->exec('BEGIN IMMEDIATE');
        try {
            $q = $this->db->prepare('SELECT COUNT(*) FROM login_failures WHERE key = ? AND at > ?');
            $q->execute([$key, $now - self::LOGIN_WINDOW]);
            $id = null;
            if ((int) $q->fetchColumn() < self::LOGIN_MAX_FAILURES) {
                $this->db->prepare('INSERT INTO login_failures (key, at) VALUES (?, ?)')->execute([$key, $now]);
                $id = (int) $this->db->lastInsertId();
            }
            $this->db->exec('COMMIT');
        } catch (Throwable $e) {
            $this->db->exec('ROLLBACK');
            throw $e;
        }
        return $id;
    }

    public function loginSucceeded(int $attempt): void
    {
        $this->db->prepare('DELETE FROM login_failures WHERE rowid = ?')->execute([$attempt]);
    }

    /** Usuwa wygasłe wiadomości, sesje i stare nieudane logowania; zwraca liczbę usuniętych wiadomości. */
    public function purge(int $now): int
    {
        $q = $this->db->prepare('DELETE FROM messages WHERE expires <= ?');
        $q->execute([$now]);
        $this->db->prepare('DELETE FROM sessions WHERE expires <= ?')->execute([$now]);
        $this->db->prepare('DELETE FROM login_failures WHERE at <= ?')->execute([$now - self::LOGIN_WINDOW]);
        return $q->rowCount();
    }
}
