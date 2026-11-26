<?php
declare(strict_types=1);

// Tworzy config.php: hash hasła i losowy sekret (podpisuje sesje i klucze limitu logowania).
// Ponowne uruchomienie = zmiana hasła i wylogowanie wszystkich urządzeń.
// Użycie: php bin/setup.php   (albo: echo 'haslo' | php bin/setup.php - bez pytania)

require dirname(__DIR__) . '/src/Auth.php';

$target = getenv('BOREDLINKS_CONFIG') ?: dirname(__DIR__) . '/config.php';
$tty = stream_isatty(STDIN);
if ($tty) {
    fwrite(STDOUT, 'Nowe hasło: ');
    shell_exec('stty -echo');
}
$password = rtrim((string) fgets(STDIN), "\r\n");
if ($tty) {
    shell_exec('stty echo');
    fwrite(STDOUT, "\n");
}
if (mb_strlen($password, 'UTF-8') < Auth::MIN_PASSWORD) {
    fwrite(STDERR, 'Hasło musi mieć co najmniej ' . Auth::MIN_PASSWORD . " znaków.\n");
    exit(1);
}

// Zapis do pliku tymczasowego 0600 i podmiana przez rename - działający config.php nigdy nie jest w połowie zapisany
$tmp = $target . '.tmp-' . bin2hex(random_bytes(4));
$old = umask(0077);
$ok = file_put_contents($tmp, Auth::configFile($password)) !== false
    && chmod($tmp, 0600)
    && rename($tmp, $target);
umask($old);
if (!$ok) {
    @unlink($tmp);
    fwrite(STDERR, "Nie udało się zapisać $target\n");
    exit(1);
}
echo "Zapisano $target\n";
