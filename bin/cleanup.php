<?php
declare(strict_types=1);

// Usuwa wygasłe wiadomości, sesje i stare nieudane logowania. Do crona na hostingu, np. co godzinę:
//   php /ścieżka/do/boredlinks/bin/cleanup.php

require dirname(__DIR__) . '/src/Store.php';

$dbPath = getenv('BOREDLINKS_DB') ?: dirname(__DIR__) . '/data/boredlinks.sqlite';
if (!is_file($dbPath)) {
    exit(0);
}
$removed = (new Store($dbPath))->purge(time());
echo "Usunięto wygasłych wiadomości: $removed\n";
