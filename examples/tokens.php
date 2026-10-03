<?php
/**
 * Fresh tokens for pages served from a page cache (the refresh_url in config.php).
 */

$guard = require __DIR__ . '/config.php';
$guard->sendTokens();
