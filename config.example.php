<?php

/*
 * ITFlow example configuration.
 * Copy this file to config.php and edit values for your installation.
 */

$dbhost = 'localhost';
$dbusername = 'itflow';
$dbpassword = 'change_me';
$database = 'itflow';

$config_base_url = 'itflow.example.com';
$repo_branch = 'master';

$mysqli = mysqli_connect($dbhost, $dbusername, $dbpassword, $database);

if (!$mysqli) {
    die('Database connection failed: ' . mysqli_connect_error());
}

mysqli_set_charset($mysqli, 'utf8mb4');
