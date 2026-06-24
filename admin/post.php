<?php
/*
 * ITFlow - Admin GET/POST request handler
 */

require_once "../config.php";
require_once "../functions.php";
require_once "../includes/check_login.php";

// Define a variable that we can use to only allow running post files via inclusion (prevents people/bots poking them)
define('FROM_POST_HANDLER', true);

// Determine which files we should load

// Parse URL & get the path
$path = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_PATH);

// Get the base name (the page name)
$module = explode(".", basename($path))[0];

// Strip off any _details bits
$module = str_ireplace('_details', '', $module);

// Dynamically load admin-related module POST logic
if (isset($session_is_admin) && $session_is_admin) {
    // As (almost) every admin setting is only changed from 1 page, we can dynamically load the relevant logic inside this single admin check IF statement
    //  To add a new admin POST request handler, add a file named after the admin page
    //    e.g. changes made on the page http://itflow/admin_ticket_statues.php will load the page admin/post/admin_ticket_statues.php to handle the changes

    include_once "post/$module.php";
    
}

// Logout is the same for user and admin
require_once "../post/logout.php";

// TODO: Find a home for these
require_once "../post/misc.php";


// ITFlow server backup/restore/release-prep handlers.
// Loaded late so admin/post.php has already initialized the normal ITFlow context.
if (
    isset($_GET['create_server_backup']) ||
    isset($_GET['download_server_backup']) ||
    isset($_GET['delete_server_backup']) ||
    isset($_GET['create_release_prep_export']) ||
    isset($_GET['download_release_prep_export']) ||
    isset($_GET['delete_release_prep_export']) ||
    isset($_POST['restore_server_backup']) ||
    isset($_POST['upload_restore_backup']) ||
    isset($_POST['create_release_prep_export']) ||
    isset($_POST['delete_release_prep_export'])
) {
    require_once 'post/backup.php';
}

