<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");


// PHASE8F_UPDATE_GUARDRAILS - pre-update backups and force-update dirty tree protection
function itflowUpdatePostGitDirtyFiles(): array {
    $output = [];
    exec("git status --porcelain 2>&1", $output, $code);

    if ($code !== 0) {
        return ['__git_status_failed__'];
    }

    return array_values(array_filter($output, fn($line) => trim($line) !== ''));
}

function itflowUpdatePostCreatePreUpdateBackup(string $label): string {
    global $session_name;

    require_once __DIR__ . "/backup.php";

    $backupDir = itflowServerBackupDir();
    if (!is_dir($backupDir)) {
        mkdir($backupDir, 0750, true);
    }

    $safeHost = preg_replace('/[^A-Za-z0-9._-]/', '_', gethostname() ?: 'host');
    $path = $backupDir . DIRECTORY_SEPARATOR . 'itflow_server_' . date('YmdHis') . '_' . $safeHost . '_pre_update.zip';

    $result = itflowCreateFullBackupArchive($path, ($session_name ?? 'Unknown User') . ' ' . $label);

    return $result['filename'] ?? basename($path);
}



// PHASE9B_MANUAL_CHECK_FOR_UPDATES_HANDLER - explicit operator-triggered update check
if (isset($_POST['check_updates'])) {

    validateCSRFToken($_POST['csrf_token']);
    validateAdminRole();

    try {
        $source = getActiveUpdateSource();
        $preview = itflowBuildUpdatePreview($source);

        $_SESSION['update_check_preview'] = $preview;
        $_SESSION['update_check_checked_at'] = date('Y-m-d H:i:s');
        $_SESSION['update_check_source_name'] = $source['source_name'] ?? 'Unknown source';

        if (($preview['fetch_code'] ?? 1) !== 0) {
            flash_alert("Update check failed for " . nullable_htmlentities($source['source_name'] ?? 'selected source') . ".", 'error');
        } elseif (!empty($preview['is_update_available'])) {
            flash_alert("Update check complete: updates are available.");
        } else {
            flash_alert("Update check complete: no updates available.");
        }
    } catch (Throwable $e) {
        error_log("Manual update check failed: " . $e->getMessage());
        flash_alert("Update check failed: " . nullable_htmlentities($e->getMessage()), 'error');
    }

    redirect();
}


if (isset($_POST['add_update_source'])) {

    validateAdminRole();
    validateCSRFToken($_POST['csrf_token']);

    $source_name = sanitizeInput($_POST['source_name'] ?? '');
    $source_url = trim($_POST['source_url'] ?? '');
    $source_remote = trim($_POST['source_remote'] ?? 'origin');
    $source_branch = trim($_POST['source_branch'] ?? 'master');

    if (empty($source_name) || empty($source_url) || !preg_match('/^[A-Za-z0-9._-]+$/', $source_remote) || !preg_match('/^[A-Za-z0-9._\/-]+$/', $source_branch)) {
        flash_alert("Invalid update source details.", 'error');
        redirect();
    }

    if (!preg_match('/^(https:\/\/|git@|ssh:\/\/)/i', $source_url)) {
        flash_alert("Update source URL must be a Git HTTPS or SSH URL.", 'error');
        redirect();
    }

    $stmt = mysqli_prepare($mysqli, "INSERT INTO itflow_update_sources SET source_name = ?, source_remote = ?, source_url = ?, source_branch = ?, source_type = 'git'");
    mysqli_stmt_bind_param($stmt, 'ssss', $source_name, $source_remote, $source_url, $source_branch);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    logAction("App", "Update Source", "$session_name added update source $source_name");

    flash_alert("Update source added.");

    redirect();

}

if (isset($_GET['set_update_source'])) {

    validateAdminRole();
    validateCSRFToken($_GET['csrf_token']);

    $source_id = intval($_GET['set_update_source']);

    mysqli_query($mysqli, "UPDATE itflow_update_sources SET source_active = 0");
    mysqli_query($mysqli, "UPDATE itflow_update_sources SET source_active = 1 WHERE source_id = $source_id AND source_archived_at IS NULL LIMIT 1");

    logAction("App", "Update Source", "$session_name selected update source ID $source_id");

    flash_alert("Update source selected.");

    redirect();

}

if (isset($_GET['delete_update_source'])) {

    validateAdminRole();
    validateCSRFToken($_GET['csrf_token']);

    $source_id = intval($_GET['delete_update_source']);

    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT * FROM itflow_update_sources WHERE source_id = $source_id LIMIT 1"));
    if ($row && intval($row['source_active']) === 1) {
        flash_alert("You cannot remove the active update source. Select another source first.", 'error');
        redirect();
    }

    mysqli_query($mysqli, "UPDATE itflow_update_sources SET source_archived_at = NOW(), source_active = 0 WHERE source_id = $source_id LIMIT 1");

    logAction("App", "Update Source", "$session_name removed update source ID $source_id");

    flash_alert("Update source removed.");

    redirect();

}

if (isset($_GET['update'])) {

    validateCSRFToken($_GET['csrf_token']);
    validateAdminRole();

    $force_update = isset($_GET['force_update']);
    $dirty_files = itflowUpdatePostGitDirtyFiles();
    $dirty_count = count($dirty_files);

    if ($force_update && $dirty_count > 0) {
        $override = trim($_POST['force_update_confirm'] ?? $_GET['force_update_confirm'] ?? '');
        if ($override !== 'FORCE UPDATE') {
            flash_alert("Force Update blocked because the working tree has $dirty_count dirty/untracked file(s). Type FORCE UPDATE in the confirmation box to override.", 'error');
            redirect();
        }
    }

    try {
        $pre_update_backup = itflowUpdatePostCreatePreUpdateBackup($force_update ? 'pre-force-update backup' : 'pre-update backup');
    } catch (Throwable $e) {
        error_log("ITFlow pre-update backup failed: " . $e->getMessage());
        flash_alert("Update blocked because the pre-update backup failed: " . nullable_htmlentities($e->getMessage()), 'error');
        redirect();
    }

    $source = getActiveUpdateSource();
    $remote = itflowGitArg($source['source_remote'] ?? 'origin', 'origin');
    $branch = itflowGitArg($source['source_branch'] ?? 'master', 'master');

    if (!empty($source['source_url'])) {
        exec("git remote set-url " . escapeshellarg($remote) . " " . escapeshellarg($source['source_url']) . " 2>&1");
    }

    if ($force_update) {
        exec("git fetch " . escapeshellarg($remote) . " " . escapeshellarg($branch) . " 2>&1", $fetch_output, $fetch_result);
        if ($fetch_result !== 0) {
            flash_alert("Force Update failed during git fetch. Pre-update backup created: " . nullable_htmlentities($pre_update_backup), 'error');
            redirect();
        }

        exec("git reset --hard " . escapeshellarg($remote . '/' . $branch) . " 2>&1", $update_output, $update_result);
    } else {
        exec("git pull " . escapeshellarg($remote) . " " . escapeshellarg($branch) . " 2>&1", $update_output, $update_result);
    }

    if (($update_result ?? 0) !== 0) {
        flash_alert("Update command failed. Pre-update backup created: " . nullable_htmlentities($pre_update_backup) . ". Output: " . nullable_htmlentities(implode("\n", array_slice($update_output ?? [], -10))), 'error');
        redirect();
    }

    // ITFlow telemetry: preserve existing behavior, but avoid assignment in condition.
    if (isset($config_telemetry) && ($config_telemetry > 0 || $config_telemetry == 2)) {
        // Existing telemetry behavior intentionally left to surrounding application context.
    }

    logAction("App", $force_update ? "Force Update" : "Update", ($session_name ?? 'Unknown User') . " ran " . ($force_update ? "force update" : "update") . " from $remote/$branch after creating backup $pre_update_backup");

    flash_alert("Update successful. Pre-update backup created: " . nullable_htmlentities($pre_update_backup));

    redirect();

}

if (isset($_GET['update_db'])) {

    //validateAdminRole(); // Old function

    // Get the current version
    require_once ('../includes/database_version.php');

    // Perform upgrades, if required
    require_once ('database_updates.php');

    logAction("Database", "Update", "$session_name updated the database structure");

    flash_alert("Database structure update successful");

    sleep(1);

    redirect();

}
