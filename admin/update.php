<?php
require_once "includes/inc_all_admin.php";

require_once "../includes/database_version.php";

$updates = fetchUpdates();

$latest_version = $updates->latest_version;
$current_version = $updates->current_version;
$result = $updates->result;
$update_source = $updates->source ?? [];
$update_source_name = nullable_htmlentities($update_source['source_name'] ?? 'Unknown');
$update_source_remote = nullable_htmlentities($update_source['source_remote'] ?? 'origin');
$update_source_branch = nullable_htmlentities($update_source['source_branch'] ?? 'master');
$update_source_url = nullable_htmlentities($update_source['source_url'] ?? '');

$source_remote_raw = $updates->source_remote ?? 'origin';
$source_branch_raw = $updates->source_branch ?? 'master';
$git_log = shell_exec("git log " . escapeshellarg($source_remote_raw . '/' . $source_branch_raw) . "..HEAD --pretty=format:'' 2>/dev/null");
$incoming_git_log = shell_exec("git log HEAD.." . escapeshellarg($source_remote_raw . '/' . $source_branch_raw) . " --pretty=format:'<tr><td>%h</td><td>%ar</td><td>%s</td></tr>' 2>/dev/null");

$update_sources_sql = mysqli_query($mysqli, "SELECT * FROM itflow_update_sources WHERE source_archived_at IS NULL ORDER BY source_active DESC, source_name ASC, source_id ASC");

// PHASE9B_MANUAL_CHECK_FOR_UPDATES - use explicit operator-triggered update checks
$update_preview = $_SESSION['update_check_preview'] ?? null;
$update_check_checked_at = $_SESSION['update_check_checked_at'] ?? '';
$update_check_source_name = $_SESSION['update_check_source_name'] ?? '';

if (!is_array($update_preview)) {
    $update_preview = [
        'fetch_code' => null,
        'fetch_output' => [],
        'current' => '',
        'latest' => '',
        'target' => '',
        'is_update_available' => false,
        'commits' => [],
        'changed_files' => [],
        'dirty_files' => [],
        'risk' => [],
    ];
}

$preview_commits = $update_preview['commits'] ?? [];
$preview_changed_files = $update_preview['changed_files'] ?? [];
$preview_dirty_files = $update_preview['dirty_files'] ?? [];
$preview_risk = $update_preview['risk'] ?? [];
$preview_dirty_count = count($preview_dirty_files);
$force_update_confirm_required = $preview_dirty_count > 0;

// PHASE9C_UPDATE_RISK_SCOPE_UI - separate incoming update risk from local dirty-tree risk
$local_dirty_high_risk_patterns = [
    '#^admin/database_updates\.php$#',
    '#^admin/post/#',
    '#^admin/update\.php$#',
    '#^admin/settings_#',
    '#^admin/users\.php$#',
    '#^functions\.php$#',
    '#^includes/#',
    '#^setup/#',
    '#^scripts/setup_cli\.php$#',
    '#^scripts/update_cli\.php$#',
    '#^cron/#',
    '#^agent/post/#',
];

$local_dirty_high_risk_files = [];
$local_dirty_other_files = [];

// Normalize dirty-file entries because itflowBuildUpdatePreview() may return either
// strings like "M admin/update.php" or structured arrays depending on helper version.
foreach ($preview_dirty_files as $dirty_file) {
    $dirty_label = '';
    $dirty_path = '';

    if (is_array($dirty_file)) {
        $dirty_status = $dirty_file['status'] ?? $dirty_file['code'] ?? $dirty_file['state'] ?? '';
        $dirty_path = $dirty_file['path'] ?? $dirty_file['file'] ?? $dirty_file['filename'] ?? $dirty_file['name'] ?? '';

        if ($dirty_path === '') {
            foreach ($dirty_file as $dirty_value) {
                if (is_string($dirty_value) && $dirty_value !== '') {
                    $dirty_path = $dirty_value;
                    break;
                }
            }
        }

        $dirty_label = trim(($dirty_status !== '' ? $dirty_status . ' ' : '') . $dirty_path);

        if ($dirty_label === '') {
            $dirty_label = json_encode($dirty_file, JSON_UNESCAPED_SLASHES);
        }
    } else {
        $dirty_label = (string)$dirty_file;
        $dirty_path = $dirty_label;
    }

    $dirty_path = trim(preg_replace('/^[A-Z? ][A-Z? ]\s+/', '', $dirty_path));

    if (str_contains($dirty_path, ' -> ')) {
        $dirty_parts = explode(' -> ', $dirty_path);
        $dirty_path = trim(end($dirty_parts));
    }

    $is_high_risk_dirty = false;

    foreach ($local_dirty_high_risk_patterns as $risk_pattern) {
        if (preg_match($risk_pattern, $dirty_path)) {
            $is_high_risk_dirty = true;
            break;
        }
    }

    if ($is_high_risk_dirty) {
        $local_dirty_high_risk_files[] = $dirty_label;
    } else {
        $local_dirty_other_files[] = $dirty_label;
    }
}

$local_dirty_high_risk_count = count($local_dirty_high_risk_files);
$local_dirty_other_count = count($local_dirty_other_files);


// PHASE9A_GOLDEN_RELEASE_PREP_EXPORT_LIST
$release_prep_dir = '/var/backups/itflow/release-prep';
$release_prep_exports = [];

if (is_dir($release_prep_dir)) {
    foreach (glob($release_prep_dir . '/itflow_release_prep_*.zip') ?: [] as $release_prep_file) {
        $release_prep_exports[] = [
            'name' => basename($release_prep_file),
            'size' => filesize($release_prep_file),
            'mtime' => filemtime($release_prep_file),
            'sha256' => is_file($release_prep_file . '.sha256') ? trim(file_get_contents($release_prep_file . '.sha256')) : '',
        ];
    }

    usort($release_prep_exports, fn($a, $b) => $b['mtime'] <=> $a['mtime']);
}


$server_backup_dir = '/var/backups/itflow';
$server_backups = [];
if (is_dir($server_backup_dir)) {
    foreach (glob($server_backup_dir . '/itflow_server_*.zip') ?: [] as $backup_file) {
        if (!is_file($backup_file)) {
            continue;
        }
        $backup_name = basename($backup_file);
        $backup_type = 'Manual';
        if (str_contains($backup_name, '_pre_restore.zip')) {
            $backup_type = 'Pre-Restore';
        } elseif (str_contains($backup_name, '_uploaded.zip')) {
            $backup_type = 'Uploaded';
        }

        // PHASE8D2_BACKUP_TYPE_LABELS
        $server_backups[] = [
            'name' => $backup_name,
            'type' => $backup_type,
            'size' => filesize($backup_file),
            'mtime' => filemtime($backup_file),
            'sha256' => hash_file('sha256', $backup_file),
        ];
    }
    usort($server_backups, fn($a, $b) => $b['mtime'] <=> $a['mtime']);
}

?>

    <div class="card card-dark">
        <div class="card-header py-3">
            <h3 class="card-title"><i class="fas fa-fw fa-download mr-2"></i>Update</h3>
        </div>
        <div class="card-body">

            <div class="row">
                <div class="col-lg-7">
                    <h4>Current Update Source</h4>
                    <p class="mb-1"><strong><?php echo $update_source_name; ?></strong></p>
                    <p class="text-muted mb-1">
                        Remote: <code><?php echo $update_source_remote; ?></code>
                        &nbsp; Branch: <code><?php echo $update_source_branch; ?></code>
                    </p>
                    <p class="text-muted">URL: <code><?php echo $update_source_url; ?></code></p>
                </div>
                <div class="col-lg-5">
                    <form method="post" action="post.php" class="border rounded p-3 bg-light">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <h5>Add Update Source</h5>
                        <div class="form-group">
                            <label>Name</label>
                            <input type="text" class="form-control" name="source_name" placeholder="Official upstream" required>
                        </div>
                        <div class="form-group">
                            <label>Git URL</label>
                            <input type="text" class="form-control" name="source_url" placeholder="https://github.com/itflow-org/itflow.git" required>
                        </div>
                        <div class="form-row">
                            <div class="form-group col-md-6">
                                <label>Remote Alias</label>
                                <input type="text" class="form-control" name="source_remote" value="origin" required>
                            </div>
                            <div class="form-group col-md-6">
                                <label>Branch</label>
                                <input type="text" class="form-control" name="source_branch" value="master" required>
                            </div>
                        </div>
                        <button class="btn btn-primary" type="submit" name="add_update_source"><i class="fas fa-plus mr-2"></i>Add Source</button>
                    </form>
                </div>
            </div>

            <hr>

            <h4>Available Update Sources</h4>
            <div class="table-responsive">
                <table class="table table-sm table-striped">
                    <thead>
                    <tr>
                        <th>Active</th>
                        <th>Name</th>
                        <th>Remote</th>
                        <th>Branch</th>
                        <th>URL</th>
                        <th class="text-right">Actions</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php while ($source = mysqli_fetch_assoc($update_sources_sql)) { ?>
                        <tr>
                            <td><?php echo intval($source['source_active']) === 1 ? '<span class="badge badge-success">Active</span>' : ''; ?></td>
                            <td><?php echo nullable_htmlentities($source['source_name']); ?></td>
                            <td><code><?php echo nullable_htmlentities($source['source_remote']); ?></code></td>
                            <td><code><?php echo nullable_htmlentities($source['source_branch']); ?></code></td>
                            <td><code><?php echo nullable_htmlentities($source['source_url']); ?></code></td>
                            <td class="text-right">
                                <?php if (intval($source['source_active']) !== 1) { ?>
                                    <a class="btn btn-sm btn-outline-success confirm-link" href="post.php?set_update_source=<?php echo intval($source['source_id']); ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>">Use</a>
                                    <a class="btn btn-sm btn-outline-danger confirm-link" href="post.php?delete_update_source=<?php echo intval($source['source_id']); ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>">Remove</a>
                                <?php } else { ?>
                                    <span class="text-muted">Selected</span>
                                <?php } ?>
                            </td>
                        </tr>
                    <?php } ?>
                    </tbody>
                </table>
            </div>

            <hr>


            
            <!-- PHASE8E_UPDATE_PREVIEW_UI -->
            <div class="card card-outline card-info">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-fw fa-code-branch mr-2"></i>Generated Update Preview</h3>
                </div>
                <div class="card-body">

                    <!-- PHASE9B_MANUAL_CHECK_FOR_UPDATES_UI -->
                    <form method="post" action="post.php" class="mb-3">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <button type="submit" name="check_updates" class="btn btn-primary">
                            <i class="fas fa-fw fa-sync-alt mr-2"></i>Check for Updates
                        </button>
                        <?php if (!empty($update_check_checked_at)) { ?>
                            <span class="text-muted ml-2">
                                Last checked <?php echo nullable_htmlentities($update_check_checked_at); ?>
                                against <?php echo nullable_htmlentities($update_check_source_name); ?>.
                            </span>
                        <?php } else { ?>
                            <span class="text-muted ml-2">
                                No manual update check has been run in this session.
                            </span>
                        <?php } ?>
                    </form>


                    <?php if (empty($update_check_checked_at)) { ?>
                        <div class="alert alert-secondary">
                            Click <strong>Check for Updates</strong> to fetch the selected source and generate the update preview.
                        </div>
                    <?php } ?>

                    <p class="text-muted mb-2">
                        Comparing current code commit
                        <code><?php echo nullable_htmlentities(substr($update_preview['current'] ?? '', 0, 12)); ?></code>
                        to selected source
                        <code><?php echo nullable_htmlentities($update_preview['target'] ?? ''); ?></code>
                        at
                        <code><?php echo nullable_htmlentities(substr($update_preview['latest'] ?? '', 0, 12)); ?></code>.
                    </p>

                    <?php if (($update_preview['fetch_code'] ?? 1) !== 0) { ?>
                        <div class="alert alert-danger">
                            Git fetch failed for the selected update source. Preview may be incomplete.
                            <pre class="mb-0"><?php echo nullable_htmlentities(implode("\n", $update_preview['fetch_output'] ?? [])); ?></pre>
                        </div>
                    <?php } elseif (empty($update_preview['is_update_available'])) { ?>
                        <div class="alert alert-success mb-3">
                            No code update is currently available from the selected source.
                        </div>
                    <?php } else { ?>
                        <div class="alert alert-warning mb-3">
                            Update available: <?php echo count($preview_commits); ?> commit(s), <?php echo count($preview_changed_files); ?> changed file(s).
                        </div>
                    <?php } ?>

                    <?php if (!empty($preview_dirty_files)) { ?>
                        <div class="alert alert-danger">
                            <strong>Local working tree has uncommitted/untracked changes.</strong>
                            These may be overwritten by force update.
                            <ul class="mb-0">
                                <?php foreach (array_slice($preview_dirty_files, 0, 20) as $dirty) { ?>
                                    <li><code><?php echo nullable_htmlentities($dirty['status']); ?></code> <?php echo nullable_htmlentities($dirty['file']); ?></li>
                                <?php } ?>
                                <?php if (count($preview_dirty_files) > 20) { ?>
                                    <li>...and <?php echo count($preview_dirty_files) - 20; ?> more</li>
                                <?php } ?>
                            </ul>
                        </div>
                    <?php } ?>

                    <h5>Incoming Update Risk</h5>

                    <p class="text-muted small mb-2">
                        This section evaluates files coming from the selected update source only. Local server changes are evaluated separately below.
                    </p>
                    <div class="mb-3">
                        <?php if (!empty($preview_risk['database_updates'])) { ?><span class="badge badge-danger mr-1">Database migrations</span><?php } ?>
                        <?php if (!empty($preview_risk['config_related'])) { ?><span class="badge badge-warning mr-1">Config/setup/version files</span><?php } ?>
                        <?php if (!empty($preview_risk['composer_related'])) { ?><span class="badge badge-warning mr-1">Composer dependency files</span><?php } ?>
                        <?php if (!empty($preview_risk['admin_post_update'])) { ?><span class="badge badge-info mr-1">Update system changes</span><?php } ?>
                        <?php if (!empty($preview_risk['uploads_related'])) { ?><span class="badge badge-secondary mr-1">Uploads path changes</span><?php } ?>
                        <?php if (empty(array_filter($preview_risk))) { ?><span class="badge badge-success">No high-risk incoming update categories detected</span><?php } ?>
                    </div>

                    <div class="row">
                        <div class="col-lg-6">

                    <!-- PHASE9C_UPDATE_RISK_SCOPE_UI -->
                    <h5 class="mt-3">Local Working Tree Risk</h5>
                    <?php if ($preview_dirty_count > 0) { ?>
                        <?php if ($local_dirty_high_risk_count > 0) { ?>
                            <div class="alert alert-danger">
                                <strong>High-risk local files present.</strong>
                                These are local uncommitted/untracked changes on this server, not incoming update files.
                                A force update may overwrite them unless they are committed, exported, or backed up first.
                                <ul class="mb-0 mt-2">
                                    <?php foreach (array_slice($local_dirty_high_risk_files, 0, 20) as $dirty_file) { ?>
                                        <li><code><?php echo nullable_htmlentities($dirty_file); ?></code></li>
                                    <?php } ?>
                                    <?php if ($local_dirty_high_risk_count > 20) { ?>
                                        <li>...and <?php echo $local_dirty_high_risk_count - 20; ?> more high-risk local file(s)</li>
                                    <?php } ?>
                                </ul>
                            </div>
                        <?php } else { ?>
                            <span class="badge badge-warning">Local dirty-tree risk present, but no high-risk local categories detected</span>
                        <?php } ?>

                        <?php if ($local_dirty_other_count > 0) { ?>
                            <div class="text-muted small mt-2">
                                Other local dirty files: <?php echo $local_dirty_other_count; ?>.
                            </div>
                        <?php } ?>
                    <?php } else { ?>
                        <span class="badge badge-success">Local working tree clean</span>
                    <?php } ?>

                            <h5>Incoming Commits</h5>
                            <div class="table-responsive" style="max-height: 320px; overflow:auto;">
                                <table class="table table-sm table-striped">
                                    <thead>
                                    <tr>
                                        <th>Commit</th>
                                        <th>Date</th>
                                        <th>Author</th>
                                        <th>Subject</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    <?php if (!empty($preview_commits)) { ?>
                                        <?php foreach (array_slice($preview_commits, 0, 100) as $commit) { ?>
                                            <tr>
                                                <td><code><?php echo nullable_htmlentities($commit['hash']); ?></code></td>
                                                <td><?php echo nullable_htmlentities($commit['date']); ?></td>
                                                <td><?php echo nullable_htmlentities($commit['author']); ?></td>
                                                <td><?php echo nullable_htmlentities($commit['subject']); ?></td>
                                            </tr>
                                        <?php } ?>
                                    <?php } else { ?>
                                        <tr><td colspan="4" class="text-muted">No incoming commits.</td></tr>
                                    <?php } ?>
                                    </tbody>
                                </table>
                            </div>
                            <?php if (count($preview_commits) > 100) { ?>
                                <small class="text-muted">Showing first 100 of <?php echo count($preview_commits); ?> commits.</small>
                            <?php } ?>
                        </div>

                        <div class="col-lg-6">
                            <h5>Changed Files</h5>
                            <div class="table-responsive" style="max-height: 320px; overflow:auto;">
                                <table class="table table-sm table-striped">
                                    <thead>
                                    <tr>
                                        <th>Status</th>
                                        <th>File</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    <?php if (!empty($preview_changed_files)) { ?>
                                        <?php foreach (array_slice($preview_changed_files, 0, 150) as $changed) { ?>
                                            <tr>
                                                <td><code><?php echo nullable_htmlentities($changed['status']); ?></code></td>
                                                <td><code><?php echo nullable_htmlentities($changed['file']); ?></code></td>
                                            </tr>
                                        <?php } ?>
                                    <?php } else { ?>
                                        <tr><td colspan="2" class="text-muted">No changed files.</td></tr>
                                    <?php } ?>
                                    </tbody>
                                </table>
                            </div>
                            <?php if (count($preview_changed_files) > 150) { ?>
                                <small class="text-muted">Showing first 150 of <?php echo count($preview_changed_files); ?> changed files.</small>
                            <?php } ?>
                        </div>
                    </div>
                </div>
            </div>


            <!-- PHASE9A_GOLDEN_RELEASE_PREP_UI -->
            <div class="card card-outline card-info">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-fw fa-file-archive mr-2"></i>Golden Server Release Prep</h3>
                </div>
                <div class="card-body">
                    <p class="text-muted">
                        Generate a downloadable handoff ZIP containing the current server-vs-repo status, tracked diff patch,
                        copied changed files, lint summary, residue scan, exclusions, and a ChatGPT handoff context file.
                        Secrets and runtime paths such as <code>config.php</code>, uploads, backups, logs, SQL dumps, vendor,
                        node_modules, cache, and temp files are excluded.
                    </p>

                    <form method="post" action="post.php" class="mb-3">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <button type="submit" name="create_release_prep_export" class="btn btn-info confirm-link">
                            <i class="fas fa-fw fa-box-open mr-2"></i>Generate Golden Release Prep Export
                        </button>
                    </form>

                    <?php if (!empty($release_prep_exports)) { ?>
                        <div class="table-responsive">
                            <table class="table table-sm table-striped">
                                <thead>
                                <tr>
                                    <th>Export</th>
                                    <th>Created</th>
                                    <th>Size</th>
                                    <th>SHA256</th>
                                    <th class="text-right">Actions</th>
                                </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($release_prep_exports as $export) { ?>
                                    <tr>
                                        <td><code><?php echo nullable_htmlentities($export['name']); ?></code></td>
                                        <td><?php echo date('Y-m-d H:i:s', $export['mtime']); ?></td>
                                        <td><?php echo round($export['size'] / 1024 / 1024, 2); ?> MB</td>
                                        <td><small><code><?php echo nullable_htmlentities($export['sha256']); ?></code></small></td>
                                        <td class="text-right">
                                            <a class="btn btn-sm btn-primary"
                                               href="post.php?download_release_prep_export=<?php echo urlencode($export['name']); ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>">
                                                <i class="fas fa-fw fa-download"></i>
                                            </a>
                                            <form method="post" action="post.php" class="d-inline">
                                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                <input type="hidden" name="delete_release_prep_export" value="<?php echo nullable_htmlentities($export['name']); ?>">
                                                <button type="submit" class="btn btn-sm btn-danger confirm-link">
                                                    <i class="fas fa-fw fa-trash"></i>
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php } ?>
                                </tbody>
                            </table>
                        </div>
                    <?php } else { ?>
                        <div class="text-muted">No release prep exports have been generated yet.</div>
                    <?php } ?>
                </div>
            </div>

<!-- PHASE8C_SERVER_BACKUP_UI -->
            <div class="card card-outline card-secondary">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-fw fa-database mr-2"></i>Update Safety Backups</h3>
                </div>
                <div class="card-body">
                    <p class="text-muted">
                        Create a full ITFlow backup before updating. Server-side backups are stored outside the web root in
                        <code><?php echo nullable_htmlentities($server_backup_dir); ?></code>.
                    </p>

                    <a class="btn btn-primary confirm-link mb-3" href="post.php?create_server_backup&csrf_token=<?php echo $_SESSION['csrf_token']; ?>">
                        <i class="fas fa-save mr-2"></i>Create Server Backup Now
                    </a>
                    <a class="btn btn-outline-secondary mb-3" href="post.php?download_backup&csrf_token=<?php echo $_SESSION['csrf_token']; ?>">
                        <i class="fas fa-download mr-2"></i>Create & Download Backup
                    </a>

                    <div class="table-responsive">
                        <table class="table table-sm table-striped">
                            <thead>
                            <tr>
                                <th>Backup</th>
                                <th>Type</th>
                                <th>Created</th>
                                <th>Size</th>
                                <th>SHA256</th>
                                <th class="text-right">Actions</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php if (!empty($server_backups)) { ?>
                                <?php foreach ($server_backups as $backup) { ?>
                                    <tr>
                                        <td><code><?php echo nullable_htmlentities($backup['name']); ?></code></td>
                                        <td><span class="badge badge-secondary"><?php echo nullable_htmlentities($backup['type'] ?? 'Manual'); ?></span></td>
                                        <td><?php echo date('Y-m-d H:i:s', $backup['mtime']); ?></td>
                                        <td><?php echo number_format($backup['size'] / 1048576, 2); ?> MB</td>
                                        <td><small><code><?php echo nullable_htmlentities(substr($backup['sha256'], 0, 16)); ?>...</code></small></td>
                                        <td class="text-right">
                                            <a class="btn btn-sm btn-outline-primary" href="post.php?download_server_backup=<?php echo urlencode($backup['name']); ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>">
                                                Download
                                            </a>
                                            <button type="button" class="btn btn-sm btn-outline-warning" data-toggle="collapse" data-target="#restoreBackup<?php echo md5($backup['name']); ?>">
                                                Restore
                                            </button>
                                            <a class="btn btn-sm btn-outline-danger confirm-link" href="post.php?delete_server_backup=<?php echo urlencode($backup['name']); ?>&csrf_token=<?php echo $_SESSION['csrf_token']; ?>">
                                                Delete
                                            </a>
                                        </td>
                                    </tr>
                                    <tr class="collapse" id="restoreBackup<?php echo md5($backup['name']); ?>">
                                        <td colspan="6">
                                            <form method="post" action="post.php" class="border rounded p-3 bg-warning">
                                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                <input type="hidden" name="restore_backup_name" value="<?php echo nullable_htmlentities($backup['name']); ?>">
                                                <h5 class="font-weight-bold"><i class="fas fa-exclamation-triangle mr-2"></i>Restore Backup</h5>
                                                <p>
                                                    This will replace the current database and uploads with the selected backup.
                                                    A pre-restore safety backup will be created automatically first.
                                                </p>
                                                <label>Type <code>RESTORE</code> to confirm</label>
                                                <div class="input-group">
                                                    <input type="text" class="form-control" name="restore_confirm" autocomplete="off" required>
                                                    <div class="input-group-append">
                                                        <button type="submit" class="btn btn-danger" name="restore_server_backup">
                                                            Restore This Backup
                                                        </button>
                                                    </div>
                                                </div>
                                            </form>
                                        </td>
                                    </tr>
                                <?php } ?>
                            <?php } else { ?>
                                <tr>
                                    <td colspan="6" class="text-muted">No server-side backups found.</td>
                                </tr>
                            <?php } ?>
                            </tbody>
                        </table>
                    </div>

                    <small class="text-muted">
                        Restores require typed confirmation and automatically create a pre-restore safety backup.
                    </small>

                    <!-- PHASE8D_RESTORE_UI -->
                    <hr>
                    <form method="post" action="post.php" enctype="multipart/form-data" class="border rounded p-3">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <h5><i class="fas fa-upload mr-2"></i>Upload Backup for Restore</h5>
                        <p class="text-muted">
                            Upload an ITFlow backup ZIP. The file will be validated and added to the server-side backup list before it can be restored.
                        </p>
                        <div class="input-group">
                            <div class="custom-file">
                                <input type="file" class="custom-file-input" id="backupFileUpload" name="backup_file" accept=".zip" required>
                                <label class="custom-file-label" for="backupFileUpload">Choose backup ZIP</label>
                            </div>
                            <div class="input-group-append">
                                <button class="btn btn-outline-primary" type="submit" name="upload_server_backup">
                                    Upload & Validate
                                </button>
                            </div>
                        </div>
                    </form>

                </div>
            </div>

            <hr>


                        <!-- PHASE8F_UPDATE_GUARDRAILS_UI -->
                        <div class="alert alert-info text-left">
                            <strong>Update guardrails are active.</strong>
                            A server-side pre-update backup will be created before Update App or Force Update runs.
                            Current dirty/untracked file count: <strong><?php echo intval($preview_dirty_count); ?></strong>.
                        </div>

                        <?php if ($force_update_confirm_required) { ?>
                            <div class="alert alert-warning text-left">
                                Force Update is protected because local dirty/untracked files exist.
                                Use the guarded Force Update form below and type <code>FORCE UPDATE</code> exactly if you intentionally want to overwrite local changes.
                            </div>
                        <?php } ?>

                        <form method="post" action="post.php?update=true&force_update=true&csrf_token=<?php echo $_SESSION['csrf_token']; ?>" class="border rounded p-3 bg-light text-left mb-3">
                            <label class="mb-1">
                                Guarded Force Update confirmation
                            </label>
                            <input type="text" class="form-control form-control-sm mb-2" name="force_update_confirm" autocomplete="off" placeholder="FORCE UPDATE" <?php if ($force_update_confirm_required) { echo 'required'; } ?>>
                            <button type="submit" class="btn btn-danger confirm-link">
                                <i class="fas fa-fw fa-exclamation-triangle mr-2"></i>Guarded FORCE Update App
                            </button>
                        </form>

            <div class="text-center">

            <?php if ($result !== 0) { ?>
                <div class="alert alert-danger text-left">
                    <strong>WARNING: Could not execute git fetch for the selected update source.</strong>
                    <br><br>
                    <i>Error details:- <?php echo nullable_htmlentities(implode("\n", $updates->output ?? [])); ?></i>
                    <br><br>
                    Things to check: Is Git installed? Is the selected update source URL correct? Are web server file permissions too strict?
                </div>
            <?php } ?>

            <?php if (version_compare(LATEST_DATABASE_VERSION, CURRENT_DATABASE_VERSION, '>')) { ?>
                <div class="alert alert-danger">
                    <h1 class="font-weight-bold text-center">⚠️ DANGER ⚠️</h1>
                    <h2 class="font-weight-bold text-center">Do NOT run updates without first taking a backup</h2>
                    <p>VM Snapshots are highly recommended over other methods - see the <a href="https://docs.itflow.org/backups" class="alert-link" target="_blank">docs</a>. Review the selected source changelog for breaking changes that may require manual remediation.</p>
                    <p class="text-center font-weight-bold">Ignore this warning at your own risk.</p>
                </div>
                <br>
                <a class="btn btn-dark btn-lg my-4" href="post.php?update_db"><i class="fas fa-fw fa-4x fa-download mb-1"></i><h5>Update Database</h5></a>
                <br>
                <small class="text-secondary">Current DB Version: <?php echo CURRENT_DATABASE_VERSION; ?></small>
                <br>
                <small class="text-secondary">Latest DB Version: <?php echo LATEST_DATABASE_VERSION; ?></small>
                <br>
                <hr>

            <?php } else {
                if (!empty($incoming_git_log)) { ?>
                    <div class="alert alert-danger">
                        <h1 class="font-weight-bold text-center">⚠️ DANGER ⚠️</h1>
                        <h2 class="font-weight-bold text-center">Do NOT run updates without first taking a backup</h2>
                        <p>VM Snapshots are highly recommended over other methods. The update will use <strong><?php echo $update_source_name; ?></strong> / <code><?php echo $update_source_branch; ?></code>.</p>
                        <p class="text-center font-weight-bold">Ignore this warning at your own risk.</p>
                    </div>

                    <a class="btn btn-primary btn-lg my-4 confirm-link" href="post.php?update"><i class="fas fa-fw fa-4x fa-download mb-1"></i><h5>Update App</h5></a>

                <?php } else { ?>
                    <p><strong>Application Release Version:<br><strong class="text-dark"><?php echo APP_VERSION; ?></strong></p>
                    <p class="text-secondary">Database Version:<br><strong class="text-dark"><?php echo CURRENT_DATABASE_VERSION; ?></strong></p>
                    <p class="text-secondary">Code Commit:<br><strong class="text-dark"><?php echo nullable_htmlentities($current_version); ?></strong></p>
                    <p class="text-muted">You are up to date with the selected update source.<br>Everything is going to be alright</p>
                    <i class="far fa-3x text-dark fa-smile-wink"></i><br>

                    <?php if (rand(1,10) == 1) { ?>
                        <br>
                        <div class="alert alert-info alert-dismissible fade show" role="alert">
                            You're up to date, but when was the last time you checked your ITFlow backup works?
                            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                        </div>
                    <?php } ?>

                <?php }
            }

            if (!empty($incoming_git_log)) { ?>
                <table class="table">
                    <thead>
                    <tr>
                        <th>Commit</th>
                        <th>When</th>
                        <th>Description</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php echo $incoming_git_log; ?>
                    </tbody>
                </table>
                <?php
            }

            ?>

            </div>

        </div>
    </div>

<?php

require_once "../includes/footer.php";
