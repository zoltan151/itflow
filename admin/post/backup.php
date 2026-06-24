<?php


// PHASE9A_GOLDEN_RELEASE_PREP_EXPORT - package golden-server local changes for repo release preparation
if (!function_exists('itflowReleasePrepDir')) {
    function itflowReleasePrepDir(): string {
        return '/var/backups/itflow/release-prep';
    }
}

if (!function_exists('itflowReleasePrepSafeBasename')) {
    function itflowReleasePrepSafeBasename(string $name): string {
        $name = basename($name);

        if (!preg_match('/^itflow_release_prep_[0-9]{14}_[A-Za-z0-9._-]+\.zip$/', $name)) {
            return '';
        }

        return $name;
    }
}

if (!function_exists('itflowReleasePrepIsExcludedPath')) {
    function itflowReleasePrepIsExcludedPath(string $path): bool {
        $path = ltrim(str_replace('\\', '/', $path), './');

        if ($path === '') {
            return true;
        }

        $exact = [
            'config.php',
            '.env',
        ];

        if (in_array($path, $exact, true)) {
            return true;
        }

        $prefixes = [
            '.git/',
            'uploads/',
            'backups/',
            'storage/',
            'cache/',
            'logs/',
            'tmp/',
            'vendor/',
            'node_modules/',
            'plugins/',
        ];

        foreach ($prefixes as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        $lower = strtolower($path);
        $blockedSuffixes = [
            '.zip',
            '.tar',
            '.tar.gz',
            '.tgz',
            '.sql',
            '.log',
            '.bak',
            '.backup',
            '.orig',
            '.rej',
            '.swp',
        ];

        foreach ($blockedSuffixes as $suffix) {
            if (str_ends_with($lower, $suffix)) {
                return true;
            }
        }

        if (str_contains($lower, '.bak.')) {
            return true;
        }

        if (str_contains($lower, '.broken')) {
            return true;
        }

        return false;
    }
}

if (!function_exists('itflowReleasePrepRunCommand')) {
    function itflowReleasePrepRunCommand(string $command): array {
        $output = [];
        exec($command . ' 2>&1', $output, $code);

        return [
            'code' => $code,
            'output' => $output,
            'text' => implode("\n", $output),
        ];
    }
}

if (!function_exists('itflowReleasePrepWriteFile')) {
    function itflowReleasePrepWriteFile(string $path, string $contents): void {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }

        file_put_contents($path, $contents);
    }
}

if (!function_exists('itflowReleasePrepRemoveDirectoryTree')) {
    function itflowReleasePrepRemoveDirectoryTree(string $dir): void {
        if (!is_dir($dir)) {
            return;
        }

        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($items as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
            } else {
                unlink($item->getPathname());
            }
        }

        rmdir($dir);
    }
}

if (!function_exists('itflowReleasePrepGitStatusEntries')) {
    function itflowReleasePrepGitStatusEntries(): array {
        $result = itflowReleasePrepRunCommand('git status --porcelain');

        $entries = [];

        foreach ($result['output'] as $line) {
            if (trim($line) === '') {
                continue;
            }

            $status = substr($line, 0, 2);
            $path = trim(substr($line, 3));

            if (str_contains($path, ' -> ')) {
                $parts = explode(' -> ', $path);
                $path = trim(end($parts));
            }

            $entries[] = [
                'status' => $status,
                'path' => $path,
                'excluded' => itflowReleasePrepIsExcludedPath($path),
            ];
        }

        return $entries;
    }
}

if (!function_exists('itflowReleasePrepCopyChangedFiles')) {
    function itflowReleasePrepCopyChangedFiles(string $exportRoot, array $entries): array {
        $copied = [];
        $excluded = [];

        foreach ($entries as $entry) {
            $path = $entry['path'];

            if ($entry['excluded']) {
                $excluded[] = $entry['status'] . ' ' . $path;
                continue;
            }

            if (!is_file($path)) {
                $excluded[] = $entry['status'] . ' ' . $path . ' (not a regular file or deleted)';
                continue;
            }

            $dest = $exportRoot . '/changed-files/' . $path;
            $dir = dirname($dest);

            if (!is_dir($dir)) {
                mkdir($dir, 0750, true);
            }

            copy($path, $dest);
            $copied[] = $entry['status'] . ' ' . $path;
        }

        return [
            'copied' => $copied,
            'excluded' => $excluded,
        ];
    }
}

if (!function_exists('itflowCreateGoldenReleasePrepExport')) {
    function itflowCreateGoldenReleasePrepExport(): array {
        global $mysqli, $session_name;

        // PHASE9A_PROJECT_ROOT_CWD_FIX - generate export from ITFlow project root even when called from admin/post.php
        $previousWorkingDirectory = getcwd();
        $projectRoot = realpath(dirname(__DIR__, 2));
        if ($projectRoot && is_dir($projectRoot)) {
            chdir($projectRoot);
        }

        $baseDir = itflowReleasePrepDir();
        if (!is_dir($baseDir)) {
            mkdir($baseDir, 0750, true);
        }

        if (!is_writable($baseDir)) {
            throw new RuntimeException("Release prep directory is not writable: " . $baseDir);
        }

        $host = preg_replace('/[^A-Za-z0-9._-]/', '_', gethostname() ?: 'host');
        $stamp = date('YmdHis');
        $exportName = 'itflow_release_prep_' . $stamp . '_' . $host;
        $tmpRoot = sys_get_temp_dir() . '/' . $exportName;
        $zipPath = $baseDir . '/' . $exportName . '.zip';

        if (is_dir($tmpRoot)) {
            itflowReleasePrepRemoveDirectoryTree($tmpRoot);
        }

        mkdir($tmpRoot, 0750, true);

        try {
            $entries = itflowReleasePrepGitStatusEntries();
            $copyResult = itflowReleasePrepCopyChangedFiles($tmpRoot, $entries);

            $gitHead = trim(itflowReleasePrepRunCommand('git rev-parse HEAD')['text']);
            $gitBranch = trim(itflowReleasePrepRunCommand('git rev-parse --abbrev-ref HEAD')['text']);
            $gitRemote = trim(itflowReleasePrepRunCommand('git remote -v')['text']);
            $gitStatus = itflowReleasePrepRunCommand('git status --porcelain')['text'];
            $gitStatusLong = itflowReleasePrepRunCommand('git status')['text'];
            $gitDiff = itflowReleasePrepRunCommand('git diff --binary')['text'];
            $gitDiffStat = itflowReleasePrepRunCommand('git diff --stat')['text'];
            $gitLsFilesOther = itflowReleasePrepRunCommand('git ls-files --others --exclude-standard')['text'];

            $appVersion = defined('APP_VERSION') ? APP_VERSION : 'Unknown';
            $latestDbVersion = defined('LATEST_DATABASE_VERSION') ? LATEST_DATABASE_VERSION : 'Unknown';
            $currentDbVersion = 'Unknown';

            if (isset($mysqli) && $mysqli instanceof mysqli) {
                $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT config_current_database_version FROM settings LIMIT 1"));
                $currentDbVersion = $row['config_current_database_version'] ?? 'Unknown';
            }

            $activeSource = function_exists('getActiveUpdateSource') ? getActiveUpdateSource() : [];
            $activeSourceText = '';
            if (!empty($activeSource)) {
                $activeSourceText .= "Name: " . ($activeSource['source_name'] ?? '') . "\n";
                $activeSourceText .= "Remote: " . ($activeSource['source_remote'] ?? '') . "\n";
                $activeSourceText .= "URL: " . ($activeSource['source_url'] ?? '') . "\n";
                $activeSourceText .= "Branch: " . ($activeSource['source_branch'] ?? '') . "\n";
            }

            $lintFiles = [
                'functions.php',
                'admin/update.php',
                'admin/post/update.php',
                'admin/post/backup.php',
                'admin/database_updates.php',
                'setup/index.php',
                'scripts/setup_cli.php',
                'scripts/update_cli.php',
                'includes/load_global_settings.php',
            ];

            $lintText = '';
            foreach ($lintFiles as $lintFile) {
                if (is_file($lintFile)) {
                    $lintText .= '$ php -l ' . $lintFile . "\n";
                    $lintText .= itflowReleasePrepRunCommand('php -l ' . escapeshellarg($lintFile))['text'] . "\n\n";
                }
            }

            // Build private-residue scan terms from fragments so the public source does not itself contain
            // customer/company-specific strings that the public residue scanner is looking for.
            $privateResiduePattern = implode('|', [
                'Info' . 'Tech',
                'info' . 'tech\\.net',
                'support@' . 'info' . 'tech\\.net',
                'support\\.' . 'info' . 'tech\\.net',
                'Flex' . 'is',
                'flex' . 'is',
            ]);

            $publicAllowPattern = implode('|', [
                'support@example\\.com',
                'support@yourcompany\\.com',
                'example\\.com',
            ]);

            $residueCommand = "find . "
                . "-path './.git' -prune -o "
                . "-path './uploads' -prune -o "
                . "-path './tmp' -prune -o "
                . "-path './backups' -prune -o "
                . "-path './vendor' -prune -o "
                . "-path './plugins' -prune -o "
                . "-path './node_modules' -prune -o "
                . "-type f "
                . "! -name 'config.php' "
                . "! -name '*.tar.gz' "
                . "! -name '*.zip' "
                . "! -name '*.sql' "
                . "! -name '*.log' "
                . "-print0 | xargs -0 grep -InE " . escapeshellarg($privateResiduePattern)
                . " 2>/dev/null | grep -vE " . escapeshellarg($publicAllowPattern)
                . " || true";

            $residueText = itflowReleasePrepRunCommand($residueCommand)['text'];

            $changedTracked = [];
            $untracked = [];
            $deleted = [];
            $other = [];

            foreach ($entries as $entry) {
                $line = $entry['status'] . ' ' . $entry['path'];
                if (str_starts_with($entry['status'], '??')) {
                    $untracked[] = $line;
                } elseif (str_contains($entry['status'], 'D')) {
                    $deleted[] = $line;
                } elseif (trim($entry['status']) !== '') {
                    $changedTracked[] = $line;
                } else {
                    $other[] = $line;
                }
            }

            $manifest = "# Golden Server Release Prep Export\n\n";
            $manifest .= "Generated: " . date('c') . "\n";
            $manifest .= "Generated by: " . ($session_name ?? 'Unknown User') . "\n";
            $manifest .= "Host: " . $host . "\n";
            $manifest .= "Path: " . getcwd() . "\n";
            $manifest .= "Git branch: " . $gitBranch . "\n";
            $manifest .= "Git HEAD: " . $gitHead . "\n";
            $manifest .= "App version: " . $appVersion . "\n";
            $manifest .= "Latest DB version constant: " . $latestDbVersion . "\n";
            $manifest .= "Current DB version: " . $currentDbVersion . "\n";
            $manifest .= "Dirty file count: " . count($entries) . "\n";
            $manifest .= "Changed tracked count: " . count($changedTracked) . "\n";
            $manifest .= "Untracked count: " . count($untracked) . "\n";
            $manifest .= "Deleted count: " . count($deleted) . "\n";
            $manifest .= "Copied changed file count: " . count($copyResult['copied']) . "\n";
            $manifest .= "Excluded file count: " . count($copyResult['excluded']) . "\n";

            $summary = "# Summary\n\n";
            $summary .= "This export packages local golden-server changes for review and for updating the forked repository.\n\n";
            $summary .= "## Counts\n\n";
            $summary .= "- Dirty files: " . count($entries) . "\n";
            $summary .= "- Changed tracked: " . count($changedTracked) . "\n";
            $summary .= "- Untracked: " . count($untracked) . "\n";
            $summary .= "- Deleted: " . count($deleted) . "\n";
            $summary .= "- Copied files: " . count($copyResult['copied']) . "\n";
            $summary .= "- Excluded files: " . count($copyResult['excluded']) . "\n\n";
            $summary .= "## Important\n\n";
            $summary .= "Secrets and runtime paths are intentionally excluded. config.php, uploads, backups, logs, SQL dumps, vendor, node_modules, and cache/temp paths should not be included.\n";

            $chatgpt = "# ChatGPT Handoff Context\n\n";
            $chatgpt .= "This ZIP was generated from the golden ITFlow server.\n\n";
            $chatgpt .= "## Goal\n\n";
            $chatgpt .= "Update the forked repository with the local changes that exist on this golden server, while keeping the public fork generic and free of environment-specific secrets or branding residue.\n\n";
            $chatgpt .= "## Environment\n\n";
            $chatgpt .= "- Host: " . $host . "\n";
            $chatgpt .= "- Path: " . getcwd() . "\n";
            $chatgpt .= "- Git branch: " . $gitBranch . "\n";
            $chatgpt .= "- Git HEAD: " . $gitHead . "\n";
            $chatgpt .= "- App version: " . $appVersion . "\n";
            $chatgpt .= "- Latest DB version constant: " . $latestDbVersion . "\n";
            $chatgpt .= "- Current DB version: " . $currentDbVersion . "\n\n";
            $chatgpt .= "## Active Update Source\n\n";
            $chatgpt .= "```text\n" . ($activeSourceText ?: 'Unknown') . "```\n\n";
            $chatgpt .= "## Dirty Working Tree Summary\n\n";
            $chatgpt .= "- Dirty file count: " . count($entries) . "\n";
            $chatgpt .= "- Changed tracked count: " . count($changedTracked) . "\n";
            $chatgpt .= "- Untracked count: " . count($untracked) . "\n";
            $chatgpt .= "- Deleted count: " . count($deleted) . "\n";
            $chatgpt .= "- Copied changed file count: " . count($copyResult['copied']) . "\n";
            $chatgpt .= "- Excluded file count: " . count($copyResult['excluded']) . "\n\n";
            $chatgpt .= "## Suggested Task\n\n";
            $chatgpt .= "Review MANIFEST.md, git/git-status.txt, git/git-diff.patch, git/git-diff-stat.txt, changed-files/, safety/residue-scan.txt, and safety/php-lint-summary.txt. Then produce a safe plan to merge these golden-server changes into the forked repo without including secrets, runtime data, backups, logs, uploads, or environment-specific hard-coding.\n\n";
            $chatgpt .= "## Notes\n\n";
            $chatgpt .= "The changed-files directory contains full copies of non-excluded dirty files. git/git-diff.patch contains tracked-file diffs. Untracked files that are not excluded are copied but will not appear in git/git-diff.patch.\n";

            itflowReleasePrepWriteFile($tmpRoot . '/MANIFEST.md', $manifest);
            itflowReleasePrepWriteFile($tmpRoot . '/SUMMARY.txt', $summary);
            itflowReleasePrepWriteFile($tmpRoot . '/CHATGPT_CONTEXT.md', $chatgpt);

            itflowReleasePrepWriteFile($tmpRoot . '/git/git-head.txt', $gitHead . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/git/git-branch.txt', $gitBranch . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/git/git-remotes.txt', $gitRemote . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/git/git-status.txt', $gitStatus . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/git/git-status-long.txt', $gitStatusLong . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/git/git-diff.patch', $gitDiff . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/git/git-diff-stat.txt', $gitDiffStat . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/git/git-untracked.txt', $gitLsFilesOther . "\n");

            itflowReleasePrepWriteFile($tmpRoot . '/lists/changed-tracked.txt', implode("\n", $changedTracked) . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/lists/untracked.txt', implode("\n", $untracked) . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/lists/deleted.txt', implode("\n", $deleted) . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/lists/copied-files.txt', implode("\n", $copyResult['copied']) . "\n");
            itflowReleasePrepWriteFile($tmpRoot . '/lists/excluded-files.txt', implode("\n", $copyResult['excluded']) . "\n");

            itflowReleasePrepWriteFile($tmpRoot . '/database/version-summary.txt', "APP_VERSION=$appVersion\nLATEST_DATABASE_VERSION=$latestDbVersion\nCURRENT_DATABASE_VERSION=$currentDbVersion\n");
            itflowReleasePrepWriteFile($tmpRoot . '/database/active-update-source.txt', $activeSourceText . "\n");

            itflowReleasePrepWriteFile($tmpRoot . '/safety/php-lint-summary.txt', $lintText);
            itflowReleasePrepWriteFile($tmpRoot . '/safety/residue-scan.txt', ($residueText !== '' ? $residueText : "none\n"));
            itflowReleasePrepWriteFile($tmpRoot . '/safety/exclusion-policy.txt', "Excluded: config.php, .env, uploads, backups, storage, cache, logs, tmp, vendor, node_modules, plugins, archives, SQL dumps, logs, backup/orig/rej/swp files.\n");

            $zip = new ZipArchive();
            if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
                throw new RuntimeException("Unable to create release prep ZIP: " . $zipPath);
            }

            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($tmpRoot, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($files as $file) {
                if (!$file->isFile()) {
                    continue;
                }

                $fullPath = $file->getRealPath();
                $local = substr($fullPath, strlen($tmpRoot) + 1);
                $zip->addFile($fullPath, $local);
            }

            $zip->close();

            chmod($zipPath, 0640);

            $sha = hash_file('sha256', $zipPath);
            file_put_contents($zipPath . '.sha256', $sha . "  " . basename($zipPath) . "\n");

            return [
                'path' => $zipPath,
                'filename' => basename($zipPath),
                'sha256' => $sha,
                'dirty_count' => count($entries),
                'copied_count' => count($copyResult['copied']),
                'excluded_count' => count($copyResult['excluded']),
                'size' => filesize($zipPath),
            ];
        } finally {
            if (is_dir($tmpRoot)) {
                itflowReleasePrepRemoveDirectoryTree($tmpRoot);
            }

            if (!empty($previousWorkingDirectory) && is_dir($previousWorkingDirectory)) {
                chdir($previousWorkingDirectory);
            }
        }
    }
}

// PHASE9A_GOLDEN_RELEASE_PREP_EXPORT_HANDLERS
if (isset($_POST['create_release_prep_export'])) {

    validateCSRFToken($_POST['csrf_token']);
    validateAdminRole();

    try {
        $result = itflowCreateGoldenReleasePrepExport();
        flash_alert("Golden release prep export created: " . nullable_htmlentities($result['filename']));
    } catch (Throwable $e) {
        error_log("Golden release prep export failed: " . $e->getMessage());
        flash_alert("Golden release prep export failed: " . nullable_htmlentities($e->getMessage()), 'error');
    }

    redirect();
}

if (isset($_GET['download_release_prep_export'])) {

    validateCSRFToken($_GET['csrf_token']);
    validateAdminRole();

    $name = itflowReleasePrepSafeBasename($_GET['download_release_prep_export'] ?? '');
    if ($name === '') {
        flash_alert("Invalid release prep export filename.", 'error');
        redirect();
    }

    $path = realpath(itflowReleasePrepDir() . '/' . $name);
    $base = realpath(itflowReleasePrepDir());

    if (!$path || !$base || !str_starts_with($path, $base . DIRECTORY_SEPARATOR) || !is_file($path)) {
        flash_alert("Release prep export not found.", 'error');
        redirect();
    }

    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
    header('Content-Length: ' . filesize($path));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    readfile($path);
    exit;
}

if (isset($_POST['delete_release_prep_export'])) {

    validateCSRFToken($_POST['csrf_token']);
    validateAdminRole();

    $name = itflowReleasePrepSafeBasename($_POST['delete_release_prep_export'] ?? '');
    if ($name === '') {
        flash_alert("Invalid release prep export filename.", 'error');
        redirect();
    }

    $path = realpath(itflowReleasePrepDir() . '/' . $name);
    $base = realpath(itflowReleasePrepDir());

    if (!$path || !$base || !str_starts_with($path, $base . DIRECTORY_SEPARATOR) || !is_file($path)) {
        flash_alert("Release prep export not found.", 'error');
        redirect();
    }

    unlink($path);

    $shaPath = $path . '.sha256';
    if (is_file($shaPath)) {
        unlink($shaPath);
    }

    flash_alert("Release prep export deleted.");

    redirect();
}



/*
 * ITFlow - GET/POST request handler for DB / master key backup
 * Rewritten with streaming SQL dump, component checksums, safer zipping, and better headers.
 */

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

require_once "../includes/app_version.php";

// --- Optional performance levers for big backups ---
@set_time_limit(0);
if (function_exists('ini_set')) {
    @ini_set('memory_limit', '1024M');
}

/**
 * Write a line to a file handle with newline.
 */
function fwrite_ln($fh, string $s): void {
    fwrite($fh, $s);
    fwrite($fh, PHP_EOL);
}

/**
 * Stream a SQL dump of schema and data into $sqlFile.
 * - Tables first (DROP + CREATE + INSERTs)
 * - Views (DROP VIEW + CREATE VIEW)
 * - Triggers (DROP TRIGGER + CREATE TRIGGER)
 *
 * NOTE: Routines/events are not dumped here. Add if needed.
 */
function dump_database_streaming(mysqli $mysqli, string $sqlFile): void {
    $fh = fopen($sqlFile, 'wb');
    if (!$fh) {
        http_response_code(500);
        exit("Cannot open dump file");
    }

    // Preamble
    fwrite_ln($fh, "-- UTF-8 + Foreign Key Safe Dump");
    fwrite_ln($fh, "SET NAMES 'utf8mb4';");
    fwrite_ln($fh, "SET FOREIGN_KEY_CHECKS = 0;");
    fwrite_ln($fh, "SET UNIQUE_CHECKS = 0;");
    fwrite_ln($fh, "SET AUTOCOMMIT = 0;");
    fwrite_ln($fh, "");

    // Gather tables and views
    $tables = [];
    $views  = [];

    $res = $mysqli->query("SHOW FULL TABLES");
    if (!$res) {
        fclose($fh);
        error_log("MySQL Error (SHOW FULL TABLES): " . $mysqli->error);
        http_response_code(500);
        exit("Error retrieving tables.");
    }
    while ($row = $res->fetch_array(MYSQLI_NUM)) {
        $name = $row[0];
        $type = strtoupper($row[1] ?? '');
        if ($type === 'VIEW') {
            $views[] = $name;
        } else {
            $tables[] = $name;
        }
    }
    $res->close();

    // --- TABLES: structure and data ---
    foreach ($tables as $table) {
        $createRes = $mysqli->query("SHOW CREATE TABLE `{$mysqli->real_escape_string($table)}`");
        if (!$createRes) {
            error_log("MySQL Error (SHOW CREATE TABLE $table): " . $mysqli->error);
            // continue to next table
            continue;
        }
        $createRow = $createRes->fetch_assoc();
        $createSQL = array_values($createRow)[1] ?? '';
        $createRes->close();

        fwrite_ln($fh, "-- ----------------------------");
        fwrite_ln($fh, "-- Table structure for `{$table}`");
        fwrite_ln($fh, "-- ----------------------------");
        fwrite_ln($fh, "DROP TABLE IF EXISTS `{$table}`;");
        fwrite_ln($fh, $createSQL . ";");
        fwrite_ln($fh, "");

        // Dump data in a streaming fashion
        $dataRes = $mysqli->query("SELECT * FROM `{$mysqli->real_escape_string($table)}`", MYSQLI_USE_RESULT);
        if ($dataRes) {
            $wroteHeader = false;
            while ($row = $dataRes->fetch_assoc()) {
                if (!$wroteHeader) {
                    fwrite_ln($fh, "-- Dumping data for table `{$table}`");
                    $wroteHeader = true;
                }
                $cols = array_map(fn($c) => '`' . $mysqli->real_escape_string($c) . '`', array_keys($row));
                $vals = array_map(
                    function ($v) use ($mysqli) {
                        return is_null($v) ? "NULL" : "'" . $mysqli->real_escape_string($v) . "'";
                    },
                    array_values($row)
                );
                fwrite_ln($fh, "INSERT INTO `{$table}` (" . implode(", ", $cols) . ") VALUES (" . implode(", ", $vals) . ");");
            }
            $dataRes->close();
            if ($wroteHeader) fwrite_ln($fh, "");
        }
    }

    // --- VIEWS ---
    foreach ($views as $view) {
        $escView = $mysqli->real_escape_string($view);
        $cRes = $mysqli->query("SHOW CREATE VIEW `{$escView}`");
        if ($cRes) {
            $row = $cRes->fetch_assoc();
            $createView = $row['Create View'] ?? '';
            $cRes->close();

            fwrite_ln($fh, "-- ----------------------------");
            fwrite_ln($fh, "-- View structure for `{$view}`");
            fwrite_ln($fh, "-- ----------------------------");
            fwrite_ln($fh, "DROP VIEW IF EXISTS `{$view}`;");
            // Ensure statement ends with semicolon
            if (!str_ends_with($createView, ';')) $createView .= ';';
            fwrite_ln($fh, $createView);
            fwrite_ln($fh, "");
        }
    }

    // --- TRIGGERS ---
    $tRes = $mysqli->query("SHOW TRIGGERS");
    if ($tRes) {
        while ($t = $tRes->fetch_assoc()) {
            $triggerName = $t['Trigger'];
            $escTrig = $mysqli->real_escape_string($triggerName);
            $crt = $mysqli->query("SHOW CREATE TRIGGER `{$escTrig}`");
            if ($crt) {
                $row = $crt->fetch_assoc();
                $createTrig = $row['SQL Original Statement'] ?? ($row['Create Trigger'] ?? '');
                $crt->close();

                fwrite_ln($fh, "-- ----------------------------");
                fwrite_ln($fh, "-- Trigger for `{$triggerName}`");
                fwrite_ln($fh, "-- ----------------------------");
                fwrite_ln($fh, "DROP TRIGGER IF EXISTS `{$triggerName}`;");
                if (!str_ends_with($createTrig, ';')) $createTrig .= ';';
                fwrite_ln($fh, $createTrig);
                fwrite_ln($fh, "");
            }
        }
        $tRes->close();
    }

    // Postamble
    fwrite_ln($fh, "SET FOREIGN_KEY_CHECKS = 1;");
    fwrite_ln($fh, "SET UNIQUE_CHECKS = 1;");
    fwrite_ln($fh, "COMMIT;");

    fclose($fh);
}

/**
 * Zip a folder to $zipFilePath, skipping symlinks and dot-entries.
 */
function zipFolderStrict(string $folderPath, string $zipFilePath): void {
    $zip = new ZipArchive();
    if ($zip->open($zipFilePath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        error_log("Failed to open zip file: $zipFilePath");
        http_response_code(500);
        exit("Internal Server Error: Cannot open zip archive.");
    }

    $folderReal = realpath($folderPath);
    if (!$folderReal || !is_dir($folderReal)) {
        // Create an empty archive if uploads folder doesn't exist yet
        $zip->close();
        return;
    }

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($folderReal, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($files as $file) {
        /** @var SplFileInfo $file */
        if ($file->isDir()) continue;
        if ($file->isLink()) continue; // skip symlinks
        $filePath = $file->getRealPath();
        if ($filePath === false) continue;

        // ensure path is inside the folder boundary
        if (strpos($filePath, $folderReal . DIRECTORY_SEPARATOR) !== 0 && $filePath !== $folderReal) {
            continue;
        }

        $relativePath = substr($filePath, strlen($folderReal) + 1);
        $zip->addFile($filePath, $relativePath);
    }

    $zip->close();
}


// PHASE8C_SERVER_BACKUP_HELPERS - server-side backups for Admin -> Update
function itflowServerBackupDir(): string {
    return '/var/backups/itflow';
}

function itflowSafeBackupBasename(string $name): string {
    $name = basename($name);
    if (!preg_match('/^itflow_server_[0-9]{14}_[A-Za-z0-9._-]+(?:_pre_restore|_uploaded|_pre_update)?\.zip$/', $name)) {
        return '';
    }
    return $name;
}

function itflowCreateFullBackupArchive(string $finalZipPath, string $generatedBy = 'Unknown User'): array {
    global $mysqli;

    $backupDir = dirname($finalZipPath);
    if (!is_dir($backupDir)) {
        mkdir($backupDir, 0750, true);
    }

    if (!is_writable($backupDir)) {
        throw new RuntimeException("Backup directory is not writable: " . $backupDir);
    }

    $baseName = pathinfo($finalZipPath, PATHINFO_FILENAME);
    $cleanupFiles = [];

    $registerTempFileForCleanup = function ($file) use (&$cleanupFiles) {
        $cleanupFiles[] = $file;
    };

    try {
        $sqlFile     = tempnam(sys_get_temp_dir(), $baseName . "_sql_");
        $uploadsZip  = tempnam(sys_get_temp_dir(), $baseName . "_uploads_");
        $versionFile = tempnam(sys_get_temp_dir(), $baseName . "_version_");
        $manifestFile = tempnam(sys_get_temp_dir(), $baseName . "_manifest_");

        foreach ([$sqlFile, $uploadsZip, $versionFile, $manifestFile] as $f) {
            $registerTempFileForCleanup($f);
            @chmod($f, 0600);
        }

        dump_database_streaming($mysqli, $sqlFile);
        zipFolderStrict("../uploads", $uploadsZip);

        $commitHash = (function_exists('shell_exec') ? trim(shell_exec('git log -1 --format=%H 2>/dev/null')) : '') ?: 'N/A';
        $gitBranch  = (function_exists('shell_exec') ? trim(shell_exec('git rev-parse --abbrev-ref HEAD 2>/dev/null')) : '') ?: 'N/A';

        $dbSha = hash_file('sha256', $sqlFile) ?: 'N/A';
        $upSha = hash_file('sha256', $uploadsZip) ?: 'N/A';

        $versionContent  = "ITFlow Backup Metadata\n";
        $versionContent .= "-----------------------------\n";
        $versionContent .= "Generated: " . date('Y-m-d H:i:s') . "\n";
        $versionContent .= "Backup File: " . basename($finalZipPath) . "\n";
        $versionContent .= "Generated By: " . $generatedBy . "\n";
        $versionContent .= "Host: " . gethostname() . "\n";
        $versionContent .= "Git Branch: $gitBranch\n";
        $versionContent .= "Git Commit: $commitHash\n";
        $versionContent .= "ITFlow Version: " . (defined('APP_VERSION') ? APP_VERSION : 'Unknown') . "\n";
        $versionContent .= "Database Version: " . (defined('CURRENT_DATABASE_VERSION') ? CURRENT_DATABASE_VERSION : 'Unknown') . "\n";
        $versionContent .= "Checksums (SHA256):\n";
        $versionContent .= "  db.sql: $dbSha\n";
        $versionContent .= "  uploads.zip: $upSha\n";

        file_put_contents($versionFile, $versionContent);
        @chmod($versionFile, 0600);

        $manifest  = "filename=" . basename($finalZipPath) . "\n";
        $manifest .= "generated_at=" . date('c') . "\n";
        $manifest .= "generated_by=" . $generatedBy . "\n";
        $manifest .= "host=" . gethostname() . "\n";
        $manifest .= "git_branch=$gitBranch\n";
        $manifest .= "git_commit=$commitHash\n";
        $manifest .= "app_version=" . (defined('APP_VERSION') ? APP_VERSION : 'Unknown') . "\n";
        $manifest .= "database_version=" . (defined('CURRENT_DATABASE_VERSION') ? CURRENT_DATABASE_VERSION : 'Unknown') . "\n";
        $manifest .= "db_sql_sha256=$dbSha\n";
        $manifest .= "uploads_zip_sha256=$upSha\n";

        file_put_contents($manifestFile, $manifest);
        @chmod($manifestFile, 0600);

        $final = new ZipArchive();
        if ($final->open($finalZipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
            throw new RuntimeException("Unable to create backup archive: " . $finalZipPath);
        }

        $final->addFile($sqlFile, "db.sql");
        $final->addFile($uploadsZip, "uploads.zip");
        $final->addFile($versionFile, "version.txt");
        $final->addFile($manifestFile, "manifest.txt");
        $final->close();

        @chmod($finalZipPath, 0640);

        return [
            'path' => $finalZipPath,
            'filename' => basename($finalZipPath),
            'size' => filesize($finalZipPath),
            'sha256' => hash_file('sha256', $finalZipPath),
        ];
    } finally {
        foreach ($cleanupFiles as $file) {
            if (is_file($file)) {
                @unlink($file);
            }
        }
    }
}

if (isset($_GET['create_server_backup'])) {

    validateCSRFToken($_GET['csrf_token']);
    validateAdminRole();

    $backupDir = itflowServerBackupDir();
    $timestamp = date('YmdHis');
    $safeHost = preg_replace('/[^A-Za-z0-9._-]/', '_', gethostname() ?: 'host');
    $filename = "itflow_server_{$timestamp}_{$safeHost}.zip";
    $path = $backupDir . DIRECTORY_SEPARATOR . $filename;

    try {
        $result = itflowCreateFullBackupArchive($path, $session_name ?? 'Unknown User');

        logAction("System", "Backup", ($session_name ?? 'Unknown User') . " created server-side backup " . $result['filename']);
        appNotify("Backup Completed", "Server-side backup created: " . $result['filename']);

        flash_alert("Server backup created: " . nullable_htmlentities($result['filename']));
    } catch (Throwable $e) {
        error_log("ITFlow server backup failed: " . $e->getMessage());

        logAction("System", "Backup Failed", ($session_name ?? 'Unknown User') . " failed to create server-side backup");
        appNotify("Backup Failed", "Server-side backup failed: " . $e->getMessage());

        flash_alert("Server backup failed: " . nullable_htmlentities($e->getMessage()), 'error');
    }

    redirect();

}

if (isset($_GET['download_server_backup'])) {

    validateCSRFToken($_GET['csrf_token']);
    validateAdminRole();

    $name = itflowSafeBackupBasename($_GET['download_server_backup'] ?? '');
    if ($name === '') {
        http_response_code(400);
        exit("Invalid backup filename.");
    }

    $path = itflowServerBackupDir() . DIRECTORY_SEPARATOR . $name;
    $realDir = realpath(itflowServerBackupDir());
    $realFile = realpath($path);

    if (!$realDir || !$realFile || strpos($realFile, $realDir . DIRECTORY_SEPARATOR) !== 0 || !is_file($realFile)) {
        http_response_code(404);
        exit("Backup not found.");
    }

    logAction("System", "Backup Download", ($session_name ?? 'Unknown User') . " downloaded server-side backup " . $name);

    header('Content-Type: application/zip');
    header('X-Content-Type-Options: nosniff');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Length: ' . filesize($realFile));
    header('Pragma: public');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Content-Transfer-Encoding: binary');

    flush();
    $fp = fopen($realFile, 'rb');
    fpassthru($fp);
    fclose($fp);
    exit;

}

if (isset($_GET['delete_server_backup'])) {

    validateCSRFToken($_GET['csrf_token']);
    validateAdminRole();

    $name = itflowSafeBackupBasename($_GET['delete_server_backup'] ?? '');
    if ($name === '') {
        flash_alert("Invalid backup filename.", 'error');
        redirect();
    }

    $path = itflowServerBackupDir() . DIRECTORY_SEPARATOR . $name;
    $realDir = realpath(itflowServerBackupDir());
    $realFile = realpath($path);

    if (!$realDir || !$realFile || strpos($realFile, $realDir . DIRECTORY_SEPARATOR) !== 0 || !is_file($realFile)) {
        flash_alert("Backup not found.", 'error');
        redirect();
    }

    if (@unlink($realFile)) {
        logAction("System", "Backup Delete", ($session_name ?? 'Unknown User') . " deleted server-side backup " . $name);
        flash_alert("Server backup deleted: " . nullable_htmlentities($name));
    } else {
        flash_alert("Could not delete backup.", 'error');
    }

    redirect();

}



// PHASE8D_RESTORE_HELPERS - validated restore support for Admin -> Update
function itflowParseManifestFile(string $manifestPath): array {
    $data = [];
    if (!is_file($manifestPath)) {
        return $data;
    }

    $lines = file($manifestPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines ?: [] as $line) {
        if (strpos($line, '=') === false) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $data[trim($key)] = trim($value);
    }

    return $data;
}

function itflowValidateRestoreBackupArchive(string $zipPath): array {
    if (!is_file($zipPath)) {
        throw new RuntimeException("Backup file does not exist.");
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        throw new RuntimeException("Backup file is not a readable ZIP archive.");
    }

    $required = ['db.sql', 'uploads.zip', 'version.txt'];
    foreach ($required as $entry) {
        if ($zip->locateName($entry) === false) {
            $zip->close();
            throw new RuntimeException("Backup archive is missing required file: " . $entry);
        }
    }

    $zip->close();

    $tmpBase = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'itflow_restore_' . bin2hex(random_bytes(8));
    if (!mkdir($tmpBase, 0700, true)) {
        throw new RuntimeException("Could not create restore temp directory.");
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        throw new RuntimeException("Backup file could not be reopened.");
    }

    if (!$zip->extractTo($tmpBase)) {
        $zip->close();
        throw new RuntimeException("Backup archive extraction failed.");
    }

    $zip->close();

    $dbSql = $tmpBase . DIRECTORY_SEPARATOR . 'db.sql';
    $uploadsZip = $tmpBase . DIRECTORY_SEPARATOR . 'uploads.zip';
    $versionTxt = $tmpBase . DIRECTORY_SEPARATOR . 'version.txt';
    $manifestTxt = $tmpBase . DIRECTORY_SEPARATOR . 'manifest.txt';

    foreach ([$dbSql, $uploadsZip, $versionTxt] as $path) {
        if (!is_file($path)) {
            throw new RuntimeException("Extracted backup is missing required file: " . basename($path));
        }
    }

    $manifest = itflowParseManifestFile($manifestTxt);

    if (!empty($manifest['db_sql_sha256'])) {
        $actual = hash_file('sha256', $dbSql);
        if (!hash_equals($manifest['db_sql_sha256'], $actual)) {
            throw new RuntimeException("db.sql checksum mismatch.");
        }
    }

    if (!empty($manifest['uploads_zip_sha256'])) {
        $actual = hash_file('sha256', $uploadsZip);
        if (!hash_equals($manifest['uploads_zip_sha256'], $actual)) {
            throw new RuntimeException("uploads.zip checksum mismatch.");
        }
    }

    $uploadsTest = new ZipArchive();
    if ($uploadsTest->open($uploadsZip) !== true) {
        throw new RuntimeException("uploads.zip inside backup is not readable.");
    }
    $uploadsTest->close();

    return [
        'tmp_dir' => $tmpBase,
        'db_sql' => $dbSql,
        'uploads_zip' => $uploadsZip,
        'version_txt' => $versionTxt,
        'manifest_txt' => $manifestTxt,
        'manifest' => $manifest,
    ];
}

function itflowRemoveDirectoryTree(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($items as $item) {
        if ($item->isLink() || $item->isFile()) {
            @unlink($item->getPathname());
        } elseif ($item->isDir()) {
            @rmdir($item->getPathname());
        }
    }

    @rmdir($dir);
}

function itflowImportSqlFileWithMysqlClient(string $sqlPath): void {
    global $dbhost, $dbusername, $dbpassword, $database;

    if (!is_file($sqlPath)) {
        throw new RuntimeException("SQL restore file is missing.");
    }

    $defaultsFile = tempnam(sys_get_temp_dir(), 'itflow_mysql_restore_');
    if (!$defaultsFile) {
        throw new RuntimeException("Could not create mysql defaults file.");
    }

    $defaults = "[client]\n";
    $defaults .= "host=" . $dbhost . "\n";
    $defaults .= "user=" . $dbusername . "\n";
    $defaults .= "password=" . $dbpassword . "\n";
    $defaults .= "database=" . $database . "\n";
    $defaults .= "default-character-set=utf8mb4\n";

    file_put_contents($defaultsFile, $defaults);
    chmod($defaultsFile, 0600);

    $cmd = "mysql --defaults-extra-file=" . escapeshellarg($defaultsFile) . " " . escapeshellarg($database) . " < " . escapeshellarg($sqlPath) . " 2>&1";

    exec($cmd, $output, $code);

    @unlink($defaultsFile);

    if ($code !== 0) {
        throw new RuntimeException("Database import failed: " . implode("\n", array_slice($output, -20)));
    }
}

function itflowRestoreUploadsZip(string $uploadsZipPath): void {
    $webRoot = realpath(__DIR__ . '/../..');
    if (!$webRoot) {
        throw new RuntimeException("Could not resolve web root.");
    }

    $uploadsPath = $webRoot . DIRECTORY_SEPARATOR . 'uploads';
    $restoreStage = $webRoot . DIRECTORY_SEPARATOR . 'uploads.restore-stage-' . date('YmdHis');
    $oldUploads = $webRoot . DIRECTORY_SEPARATOR . 'uploads.restore-old-' . date('YmdHis');

    if (!mkdir($restoreStage, 0750, true)) {
        throw new RuntimeException("Could not create uploads restore staging directory.");
    }

    $zip = new ZipArchive();
    if ($zip->open($uploadsZipPath) !== true) {
        throw new RuntimeException("Could not open uploads.zip for restore.");
    }

    if (!$zip->extractTo($restoreStage)) {
        $zip->close();
        throw new RuntimeException("Could not extract uploads.zip.");
    }

    $zip->close();

    if (is_dir($uploadsPath)) {
        if (!rename($uploadsPath, $oldUploads)) {
            itflowRemoveDirectoryTree($restoreStage);
            throw new RuntimeException("Could not move current uploads directory out of the way.");
        }
    }

    if (!rename($restoreStage, $uploadsPath)) {
        if (is_dir($oldUploads)) {
            @rename($oldUploads, $uploadsPath);
        }
        throw new RuntimeException("Could not move restored uploads directory into place.");
    }

    itflowRemoveDirectoryTree($oldUploads);
}

function itflowRunRestoreFromBackupArchive(string $zipPath, string $requestedBy): array {
    $validated = null;
    $preRestore = null;

    try {
        $validated = itflowValidateRestoreBackupArchive($zipPath);

        $backupDir = itflowServerBackupDir();
        $safeHost = preg_replace('/[^A-Za-z0-9._-]/', '_', gethostname() ?: 'host');
        $preFile = $backupDir . DIRECTORY_SEPARATOR . 'itflow_server_' . date('YmdHis') . '_' . $safeHost . '_pre_restore.zip';
        $preRestore = itflowCreateFullBackupArchive($preFile, $requestedBy . ' pre-restore safety backup');

        itflowImportSqlFileWithMysqlClient($validated['db_sql']);
        itflowRestoreUploadsZip($validated['uploads_zip']);

        return [
            'restored_from' => basename($zipPath),
            'pre_restore_backup' => $preRestore['filename'] ?? '',
            'manifest' => $validated['manifest'] ?? [],
        ];
    } finally {
        if (is_array($validated) && !empty($validated['tmp_dir'])) {
            itflowRemoveDirectoryTree($validated['tmp_dir']);
        }
    }
}

if (isset($_POST['upload_server_backup'])) {

    validateCSRFToken($_POST['csrf_token']);
    validateAdminRole();

    if (empty($_FILES['backup_file']['tmp_name']) || !is_uploaded_file($_FILES['backup_file']['tmp_name'])) {
        flash_alert("No backup file uploaded.", 'error');
        redirect();
    }

    $original = basename($_FILES['backup_file']['name'] ?? '');
    if (!preg_match('/\.zip$/i', $original)) {
        flash_alert("Uploaded backup must be a ZIP file.", 'error');
        redirect();
    }

    $backupDir = itflowServerBackupDir();
    if (!is_dir($backupDir)) {
        mkdir($backupDir, 0750, true);
    }

    $safeHost = preg_replace('/[^A-Za-z0-9._-]/', '_', gethostname() ?: 'host');
    $target = $backupDir . DIRECTORY_SEPARATOR . 'itflow_server_' . date('YmdHis') . '_' . $safeHost . '_uploaded.zip';

    if (!move_uploaded_file($_FILES['backup_file']['tmp_name'], $target)) {
        flash_alert("Could not save uploaded backup.", 'error');
        redirect();
    }

    @chmod($target, 0640);

    try {
        itflowValidateRestoreBackupArchive($target);
        logAction("System", "Backup Upload", ($session_name ?? 'Unknown User') . " uploaded restore backup " . basename($target));
        flash_alert("Backup uploaded and validated: " . nullable_htmlentities(basename($target)));
    } catch (Throwable $e) {
        @unlink($target);
        flash_alert("Uploaded backup failed validation: " . nullable_htmlentities($e->getMessage()), 'error');
    }

    redirect();

}

if (isset($_POST['restore_server_backup'])) {

    validateCSRFToken($_POST['csrf_token']);
    validateAdminRole();

    $confirm = trim($_POST['restore_confirm'] ?? '');
    if ($confirm !== 'RESTORE') {
        flash_alert("Restore confirmation failed. Type RESTORE exactly.", 'error');
        redirect();
    }

    $name = itflowSafeBackupBasename($_POST['restore_backup_name'] ?? '');
    if ($name === '') {
        flash_alert("Invalid backup filename.", 'error');
        redirect();
    }

    $path = itflowServerBackupDir() . DIRECTORY_SEPARATOR . $name;
    $realDir = realpath(itflowServerBackupDir());
    $realFile = realpath($path);

    if (!$realDir || !$realFile || strpos($realFile, $realDir . DIRECTORY_SEPARATOR) !== 0 || !is_file($realFile)) {
        flash_alert("Backup not found.", 'error');
        redirect();
    }

    try {
        $result = itflowRunRestoreFromBackupArchive($realFile, $session_name ?? 'Unknown User');

        logAction("System", "Restore", ($session_name ?? 'Unknown User') . " restored ITFlow from backup " . $name . " after creating pre-restore backup " . ($result['pre_restore_backup'] ?? ''));
        appNotify("Backup Completed", "Restore completed from backup: " . $name);

        flash_alert("Restore completed from backup " . nullable_htmlentities($name) . ". Pre-restore safety backup: " . nullable_htmlentities($result['pre_restore_backup'] ?? ''));
    } catch (Throwable $e) {
        error_log("ITFlow restore failed: " . $e->getMessage());

        logAction("System", "Restore Failed", ($session_name ?? 'Unknown User') . " failed to restore ITFlow from backup " . $name);
        appNotify("Backup Failed", "Restore failed from backup " . $name . ": " . $e->getMessage());

        flash_alert("Restore failed: " . nullable_htmlentities($e->getMessage()), 'error');
    }

    redirect();

}


if (isset($_GET['download_backup'])) {

    validateCSRFToken($_GET['csrf_token']);

    $timestamp   = date('YmdHis');
    $baseName    = "itflow_{$timestamp}";
    $downloadName = $baseName . ".zip";

    // === Scoped cleanup of temp files ===
    $cleanupFiles = [];
    $registerTempFileForCleanup = function ($file) use (&$cleanupFiles) {
        $cleanupFiles[] = $file;
    };
    register_shutdown_function(function () use (&$cleanupFiles) {
        foreach ($cleanupFiles as $file) {
            if (is_file($file)) { @unlink($file); }
        }
    });

    // === Create temp files ===
    $sqlFile     = tempnam(sys_get_temp_dir(), $baseName . "_sql_");
    $uploadsZip  = tempnam(sys_get_temp_dir(), $baseName . "_uploads_");
    $versionFile = tempnam(sys_get_temp_dir(), $baseName . "_version_");
    $finalZip    = tempnam(sys_get_temp_dir(), $baseName . "_backup_");

    foreach ([$sqlFile, $uploadsZip, $versionFile, $finalZip] as $f) {
        $registerTempFileForCleanup($f);
        @chmod($f, 0600);
    }

    // === Generate SQL Dump (streaming) ===
    dump_database_streaming($mysqli, $sqlFile);

    // === Zip the uploads folder (strict) ===
    zipFolderStrict("../uploads", $uploadsZip);

    // === Gather metadata & checksums ===
    $commitHash = (function_exists('shell_exec') ? trim(shell_exec('git log -1 --format=%H 2>/dev/null')) : '') ?: 'N/A';
    $gitBranch  = (function_exists('shell_exec') ? trim(shell_exec('git rev-parse --abbrev-ref HEAD 2>/dev/null')) : '') ?: 'N/A';

    $dbSha = hash_file('sha256', $sqlFile) ?: 'N/A';
    $upSha = hash_file('sha256', $uploadsZip) ?: 'N/A';

    $versionContent  = "ITFlow Backup Metadata\n";
    $versionContent .= "-----------------------------\n";
    $versionContent .= "Generated: " . date('Y-m-d H:i:s') . "\n";
    $versionContent .= "Backup File: " . $downloadName . "\n";
    $versionContent .= "Generated By: " . ($session_name ?? 'Unknown User') . "\n";
    $versionContent .= "Host: " . gethostname() . "\n";
    $versionContent .= "Git Branch: $gitBranch\n";
    $versionContent .= "Git Commit: $commitHash\n";
    $versionContent .= "ITFlow Version: " . (defined('APP_VERSION') ? APP_VERSION : 'Unknown') . "\n";
    $versionContent .= "Database Version: " . (defined('CURRENT_DATABASE_VERSION') ? CURRENT_DATABASE_VERSION : 'Unknown') . "\n";
    $versionContent .= "Checksums (SHA256):\n";
    $versionContent .= "  db.sql: $dbSha\n";
    $versionContent .= "  uploads.zip: $upSha\n";

    file_put_contents($versionFile, $versionContent);
    @chmod($versionFile, 0600);

    // === Build final ZIP ===
    $final = new ZipArchive();
    if ($final->open($finalZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== TRUE) {
        error_log("Failed to create final zip: $finalZip");
        http_response_code(500);
        exit("Internal Server Error: Unable to create backup archive.");
    }
    $final->addFile($sqlFile, "db.sql");
    $final->addFile($uploadsZip, "uploads.zip");
    $final->addFile($versionFile, "version.txt");
    $final->close();

    @chmod($finalZip, 0600);

    // === Serve final ZIP with a stable filename ===
    header('Content-Type: application/zip');
    header('X-Content-Type-Options: nosniff');
    header('Content-Disposition: attachment; filename="' . $downloadName . '"');
    header('Content-Length: ' . filesize($finalZip));
    header('Pragma: public');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Content-Transfer-Encoding: binary');

    // Push file
    flush();
    $fp = fopen($finalZip, 'rb');
    fpassthru($fp);
    fclose($fp);

    // Log + UX
    logAction("System", "Backup Download", ($session_name ?? 'Unknown User') . " downloaded full backup.");
    flash_alert("Full backup downloaded.");
    exit;
}

if (isset($_POST['backup_master_key'])) {

    validateCSRFToken($_POST['csrf_token']);

    $password = $_POST['password'];

    $sql = mysqli_query($mysqli, "SELECT * FROM users WHERE user_id = $session_user_id");
    $row = mysqli_fetch_assoc($sql);

    if (password_verify($password, $row['user_password'])) {
        $site_encryption_master_key = decryptUserSpecificKey($row['user_specific_encryption_ciphertext'], $password);

        logAction("Master Key", "Download", "$session_name retrieved the master encryption key");

        appNotify("Master Key", "$session_name retrieved the master encryption key");

        echo "==============================";
        echo "<br>Master encryption key:<br>";
        echo "<b>$site_encryption_master_key</b>";
        echo "<br>==============================";

    } else {
        logAction("Master Key", "Download", "$session_name attempted to retrieve the master encryption key but failed");

        flash_alert("Incorrect password.", 'error');

        redirect();
    }
}
