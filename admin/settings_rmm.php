<?php
require_once "includes/inc_all_admin.php";

function rmm_h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function rmm_db() {
    global $mysqli, $dbhost, $dbusername, $dbpassword, $database;

    if (isset($mysqli) && $mysqli instanceof mysqli) {
        return $mysqli;
    }

    $host = $dbhost ?? 'localhost';
    $user = $dbusername ?? null;
    $pass = $dbpassword ?? '';
    $db   = $database ?? 'itflow';

    if (!$user) {
        throw new Exception("Database config variables unavailable.");
    }

    $m = new mysqli($host, $user, $pass, $db);
    if ($m->connect_error) {
        throw new Exception("Database connection failed: " . $m->connect_error);
    }
    $m->set_charset("utf8mb4");
    return $m;
}

function rmm_query($sql) {
    $db = rmm_db();
    $result = $db->query($sql);
    if (!$result) {
        throw new Exception($db->error);
    }
    return $result;
}

function rmm_exec($sql) {
    $db = rmm_db();
    if (!$db->query($sql)) {
        throw new Exception($db->error);
    }
    return true;
}

function rmm_escape($value) {
    return rmm_db()->real_escape_string((string)$value);
}

function rmm_current_user_label() {
    global $session_name, $session_user_name, $session_email, $session_user_email;
    if (!empty($session_name)) return $session_name;
    if (!empty($session_user_name)) return $session_user_name;
    if (!empty($session_email)) return $session_email;
    if (!empty($session_user_email)) return $session_user_email;
    if (!empty($_SESSION['name'])) return $_SESSION['name'];
    if (!empty($_SESSION['user_name'])) return $_SESSION['user_name'];
    if (!empty($_SESSION['email'])) return $_SESSION['email'];
    if (!empty($_SESSION['user_email'])) return $_SESSION['user_email'];
    return 'ITFlow UI';
}

function rmm_latest_file($pattern) {
    $files = glob($pattern);
    if (!$files) return null;
    rsort($files);
    return $files[0];
}

function rmm_parse_csv_assoc($file) {
    $rows = [];
    if (!$file || !is_readable($file)) return $rows;
    $fh = fopen($file, 'r');
    if (!$fh) return $rows;
    $headers = fgetcsv($fh);
    if (!$headers) {
        fclose($fh);
        return $rows;
    }
    while (($data = fgetcsv($fh)) !== false) {
        $row = [];
        foreach ($headers as $i => $h) {
            $row[$h] = $data[$i] ?? '';
        }
        $rows[] = $row;
    }
    fclose($fh);
    return $rows;
}

function rmm_latest_live_summary() {
    $summary_file = rmm_latest_file('/opt/itflow-trmm-sync/reports/live-*/summary_live_fetch.txt');
    if ($summary_file && is_readable($summary_file)) {
        return file_get_contents($summary_file);
    }
    return "No live fetch report found.";
}

function rmm_latest_sync_summary() {
    $summary_file = rmm_latest_file('/opt/itflow-trmm-sync/reports/sync-*/summary.txt');
    if ($summary_file && is_readable($summary_file)) {
        return file_get_contents($summary_file);
    }
    return "No sync report found.";
}

function rmm_run_live_connection_test() {
    $cmd = "timeout 60 sudo -n /usr/local/sbin/itflow-trmm-test-connection-live 2>&1";
    $output = [];
    $code = 1;
    exec($cmd, $output, $code);
    return [
        'code' => $code,
        'output' => implode("\n", $output),
    ];
}

function rmm_asset_url($asset_id) {
    $asset_id = (int)$asset_id;
    return "/client_asset_details.php?asset_id=" . $asset_id;
}


function rmm_agent_extra($agents_by_id, $agent_id, $field) {
    $agent_id = (string)$agent_id;
    if (!isset($agents_by_id[$agent_id]) || !is_array($agents_by_id[$agent_id])) {
        return '';
    }
    return $agents_by_id[$agent_id][$field] ?? '';
}

function rmm_index_by($rows, $key) {
    $out = [];
    foreach ($rows as $row) {
        if (!empty($row[$key])) {
            $out[(string)$row[$key]] = $row;
        }
    }
    return $out;
}

$message = '';
$error = '';
$live_test_output = '';
$asset_limit = (int)($_GET['asset_limit'] ?? 200);
if (!in_array($asset_limit, [100, 200, 500], true)) {
    $asset_limit = 200;
}

$active_tab = $_GET['tab'] ?? 'settings';

// ITFlow/TRMM auto-create settings helpers BEGIN
if (!function_exists('rmm_trmm_settings_ensure')) {
    function rmm_trmm_settings_ensure(mysqli $mysqli): void {
        mysqli_query($mysqli, "CREATE TABLE IF NOT EXISTS itflow_trmm_settings (
            setting_key VARCHAR(128) NOT NULL PRIMARY KEY,
            setting_value TEXT NULL,
            updated_at DATETIME NULL ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        mysqli_query($mysqli, "CREATE TABLE IF NOT EXISTS itflow_trmm_merge_log (
            merge_id INT AUTO_INCREMENT PRIMARY KEY,
            merge_type VARCHAR(64) NOT NULL,
            source_itflow_id INT NOT NULL DEFAULT 0,
            target_itflow_id INT NOT NULL DEFAULT 0,
            trmm_id VARCHAR(255) NOT NULL DEFAULT '',
            action_taken VARCHAR(255) NOT NULL DEFAULT '',
            notes TEXT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            KEY idx_merge_type (merge_type),
            KEY idx_trmm_id (trmm_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        $defaults = [
            'scheduled_sync_enabled' => '1',
            'sync_interval_minutes' => '5',
            'auto_create_clients' => '1',
            'auto_create_sites' => '1',
            'auto_create_assets' => '1',
        ];

        foreach ($defaults as $key => $value) {
            $stmt = $mysqli->prepare("INSERT IGNORE INTO itflow_trmm_settings (setting_key, setting_value, updated_at) VALUES (?, ?, NOW())");
            if ($stmt) {
                $stmt->bind_param('ss', $key, $value);
                $stmt->execute();
                $stmt->close();
            }
        }
    }

    function rmm_trmm_setting_get(mysqli $mysqli, string $key, string $default = ''): string {
        $stmt = $mysqli->prepare("SELECT setting_value FROM itflow_trmm_settings WHERE setting_key = ?");
        if (!$stmt) return $default;
        $stmt->bind_param('s', $key);
        $stmt->execute();
        $res = $stmt->get_result();
        $row = $res ? $res->fetch_assoc() : null;
        $stmt->close();
        return $row ? (string)$row['setting_value'] : $default;
    }

    function rmm_trmm_setting_set(mysqli $mysqli, string $key, string $value): void {
        $stmt = $mysqli->prepare("INSERT INTO itflow_trmm_settings (setting_key, setting_value, updated_at)
            VALUES (?, ?, NOW())
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = NOW()");
        if (!$stmt) return;
        $stmt->bind_param('ss', $key, $value);
        $stmt->execute();
        $stmt->close();
    }

    function rmm_trmm_bool_setting(mysqli $mysqli, string $key, string $default = '1'): bool {
        return rmm_trmm_setting_get($mysqli, $key, $default) === '1';
    }
}
rmm_trmm_settings_ensure($mysqli);
// ITFlow/TRMM auto-create settings helpers END

$valid_tabs = ['settings', 'clients', 'sites', 'assets', 'jobs', 'logs'];
if (!in_array($active_tab, $valid_tabs, true)) {
    $active_tab = 'settings';
}

try {
    $latest_clients_file = rmm_latest_file('/opt/itflow-trmm-sync/reports/live-*/trmm_clients.csv');
    $latest_agents_file = rmm_latest_file('/opt/itflow-trmm-sync/reports/live-*/trmm_agents.csv');
    $latest_conflicts_file = rmm_latest_file('/opt/itflow-trmm-sync/reports/sync-*/asset_sync_conflicts.csv');

    $trmm_clients = rmm_parse_csv_assoc($latest_clients_file);
    usort($trmm_clients, function($a, $b) {
        return strcasecmp($a['trmm_client_name'] ?? '', $b['trmm_client_name'] ?? '');
    });

    $trmm_agents = rmm_parse_csv_assoc($latest_agents_file);
    $trmm_agents_by_id = rmm_index_by($trmm_agents, 'trmm_agent_id');

    $rmm_agent_options = [];
    foreach ($trmm_agents as $ta) {
        $ta_id = $ta['trmm_agent_id'] ?? '';
        if ($ta_id === '') {
            continue;
        }
        $ta_client = $ta['trmm_client_name'] ?? '';
        $ta_host = $ta['hostname'] ?? '';
        $ta_desc = $ta['description'] ?? '';
        $ta_user = $ta['logged_username'] ?? '';
        $ta_status = $ta['status'] ?? '';
        $label_parts = [];
        if ($ta_client !== '') $label_parts[] = $ta_client;
        if ($ta_host !== '') $label_parts[] = $ta_host;
        if ($ta_desc !== '') $label_parts[] = $ta_desc;
        if ($ta_user !== '') $label_parts[] = $ta_user;
        if ($ta_status !== '') $label_parts[] = $ta_status;
        $label = implode(' / ', $label_parts);
        if ($label === '') {
            $label = $ta_id;
        }
        $rmm_agent_options[] = [
            'id' => $ta_id,
            'label' => $label . ' [' . substr($ta_id, 0, 10) . '...]',
        ];
    }

    $asset_conflicts = rmm_parse_csv_assoc($latest_conflicts_file);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'] ?? '';

        if ($action === 'save_autocreate_sync_settings') {
            $scheduled_sync_enabled = !empty($_POST['scheduled_sync_enabled']) ? '1' : '0';
            $auto_create_clients = !empty($_POST['auto_create_clients']) ? '1' : '0';
            $auto_create_sites = !empty($_POST['auto_create_sites']) ? '1' : '0';
            $auto_create_assets = !empty($_POST['auto_create_assets']) ? '1' : '0';
            $sync_interval_minutes = (int)($_POST['sync_interval_minutes'] ?? 5);
            if ($sync_interval_minutes < 1) $sync_interval_minutes = 1;
            if ($sync_interval_minutes > 1440) $sync_interval_minutes = 1440;

            rmm_trmm_setting_set($mysqli, 'scheduled_sync_enabled', $scheduled_sync_enabled);
            rmm_trmm_setting_set($mysqli, 'sync_interval_minutes', (string)$sync_interval_minutes);
            rmm_trmm_setting_set($mysqli, 'auto_create_clients', $auto_create_clients);
            rmm_trmm_setting_set($mysqli, 'auto_create_sites', $auto_create_sites);
            rmm_trmm_setting_set($mysqli, 'auto_create_assets', $auto_create_assets);

            $active_tab = 'settings';
        } // END save_autocreate_sync_settings

        $requested_by = rmm_escape(rmm_current_user_label());

        if ($action === 'test_connection_live') {
            $result = rmm_run_live_connection_test();
            $live_test_output = $result['output'];

            if ($result['code'] === 0 && strpos($result['output'], 'OK') === 0) {
                rmm_exec("
                    UPDATE itflow_rmm_integrations
                    SET last_connection_status='success',
                        last_connection_at=NOW(),
                        updated_at=NOW()
                    WHERE provider='tacticalrmm'
                    LIMIT 1
                ");
                $message = "Connection test successful.";
            } else {
                rmm_exec("
                    UPDATE itflow_rmm_integrations
                    SET last_connection_status='failed',
                        last_connection_at=NOW(),
                        updated_at=NOW()
                    WHERE provider='tacticalrmm'
                    LIMIT 1
                ");
                $error = "Connection test failed.";
            }
            $active_tab = 'settings';
        }

        $job_map = [
            'client_auto_match' => 'client_auto_match',
            'asset_preview' => 'asset_preview',
            'asset_apply' => 'asset_apply',
        ];

        if (isset($job_map[$action])) {
            $job_type = rmm_escape($job_map[$action]);
            rmm_exec("INSERT INTO itflow_rmm_jobs (provider, job_type, job_status, requested_by, created_at) VALUES ('tacticalrmm', '$job_type', 'queued', '$requested_by', NOW())");
            $message = "Queued job: " . $job_map[$action] . ". It should run within about one minute.";
            if ($action === 'client_auto_match') $active_tab = 'clients';
            if ($action === 'asset_preview' || $action === 'asset_apply') $active_tab = 'jobs';
        } elseif ($action === 'manual_client_match_select') {
            $itflow_client_id = (int)($_POST['itflow_client_id'] ?? 0);
            $selected = $_POST['trmm_client_select'] ?? '';
            $parts = explode('|', $selected, 2);
            $trmm_client_id = (int)($parts[0] ?? 0);
            $trmm_client_name = rmm_escape($parts[1] ?? '');

            if ($itflow_client_id <= 0 || $trmm_client_id <= 0 || $trmm_client_name === '') {
                throw new Exception("Manual match requires selecting a TacticalRMM client.");
            }

            rmm_exec("
                INSERT INTO itflow_trmm_client_map
                  (itflow_client_id, trmm_client_id, trmm_client_name, match_type, enabled, notes, updated_at)
                VALUES
                  ($itflow_client_id, $trmm_client_id, '$trmm_client_name', 'manual_selected', 1, 'Set from RMM UI dropdown', NOW())
                ON DUPLICATE KEY UPDATE
                  trmm_client_id=VALUES(trmm_client_id),
                  trmm_client_name=VALUES(trmm_client_name),
                  match_type=VALUES(match_type),
                  enabled=1,
                  notes=VALUES(notes),
                  updated_at=NOW()
            ");

            $message = "Manual client match saved.";
            $active_tab = 'clients';
        } elseif ($action === 'disable_client_match') {
            $itflow_client_id = (int)($_POST['itflow_client_id'] ?? 0);
            if ($itflow_client_id <= 0) {
                throw new Exception("Missing ITFlow client ID.");
            }

            rmm_exec("UPDATE itflow_trmm_client_map SET enabled=0, match_type='disabled', updated_at=NOW() WHERE itflow_client_id=$itflow_client_id LIMIT 1");
            $message = "Client mapping disabled. This does not disable the ITFlow client and does not disable the client in TacticalRMM.";
            $active_tab = 'clients';
        } elseif ($action === 'manual_site_location_match') {
            $trmm_site_id = (int)($_POST['trmm_site_id'] ?? 0);
            $trmm_client_id = (int)($_POST['trmm_client_id'] ?? 0);
            $trmm_site_name_raw = trim($_POST['trmm_site_name'] ?? '');

            if (!empty($_POST['trmm_site_select'])) {
                $decoded_site_select = json_decode(base64_decode((string)$_POST['trmm_site_select'], true), true);
                if (is_array($decoded_site_select)) {
                    $trmm_site_id = (int)($decoded_site_select['trmm_site_id'] ?? 0);
                    $trmm_client_id = (int)($decoded_site_select['trmm_client_id'] ?? 0);
                    $trmm_site_name_raw = trim((string)($decoded_site_select['trmm_site_name'] ?? ''));
                }
            }

            $trmm_site_name = $mysqli->real_escape_string($trmm_site_name_raw);
            $itflow_location_id = (int)($_POST['itflow_location_id'] ?? 0);

            if ($trmm_site_id > 0 && $trmm_client_id > 0 && $trmm_site_name !== '' && $itflow_location_id > 0) {
                $loc_q = $mysqli->query("SELECT location_id, location_name, location_client_id FROM locations WHERE location_id=$itflow_location_id AND location_archived_at IS NULL LIMIT 1");
                if ($loc_q && ($loc = $loc_q->fetch_assoc())) {
                    $itflow_client_id = (int)$loc['location_client_id'];
                    $mysqli->begin_transaction();
                    $mysqli->query("DELETE FROM itflow_trmm_site_map WHERE trmm_site_id=$trmm_site_id OR itflow_location_id=$itflow_location_id");
                    $mysqli->query("
                        INSERT INTO itflow_trmm_site_map
                            (itflow_location_id, itflow_client_id, trmm_site_id, trmm_client_id, trmm_site_name, match_type, enabled, updated_at)
                        VALUES
                            ($itflow_location_id, $itflow_client_id, $trmm_site_id, $trmm_client_id, '$trmm_site_name', 'manual', 1, NOW())
                    ");
                    $mysqli->commit();
                    $_SESSION['alert_message'] = 'Site / Location mapping saved.';
                }
            }

        } elseif ($action === 'create_location_and_match_site') {
            $trmm_site_id = (int)($_POST['trmm_site_id'] ?? 0);
            $trmm_client_id = (int)($_POST['trmm_client_id'] ?? 0);
            $trmm_site_name_raw = trim($_POST['trmm_site_name'] ?? '');
            $trmm_site_name = $mysqli->real_escape_string($trmm_site_name_raw);

            $itflow_client_id = 0;
            $cm_q = $mysqli->query("SELECT itflow_client_id FROM itflow_trmm_client_map WHERE trmm_client_id=$trmm_client_id AND enabled=1 LIMIT 1");
            if ($cm_q && ($cm = $cm_q->fetch_assoc())) {
                $itflow_client_id = (int)$cm['itflow_client_id'];
            }

            if ($trmm_site_id > 0 && $trmm_client_id > 0 && $trmm_site_name_raw !== '' && $itflow_client_id > 0) {
                $existing_location_id = 0;
                $loc_q = $mysqli->query("
                    SELECT location_id
                    FROM locations
                    WHERE location_client_id=$itflow_client_id
                      AND location_archived_at IS NULL
                      AND LOWER(TRIM(location_name)) = LOWER(TRIM('$trmm_site_name'))
                    LIMIT 1
                ");
                if ($loc_q && ($loc = $loc_q->fetch_assoc())) {
                    $existing_location_id = (int)$loc['location_id'];
                }

                $mysqli->begin_transaction();

                if ($existing_location_id <= 0) {
                    $mysqli->query("
                        INSERT INTO locations
                            (location_name, location_client_id, location_primary, location_created_at)
                        VALUES
                            ('$trmm_site_name', $itflow_client_id, 0, NOW())
                    ");
                    $existing_location_id = (int)$mysqli->insert_id;
                }

                if ($existing_location_id > 0) {
                    $mysqli->query("DELETE FROM itflow_trmm_site_map WHERE trmm_site_id=$trmm_site_id OR itflow_location_id=$existing_location_id");
                    $mysqli->query("
                        INSERT INTO itflow_trmm_site_map
                            (itflow_location_id, itflow_client_id, trmm_site_id, trmm_client_id, trmm_site_name, match_type, enabled, updated_at)
                        VALUES
                            ($existing_location_id, $itflow_client_id, $trmm_site_id, $trmm_client_id, '$trmm_site_name', 'created_location', 1, NOW())
                    ");
                }

                $mysqli->commit();
                $_SESSION['alert_message'] = 'ITFlow location created and site mapping saved.';
            }

        } elseif ($action === 'disable_site_location_mapping') {
            $trmm_site_id = (int)($_POST['trmm_site_id'] ?? 0);
            $trmm_client_id = (int)($_POST['trmm_client_id'] ?? 0);
            $itflow_location_id = (int)($_POST['itflow_location_id'] ?? 0);
            $trmm_site_name = $mysqli->real_escape_string(trim($_POST['trmm_site_name'] ?? ''));

            if ($trmm_site_id > 0) {
                $existing_q = $mysqli->query("SELECT map_id FROM itflow_trmm_site_map WHERE trmm_site_id=$trmm_site_id LIMIT 1");
                if ($existing_q && $existing_q->num_rows > 0) {
                    $mysqli->query("UPDATE itflow_trmm_site_map SET enabled=0, updated_at=NOW() WHERE trmm_site_id=$trmm_site_id");
                } elseif ($itflow_location_id > 0 && $trmm_client_id > 0 && $trmm_site_name !== '') {
                    $loc_q = $mysqli->query("SELECT location_id, location_client_id FROM locations WHERE location_id=$itflow_location_id AND location_archived_at IS NULL LIMIT 1");
                    if ($loc_q && ($loc = $loc_q->fetch_assoc())) {
                        $itflow_client_id = (int)$loc['location_client_id'];
                        $mysqli->query("
                            INSERT INTO itflow_trmm_site_map
                                (itflow_location_id, itflow_client_id, trmm_site_id, trmm_client_id, trmm_site_name, match_type, enabled, updated_at)
                            VALUES
                                ($itflow_location_id, $itflow_client_id, $trmm_site_id, $trmm_client_id, '$trmm_site_name', 'disabled_before_save', 0, NOW())
                            ON DUPLICATE KEY UPDATE
                                enabled=0,
                                updated_at=NOW()
                        ");
                    }
                }
                $_SESSION['alert_message'] = 'Location Mapping disabled.';
            }

        } elseif ($action === 'enable_site_location_mapping') {
            $trmm_site_id = (int)($_POST['trmm_site_id'] ?? 0);
            if ($trmm_site_id > 0) {
                $mysqli->query("UPDATE itflow_trmm_site_map SET enabled=1, updated_at=NOW() WHERE trmm_site_id=$trmm_site_id");
                $_SESSION['alert_message'] = 'Location Mapping enabled.';
            }

        } elseif ($action === 'auto_save_site_location_candidates') {
            $latest_site_preview_file = '';
            $site_preview_files = glob('/opt/itflow-trmm-sync/reports/live-*/trmm_site_location_preview.csv') ?: [];
            if (!empty($site_preview_files)) {
                usort($site_preview_files, function ($a, $b) { return filemtime($b) <=> filemtime($a); });
                $latest_site_preview_file = $site_preview_files[0];
            }

            $saved = 0;
            if ($latest_site_preview_file && is_readable($latest_site_preview_file)) {
                $site_preview_rows = rmm_parse_csv_assoc($latest_site_preview_file);
                $mysqli->begin_transaction();

                foreach ($site_preview_rows as $sr) {
                    if (($sr['mapping_status'] ?? '') !== 'auto_match_candidate') {
                        continue;
                    }

                    $trmm_site_id = (int)($sr['trmm_site_id'] ?? 0);
                    $trmm_client_id = (int)($sr['trmm_client_id'] ?? 0);
                    $itflow_client_id = (int)($sr['itflow_client_id'] ?? 0);
                    $itflow_location_id = (int)($sr['itflow_location_id'] ?? 0);
                    $trmm_site_name = $mysqli->real_escape_string($sr['trmm_site_name'] ?? '');

                    if ($trmm_site_id <= 0 || $trmm_client_id <= 0 || $itflow_client_id <= 0 || $itflow_location_id <= 0 || $trmm_site_name === '') {
                        continue;
                    }

                    $mysqli->query("DELETE FROM itflow_trmm_site_map WHERE trmm_site_id=$trmm_site_id OR itflow_location_id=$itflow_location_id");
                    $mysqli->query("
                        INSERT INTO itflow_trmm_site_map
                            (itflow_location_id, itflow_client_id, trmm_site_id, trmm_client_id, trmm_site_name, match_type, enabled, updated_at)
                        VALUES
                            ($itflow_location_id, $itflow_client_id, $trmm_site_id, $trmm_client_id, '$trmm_site_name', 'name_exact', 1, NOW())
                    ");
                    $saved++;
                }

                $mysqli->commit();
            }

            $_SESSION['alert_message'] = 'Auto-matched ' . $saved . ' exact Location Mapping candidate(s).';

        } elseif ($action === 'manual_agent_match_select') {
            $asset_id = (int)($_POST['itflow_asset_id'] ?? 0);
            $trmm_agent_id_raw = trim($_POST['trmm_agent_id'] ?? '');
            $trmm_agent_id = rmm_escape($trmm_agent_id_raw);

            if ($asset_id <= 0 || $trmm_agent_id_raw === '') {
                throw new Exception("Manual agent match requires selecting an ITFlow asset and TacticalRMM agent.");
            }

            $asset = rmm_query("
                SELECT asset_id, asset_name, asset_client_id
                FROM assets
                WHERE asset_id=$asset_id
                  AND asset_archived_at IS NULL
                LIMIT 1
            ")->fetch_assoc();

            if (!$asset) {
                throw new Exception("Selected ITFlow asset does not exist or is archived.");
            }

            $manual_map_db = rmm_db();
            $manual_map_db->begin_transaction();

            try {
                /*
                 * Fix Match semantics:
                 * - The selected ITFlow asset is allowed to change from its old TRMM agent to the selected TRMM agent.
                 * - If the selected TRMM agent was mapped to a different ITFlow asset, that old incorrect mapping is removed.
                 * - This changes only ITFlow's mapping table. It does not modify TacticalRMM.
                 */

                rmm_exec("
                    DELETE FROM itflow_trmm_asset_map
                    WHERE trmm_agent_id='$trmm_agent_id'
                      AND itflow_asset_id<>$asset_id
                ");

                $existing_asset_map = rmm_query("
                    SELECT map_id
                    FROM itflow_trmm_asset_map
                    WHERE itflow_asset_id=$asset_id
                    LIMIT 1
                ")->fetch_assoc();

                if ($existing_asset_map) {
                    $map_id = (int)$existing_asset_map['map_id'];
                    rmm_exec("
                        UPDATE itflow_trmm_asset_map
                        SET
                          itflow_client_id=$itflow_client_id,
                          trmm_agent_id='$trmm_agent_id',
                          trmm_client_id=$trmm_client_id,
                          trmm_site_id=$trmm_site_sql,
                          last_hostname='$hostname',
                          last_serial='$serial',
                          last_os='$os',
                          last_status='$status',
                          last_seen=$last_seen_sql,
                          sync_enabled=1,
                          updated_at=NOW()
                        WHERE map_id=$map_id
                        LIMIT 1
                    ");
                } else {
                    rmm_exec("
                        INSERT INTO itflow_trmm_asset_map
                          (itflow_asset_id, itflow_client_id, trmm_agent_id, trmm_client_id, trmm_site_id,
                           last_hostname, last_serial, last_os, last_status, last_seen, sync_enabled, updated_at)
                        VALUES
                          ($asset_id, $itflow_client_id, '$trmm_agent_id', $trmm_client_id, $trmm_site_sql,
                           '$hostname', '$serial', '$os', '$status', $last_seen_sql, 1, NOW())
                    ");
                }

                rmm_exec("
                    UPDATE itflow_trmm_exclusions
                    SET enabled=0, updated_at=NOW()
                    WHERE exclusion_type IN ('trmm_agent','agent','rmm_agent')
                      AND external_id='$trmm_agent_id'
                ");

                $manual_map_db->commit();
            } catch (Throwable $manual_map_error) {
                $manual_map_db->rollback();
                throw $manual_map_error;
            }

            $message = "Manual agent/device match saved.";
            $active_tab = 'assets';
        } elseif ($action === 'disable_agent_sync') {
            $trmm_agent_id_raw = trim($_POST['trmm_agent_id'] ?? '');
            $hostname_raw = trim($_POST['hostname'] ?? '');
            $reason_raw = trim($_POST['reason'] ?? 'Disabled from RMM UI');

            if ($trmm_agent_id_raw === '') {
                throw new Exception("Missing TacticalRMM agent ID.");
            }

            $trmm_agent_id = rmm_escape($trmm_agent_id_raw);
            $hostname = rmm_escape($hostname_raw ?: $trmm_agent_id_raw);
            $reason = rmm_escape($reason_raw);

            rmm_exec("
                INSERT INTO itflow_trmm_exclusions
                  (exclusion_type, external_id, external_name, reason, enabled, updated_at)
                VALUES
                  ('trmm_agent', '$trmm_agent_id', '$hostname', '$reason', 1, NOW())
                ON DUPLICATE KEY UPDATE
                  external_id=VALUES(external_id),
                  reason=VALUES(reason),
                  enabled=1,
                  updated_at=NOW()
            ");

            rmm_exec("
                UPDATE itflow_trmm_asset_map
                SET sync_enabled=0, updated_at=NOW()
                WHERE trmm_agent_id='$trmm_agent_id'
                LIMIT 1
            ");

            $message = "TacticalRMM agent excluded from ITFlow sync. This does not disable the ITFlow asset or the agent in TacticalRMM.";
            $active_tab = 'assets';
        } elseif ($action === 'enable_agent_sync') {
            $trmm_agent_id_raw = trim($_POST['trmm_agent_id'] ?? '');
            if ($trmm_agent_id_raw === '') {
                throw new Exception("Missing TacticalRMM agent ID.");
            }
            $trmm_agent_id = rmm_escape($trmm_agent_id_raw);

            rmm_exec("
                UPDATE itflow_trmm_exclusions
                SET enabled=0, updated_at=NOW()
                WHERE exclusion_type IN ('trmm_agent','agent','rmm_agent')
                  AND external_id='$trmm_agent_id'
            ");

            $message = "TacticalRMM agent exclusion removed. Run Preview or Full Sync to remap/update it.";
            $active_tab = 'assets';
        }
    }

    $integration = rmm_query("SELECT * FROM itflow_rmm_integrations WHERE provider='tacticalrmm' LIMIT 1")->fetch_assoc();

    $counts = [];
    $count_sql = [
        'Active ITFlow assets' => "SELECT COUNT(*) c FROM assets WHERE asset_archived_at IS NULL",
        'Enabled client mappings' => "SELECT COUNT(*) c FROM itflow_trmm_client_map WHERE enabled=1",
        'Enabled asset mappings' => "SELECT COUNT(*) c FROM itflow_trmm_asset_map WHERE sync_enabled=1",
        'Duplicate TRMM agent IDs' => "SELECT COUNT(*) c FROM (SELECT trmm_agent_id FROM itflow_trmm_asset_map GROUP BY trmm_agent_id HAVING COUNT(*) > 1) x",
        'Duplicate ITFlow asset IDs' => "SELECT COUNT(*) c FROM (SELECT itflow_asset_id FROM itflow_trmm_asset_map GROUP BY itflow_asset_id HAVING COUNT(*) > 1) x",
    ];

    foreach ($count_sql as $label => $sql) {
        $counts[$label] = rmm_query($sql)->fetch_assoc()['c'] ?? 0;
    }

    $client_rows = rmm_query("
        SELECT
          c.client_id,
          c.client_name,
          m.trmm_client_id,
          m.trmm_client_name,
          m.match_type,
          m.enabled,
          m.updated_at
        FROM clients c
        LEFT JOIN itflow_trmm_client_map m ON m.itflow_client_id = c.client_id
        WHERE c.client_archived_at IS NULL
        ORDER BY c.client_name
    ");

    $asset_rows = rmm_query("
        SELECT
          m.itflow_asset_id,
          a.asset_name,
          a.asset_type,
          a.asset_status,
          c.client_name,
          m.trmm_agent_id,
          m.last_hostname,
          m.last_status,
          m.last_seen,
          m.updated_at
        FROM itflow_trmm_asset_map m
        LEFT JOIN assets a ON a.asset_id = m.itflow_asset_id
        LEFT JOIN clients c ON c.client_id = m.itflow_client_id
        WHERE m.sync_enabled=1
        ORDER BY m.updated_at DESC, m.map_id DESC
        LIMIT $asset_limit
    ");

    
    $asset_rows_all = [];
    if ($asset_rows instanceof mysqli_result) {
        while ($asset_row = $asset_rows->fetch_assoc()) {
            $asset_rows_all[] = $asset_row;
        }
    }
$itflow_assets = rmm_query("
        SELECT
          a.asset_id,
          a.asset_name,
          a.asset_type,
          c.client_name
        FROM assets a
        LEFT JOIN clients c ON c.client_id = a.asset_client_id
        WHERE a.asset_archived_at IS NULL
        ORDER BY c.client_name, a.asset_name, a.asset_id
    ");

    $jobs = rmm_query("
        SELECT job_id, job_type, job_status, requested_by, created_at, started_at, finished_at, LEFT(COALESCE(result_summary,''), 4000) result_summary
        FROM itflow_rmm_jobs
        ORDER BY job_id DESC
        LIMIT 75
    ");

    $logs = rmm_query("
        SELECT l.log_id, l.job_id, l.level, l.created_at, LEFT(l.message, 3000) message, j.job_type
        FROM itflow_rmm_job_logs l
        LEFT JOIN itflow_rmm_jobs j ON j.job_id = l.job_id
        ORDER BY l.log_id DESC
        LIMIT 100
    ");

    $exclusions = rmm_query("
        SELECT exclusion_id, exclusion_type, external_id, external_name, reason, enabled, created_at, updated_at
        FROM itflow_trmm_exclusions
        WHERE exclusion_type IN ('trmm_agent','agent','rmm_agent')
        ORDER BY enabled DESC, updated_at DESC, created_at DESC
        LIMIT 200
    ");

    $latest_live_summary = rmm_latest_live_summary();
    $latest_sync_summary = rmm_latest_sync_summary();

} catch (Throwable $e) {
    $error = $e->getMessage();
}

function rmm_tab_class($tab, $active_tab) {
    return $tab === $active_tab ? 'nav-link active' : 'nav-link';
}
?>

<div class="content-header">
  <div class="container-fluid">
    <div class="row mb-2">
      <div class="col-sm-7">
        <h1 class="m-0">RMM Integration</h1>
      </div>
      <div class="col-sm-5">
        <ol class="breadcrumb float-sm-right">
          <li class="breadcrumb-item"><a href="settings_module.php">Settings</a></li>
          <li class="breadcrumb-item"><a href="settings_integrations.php">3rd Party Integrations</a></li>
          <li class="breadcrumb-item active">RMM</li>
        </ol>
      </div>
    </div>
  </div>
</div>

<section class="content">
  <div class="container-fluid">

    <?php if (!empty($message)): ?>
      <div class="alert alert-success"><?= rmm_h($message) ?></div>
    <?php endif; ?>

    <?php if (!empty($error)): ?>
      <div class="alert alert-danger">
        <?= rmm_h($error) ?>
        <?php if (!empty($live_test_output)): ?>
          <pre class="mt-2 mb-0"><?= rmm_h($live_test_output) ?></pre>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <?php if (!empty($live_test_output) && empty($error)): ?>
      <div class="alert alert-success">
        <strong>Live connection test result:</strong>
        <pre class="mt-2 mb-0"><?= rmm_h($live_test_output) ?></pre>
      </div>
    <?php endif; ?>

    <ul class="nav nav-tabs mb-3">
      <li class="nav-item"><a class="<?= rmm_tab_class('settings', $active_tab) ?>" href="?tab=settings">Settings</a></li>
      <li class="nav-item"><a class="<?= rmm_tab_class('clients', $active_tab) ?>" href="?tab=clients">Client Mapping</a></li>
      <li class="nav-item"><a class="<?= rmm_tab_class('sites', $active_tab) ?>" href="?tab=sites">Site / Location Mapping</a></li>
      <li class="nav-item"><a class="<?= rmm_tab_class('assets', $active_tab) ?>" href="?tab=assets">Asset Mapping</a></li>
      <li class="nav-item"><a class="<?= rmm_tab_class('jobs', $active_tab) ?>" href="?tab=jobs">Jobs</a></li>
      <li class="nav-item"><a class="<?= rmm_tab_class('logs', $active_tab) ?>" href="?tab=logs">Logs</a></li>
    </ul>

    <?php if ($active_tab === 'settings'): ?>

      <div class="card mb-3" id="rmm-autocreate-sync-settings-card">
        <div class="card-header bg-dark text-white">
          <h5 class="mb-0">Auto-create & Scheduled Sync</h5>
        </div>
        <div class="card-body">
          <form method="post">
            <input type="hidden" name="action" value="save_autocreate_sync_settings">

            <div class="form-row">
              <div class="form-group col-md-3">
                <label><strong>Scheduled Sync</strong></label>
                <div class="custom-control custom-switch">
                  <input type="checkbox" class="custom-control-input" id="scheduled_sync_enabled" name="scheduled_sync_enabled" value="1" <?= rmm_trmm_bool_setting($mysqli, 'scheduled_sync_enabled', '1') ? 'checked' : '' ?>>
                  <label class="custom-control-label" for="scheduled_sync_enabled">Enabled</label>
                </div>
                <small class="form-text text-muted">The timer wakes every minute and runs only when this interval is due.</small>
              </div>

              <div class="form-group col-md-3">
                <label for="sync_interval_minutes"><strong>Sync Frequency</strong></label>
                <?php $rmm_sync_interval = (int)rmm_trmm_setting_get($mysqli, 'sync_interval_minutes', '5'); ?>
                <select class="form-control" id="sync_interval_minutes" name="sync_interval_minutes">
                  <?php foreach ([1, 2, 5, 10, 15, 30, 60, 120, 240, 720, 1440] as $minutes): ?>
                    <option value="<?= (int)$minutes ?>" <?= $rmm_sync_interval === (int)$minutes ? 'selected' : '' ?>>
                      Every <?= (int)$minutes ?> minute<?= ((int)$minutes === 1) ? '' : 's' ?>
                    </option>
                  <?php endforeach; ?>
                </select>
                <small class="form-text text-muted">Manual sync jobs still run immediately.</small>
              </div>

              <div class="form-group col-md-6">
                <label><strong>Auto-create missing ITFlow records on sync</strong></label>
                <div class="custom-control custom-checkbox">
                  <input type="checkbox" class="custom-control-input" id="auto_create_clients" name="auto_create_clients" value="1" <?= rmm_trmm_bool_setting($mysqli, 'auto_create_clients', '1') ? 'checked' : '' ?>>
                  <label class="custom-control-label" for="auto_create_clients">Create missing ITFlow Clients from TacticalRMM Clients</label>
                </div>
                <div class="custom-control custom-checkbox">
                  <input type="checkbox" class="custom-control-input" id="auto_create_sites" name="auto_create_sites" value="1" <?= rmm_trmm_bool_setting($mysqli, 'auto_create_sites', '1') ? 'checked' : '' ?>>
                  <label class="custom-control-label" for="auto_create_sites">Create missing ITFlow Locations from TacticalRMM Sites</label>
                </div>
                <div class="custom-control custom-checkbox">
                  <input type="checkbox" class="custom-control-input" id="auto_create_assets" name="auto_create_assets" value="1" <?= rmm_trmm_bool_setting($mysqli, 'auto_create_assets', '1') ? 'checked' : '' ?>>
                  <label class="custom-control-label" for="auto_create_assets">Create missing ITFlow Assets from TacticalRMM Agents</label>
                </div>
              </div>
            </div>

            <div class="alert alert-light border mb-3">
              Auto-create never deletes records, never archives duplicates, and never reassigns an already mapped TacticalRMM identity. If exact or fuzzy matching finds an ITFlow record that is already mapped to another TacticalRMM identity, it is skipped and must be handled with manual remapping. If auto-created duplicates need cleanup later, use the mapping dropdowns to repoint the TacticalRMM identity to the surviving ITFlow record, then manually archive the duplicate ITFlow record after review.
            </div>

            <button class="btn btn-primary">Save Auto-create & Sync Settings</button>
          </form>
        </div>
      </div>
      <!-- END rmm-autocreate-sync-settings-card -->

      <div class="card mb-3" id="rmm-deployment-links-card">
        <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
          <h5 class="mb-0">TacticalRMM Deployment Links</h5>
          <span class="badge badge-light">
            <?php
            $rmm_deploy_count = 0;
            $rmm_deploy_count_sql = mysqli_query($mysqli, "SHOW TABLES LIKE 'itflow_trmm_deployment_links'");
            if ($rmm_deploy_count_sql && mysqli_num_rows($rmm_deploy_count_sql) > 0) {
                $rmm_deploy_count_row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT(*) AS c FROM itflow_trmm_deployment_links WHERE active = 1"));
                $rmm_deploy_count = (int)($rmm_deploy_count_row['c'] ?? 0);
            }
            echo (int)$rmm_deploy_count;
            ?> active
          </span>
        </div>
        <div class="card-body">
          <p class="text-muted mb-3">
            These are synced from TacticalRMM <code>/clients/deployments/</code> and mapped to ITFlow clients/locations through the Client and Site mapping tables. Expired links are retained for visibility.
          </p>

          <?php
          $rmm_deploy_table_exists = false;
          $rmm_deploy_table_sql = mysqli_query($mysqli, "SHOW TABLES LIKE 'itflow_trmm_deployment_links'");
          if ($rmm_deploy_table_sql && mysqli_num_rows($rmm_deploy_table_sql) > 0) {
              $rmm_deploy_table_exists = true;
          }
          ?>

          <?php if (!$rmm_deploy_table_exists): ?>
            <div class="alert alert-warning mb-0">Deployment-link table has not been created yet. Run the sync installer or manual sync.</div>
          <?php else: ?>
            <div class="table-responsive">
              <table class="table table-sm table-striped mb-0">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>ITFlow Client</th>
                    <th>ITFlow Location</th>
                    <th>TacticalRMM Client</th>
                    <th>TacticalRMM Site</th>
                    <th>Type / Arch</th>
                    <th>Expires</th>
                    <th>Deployment</th>
                    <th>Last Synced</th>
                  </tr>
                </thead>
                <tbody>
                  <?php
                  $rmm_deploy_sql = mysqli_query($mysqli, "
                    SELECT d.*,
                           c.client_name,
                           l.location_name
                    FROM itflow_trmm_deployment_links d
                    LEFT JOIN clients c ON c.client_id = d.itflow_client_id
                    LEFT JOIN locations l ON l.location_id = d.itflow_location_id
                    WHERE d.active = 1
                    ORDER BY d.expired ASC, d.expires_at IS NULL ASC, d.expires_at ASC, d.trmm_client_name ASC, d.trmm_site_name ASC
                    LIMIT 300
                  ");
                  ?>
                  <?php if (!$rmm_deploy_sql || mysqli_num_rows($rmm_deploy_sql) === 0): ?>
                    <tr>
                      <td colspan="9" class="text-muted">No TacticalRMM deployment links synced yet.</td>
                    </tr>
                  <?php else: ?>
                    <?php while ($dl = mysqli_fetch_assoc($rmm_deploy_sql)): ?>
                      <?php
                      $is_expired = (int)($dl['expired'] ?? 0) === 1;
                      $is_unmapped_location = (int)($dl['itflow_location_id'] ?? 0) <= 0;
                      ?>
                      <tr>
                        <td>
                          <?php if ($is_expired): ?>
                            <span class="badge badge-danger">Expired</span>
                          <?php else: ?>
                            <span class="badge badge-success">Active</span>
                          <?php endif; ?>
                          <?php if ($is_unmapped_location): ?>
                            <span class="badge badge-warning">Location Unmapped</span>
                          <?php endif; ?>
                        </td>
                        <td><?= rmm_h($dl['client_name'] ?: ('ITFlow #' . (int)$dl['itflow_client_id'])) ?></td>
                        <td><?= rmm_h($dl['location_name'] ?: ('TRMM Site #' . (int)$dl['trmm_site_id'])) ?></td>
                        <td><?= rmm_h(($dl['trmm_client_name'] ?? '') . ' #' . (int)$dl['trmm_client_id']) ?></td>
                        <td><?= rmm_h(($dl['trmm_site_name'] ?? '') . ' #' . (int)$dl['trmm_site_id']) ?></td>
                        <td><?= rmm_h(trim(($dl['mon_type'] ?? '') . ' / ' . ($dl['goarch'] ?? ''), ' /')) ?></td>
                        <td><?= rmm_h($dl['expires_at'] ?: 'No expiry') ?></td>
                        <td>
                          <?php if (!empty($dl['deployment_url'])): ?>
                            <a href="<?= rmm_h($dl['deployment_url']) ?>" target="_blank" rel="noopener">Open Link</a>
                          <?php else: ?>
                            <code><?= rmm_h($dl['deployment_uid'] ?? '') ?></code>
                          <?php endif; ?>
                        </td>
                        <td><?= rmm_h($dl['last_synced_at'] ?? '') ?></td>
                      </tr>
                    <?php endwhile; ?>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
          <?php endif; ?>
        </div>
      </div>
      <!-- END rmm-deployment-links-card -->



      <div class="card card-dark">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-tools mr-2"></i>Settings</h3>
        </div>
        <div class="card-body p-0">
          <table class="table table-striped mb-0">
            <tr><th style="width: 260px;">RMM Provider</th><td><select class="form-control" style="max-width: 360px;" disabled><option>TacticalRMM</option></select></td></tr>
            <tr><th>Enabled</th><td><?= !empty($integration['enabled']) ? '<span class="badge badge-success">Yes</span>' : '<span class="badge badge-danger">No</span>' ?></td></tr>
            <tr><th>API URL</th><td><?= rmm_h($integration['api_base'] ?? '') ?></td></tr>
            <tr><th>Token</th><td><span class="badge badge-success">Configured root-only</span> <code>/opt/itflow-trmm-sync/.secrets</code></td></tr>
            <tr><th>Last connection</th><td><?= rmm_h(($integration['last_connection_status'] ?? 'never') . ' ' . ($integration['last_connection_at'] ?? '')) ?></td></tr>
            <tr><th>Last sync</th><td><?= rmm_h(($integration['last_sync_status'] ?? 'never') . ' ' . ($integration['last_sync_at'] ?? '')) ?></td></tr>
          </table>
        </div>
      </div>

      <div class="card card-dark">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-play mr-2"></i>Actions</h3>
        </div>
        <div class="card-body">
          <form method="post" class="d-inline">
            <input type="hidden" name="action" value="test_connection_live">
            <button class="btn btn-success"><i class="fas fa-bolt mr-1"></i>Test Connection Live</button>
          </form>

          <form method="post" class="d-inline ml-1">
            <input type="hidden" name="action" value="client_auto_match">
            <button class="btn btn-secondary">Auto-match All Clients</button>
          </form>

          <form method="post" class="d-inline ml-1">
            <input type="hidden" name="action" value="asset_preview">
            <button class="btn btn-info">Preview Asset Sync</button>
          </form>

          <form method="post" class="d-inline ml-1" onsubmit="return confirm('Run full live TacticalRMM asset sync now?');">
            <input type="hidden" name="action" value="asset_apply">
            <button class="btn btn-sm btn-secondary">Auto-match All Assets</button>
          </form>

          <p class="text-muted mt-3 mb-0">Connection testing runs immediately. Client auto-match, preview, and full sync are queued for the root worker.</p>
        </div>
      </div>

      <div class="row">
        <?php foreach ($counts as $label => $value): ?>
          <div class="col-md">
            <div class="small-box bg-light">
              <div class="inner">
                <h3><?= rmm_h($value) ?></h3>
                <p><?= rmm_h($label) ?></p>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>

      <div class="row">
        <div class="col-md-6">
          <div class="card card-secondary">
            <div class="card-header"><h3 class="card-title">Latest Live Fetch</h3></div>
            <div class="card-body"><pre style="max-height: 260px; overflow:auto; white-space:pre-wrap;"><?= rmm_h($latest_live_summary ?? '') ?></pre></div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="card card-secondary">
            <div class="card-header"><h3 class="card-title">Latest Sync</h3></div>
            <div class="card-body"><pre style="max-height: 260px; overflow:auto; white-space:pre-wrap;"><?= rmm_h($latest_sync_summary ?? '') ?></pre></div>
          </div>
        </div>
      </div>

    <?php elseif ($active_tab === 'clients'): ?>

      <?php
        $client_mapping_counts = [
            'mapped' => 0,
            'disabled' => 0,
            'unmatched' => 0,
        ];

        if (!empty($client_rows) && $client_rows instanceof mysqli_result) {
            $client_rows->data_seek(0);
            while ($cr_count = $client_rows->fetch_assoc()) {
                if (!empty($cr_count['trmm_client_id']) && (string)$cr_count['enabled'] === '1') {
                    $client_mapping_counts['mapped']++;
                } elseif (!empty($cr_count['trmm_client_id'])) {
                    $client_mapping_counts['disabled']++;
                } else {
                    $client_mapping_counts['unmatched']++;
                }
            }
            $client_rows->data_seek(0);
        }
      ?>


      <div class="card card-dark">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-building mr-2"></i>Client Mapping</h3>
          <div class="card-tools">
            <span class="badge badge-success mr-1">Mapped <?= (int)$client_mapping_counts['mapped'] ?></span>
            <span class="badge badge-secondary mr-1">Disabled <?= (int)$client_mapping_counts['disabled'] ?></span>
            <span class="badge badge-warning">Unmatched <?= (int)$client_mapping_counts['unmatched'] ?></span>
          </div>
        </div>
        <div class="card-body">
          <form method="post" class="d-inline">
            <input type="hidden" name="action" value="client_auto_match">
            <button class="btn btn-secondary">Auto-match All Clients</button>
          </form>
          <span class="text-muted ml-2">
            Manual matching uses TacticalRMM clients from the latest live fetch.
            <?php if (!empty($latest_clients_file)): ?>
              Source: <code><?= rmm_h($latest_clients_file) ?></code>
              | Tactical clients loaded: <?= rmm_h(count($trmm_clients)) ?>
            <?php else: ?>
              <span class="text-danger">No live TacticalRMM client list is readable yet. Run Test Connection Live or Preview Asset Sync.</span>
            <?php endif; ?>
          </span>
          <div class="alert alert-light border mt-3 mb-0 py-2">
            <strong>Save Match</strong> sets or changes the permanent ITFlow Client ↔ TacticalRMM Client mapping.
            The dropdown in <strong>Match to TacticalRMM</strong> selects the TacticalRMM Client for the ITFlow Client in that row.
            <strong>Disable Client Mapping</strong> only disables this integration mapping; it does not disable the ITFlow Client and does not disable the TacticalRMM Client.
          </div>
          <input class="form-control form-control-sm mt-3 rmm-client-final-filter" data-target="#rmm-client-table" oninput="window.rmmFinalClientSearch && window.rmmFinalClientSearch()" onkeyup="window.rmmFinalClientSearch && window.rmmFinalClientSearch()" onchange="window.rmmFinalClientSearch && window.rmmFinalClientSearch()" placeholder="Search clients, Tactical IDs, status, match type...">
        </div>
        <div class="card-body table-responsive p-0 rmm-sticky-table-wrap" style="max-height: 720px;">
          <table id="rmm-client-table" class="table table-striped table-sm mb-0 rmm-sortable-table">
            <thead>
              <tr>
                <th data-client-sort-index="0">ITFlow Client <span class="rmm-client-sort-indicator">↕</span></th>
                <th data-client-sort-index="1">TacticalRMM Client <span class="rmm-client-sort-indicator">↕</span></th>
                <th data-client-sort-index="2">Tactical ID <span class="rmm-client-sort-indicator">↕</span></th>
                <th data-client-sort-index="3">Match Type <span class="rmm-client-sort-indicator">↕</span></th>
                <th data-client-sort-index="4">Mapping Status <span class="rmm-client-sort-indicator">↕</span></th>
                <th class="rmm-no-sort" title="Choose the TacticalRMM Client for this ITFlow Client, or disable the mapping.">Match to TacticalRMM</th>
              </tr>
            </thead>
            <tbody>
            <?php if (!empty($client_rows)): ?>
              <?php while ($r = $client_rows->fetch_assoc()): ?>
                <tr data-client-final-search="<?= rmm_h(strtolower(
                  ($r['client_name'] ?? '') . ' ' .
                  ($r['client_id'] ?? '') . ' ' .
                  ($r['trmm_client_name'] ?? '') . ' ' .
                  ($r['trmm_client_id'] ?? '') . ' ' .
                  ($r['match_type'] ?? '') . ' ' .
                  (!empty($r['trmm_client_id']) ? ((string)$r['enabled'] === '1' ? 'mapped' : 'disabled') : 'unmatched')
                )) ?>">
                  <td><?= rmm_h($r['client_name']) ?><br><small class="text-muted">ITFlow <?= rmm_h($r['client_id']) ?></small></td>
                  <td><?= rmm_h($r['trmm_client_name'] ?? '') ?></td>
                  <td><?= rmm_h($r['trmm_client_id'] ?? '') ?></td>
                  <td><?= rmm_h($r['match_type'] ?? 'unmatched') ?></td>
                  <td>
                    <?php if (!empty($r['trmm_client_id']) && (string)$r['enabled'] === '1'): ?>
                      <span class="badge badge-success">Mapped</span>
                    <?php elseif (!empty($r['trmm_client_id'])): ?>
                      <span class="badge badge-warning">Disabled</span>
                    <?php else: ?>
                      <span class="badge badge-warning">Unmatched</span>
                    <?php endif; ?>
                  </td>
                  <td>
                    <form method="post" class="form-inline mb-1">
                      <input type="hidden" name="action" value="manual_client_match_select">
                      <input type="hidden" name="itflow_client_id" value="<?= rmm_h($r['client_id']) ?>">
                      <select class="form-control form-control-sm mr-1" name="trmm_client_select" data-current-label="<?= rmm_h(($r['trmm_client_name'] ?? '') . ' ' . ($r['trmm_client_id'] ?? '')) ?>" style="max-width: 260px;" required>
                        <option value="">Select TacticalRMM client...</option>
                        <?php foreach ($trmm_clients as $tc): ?>
                          <?php
                            $tc_id = $tc['trmm_client_id'] ?? '';
                            $tc_name = $tc['trmm_client_name'] ?? '';
                            if ($tc_id === '' || $tc_name === '') continue;
                            $selected = ((string)$tc_id === (string)($r['trmm_client_id'] ?? '')) ? 'selected' : '';
                          ?>
                          <option value="<?= rmm_h($tc_id . '|' . $tc_name) ?>" <?= $selected ?>>
                            <?= rmm_h($tc_name . ' [' . $tc_id . ']') ?>
                          </option>
                        <?php endforeach; ?>
                      </select>
                      <button class="btn btn-sm btn-secondary">Save Match</button>
                    </form>
                    <?php if (!empty($r['trmm_client_id'])): ?>
                      <form method="post" onsubmit="return confirm('Disable this ITFlow ↔ TacticalRMM client mapping? This does not disable the ITFlow client and does not disable the client in TacticalRMM. Agents under this Tactical client may become unmatched until the mapping is re-enabled or changed.');">
                        <input type="hidden" name="action" value="disable_client_match">
                        <input type="hidden" name="itflow_client_id" value="<?= rmm_h($r['client_id']) ?>">
                        <button class="btn btn-sm btn-danger" title="Disable this ITFlow ↔ TacticalRMM mapping only">Disable Client Mapping</button>
                      </form>
                    <?php endif; ?>
                  </td>
                </tr>
              <?php endwhile; ?>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>


    <?php elseif ($active_tab === 'sites'): ?>

      <?php
        $latest_site_preview_file = '';
        $site_preview_files = glob('/opt/itflow-trmm-sync/reports/live-*/trmm_site_location_preview.csv') ?: [];
        if (!empty($site_preview_files)) {
            usort($site_preview_files, function ($a, $b) { return filemtime($b) <=> filemtime($a); });
            $latest_site_preview_file = $site_preview_files[0];
        }

        $site_location_rows = [];
        if ($latest_site_preview_file && is_readable($latest_site_preview_file)) {
            $site_location_rows = rmm_parse_csv_assoc($latest_site_preview_file);
        }

        $site_map_by_site_id = [];
        $site_map_q = $mysqli->query("
            SELECT
                m.*,
                l.location_name,
                l.location_archived_at,
                c.client_name
            FROM itflow_trmm_site_map m
            LEFT JOIN locations l ON l.location_id = m.itflow_location_id
            LEFT JOIN clients c ON c.client_id = m.itflow_client_id
            ORDER BY m.trmm_site_name
        ");
        if ($site_map_q) {
            while ($sm = $site_map_q->fetch_assoc()) {
                $site_map_by_site_id[(string)$sm['trmm_site_id']] = $sm;
            }
        }


        $client_name_by_id = [];
        $clients_for_site_tab_q = $mysqli->query("
            SELECT client_id, client_name
            FROM clients
            WHERE client_archived_at IS NULL
            ORDER BY client_name
        ");
        if ($clients_for_site_tab_q) {
            while ($cst = $clients_for_site_tab_q->fetch_assoc()) {
                $client_name_by_id[(string)$cst['client_id']] = $cst['client_name'];
            }
        }


        $trmm_sites_by_client = [];
        foreach ($site_location_rows as $site_option_row) {
            $option_client_id = (string)($site_option_row['trmm_client_id'] ?? '');
            $option_site_id = (string)($site_option_row['trmm_site_id'] ?? '');
            if ($option_client_id === '' || $option_site_id === '') {
                continue;
            }
            $trmm_sites_by_client[$option_client_id][] = $site_option_row;
        }

        $locations_by_client = [];
        $locations_q = $mysqli->query("
            SELECT
                l.location_id,
                l.location_name,
                l.location_client_id,
                c.client_name
            FROM locations l
            LEFT JOIN clients c ON c.client_id = l.location_client_id
            WHERE l.location_archived_at IS NULL
            ORDER BY c.client_name, l.location_name
        ");
        if ($locations_q) {
            while ($loc = $locations_q->fetch_assoc()) {
                $locations_by_client[(string)$loc['location_client_id']][] = $loc;
            }
        }

        $site_counts = [
            'mapped' => 0,
            'disabled' => 0,
            'auto_match_candidate' => 0,
            'unmatched' => 0,
            'client_not_mapped' => 0,
        ];

        foreach ($site_location_rows as $sr_count) {
            $sid_count = (string)($sr_count['trmm_site_id'] ?? '');
            if ($sid_count !== '' && isset($site_map_by_site_id[$sid_count])) {
                $site_counts[((int)$site_map_by_site_id[$sid_count]['enabled'] === 1) ? 'mapped' : 'disabled']++;
            } else {
                $status_count = $sr_count['mapping_status'] ?? 'unmatched';
                if (!isset($site_counts[$status_count])) {
                    $site_counts[$status_count] = 0;
                }
                $site_counts[$status_count]++;
            }
        }
      ?>

      <div class="card card-dark">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-map-marker-alt mr-2"></i>Site / Location Mapping</h3>
          <div class="card-tools">
            <span class="badge badge-success mr-1">Mapped <?= (int)$site_counts['mapped'] ?></span>
            <span class="badge badge-secondary mr-1">Disabled <?= (int)$site_counts['disabled'] ?></span>
            <span class="badge badge-info mr-1">Exact Candidates <?= (int)$site_counts['auto_match_candidate'] ?></span>
            <span class="badge badge-warning mr-1">Unmatched <?= (int)$site_counts['unmatched'] ?></span>
            <span class="badge badge-danger">Client Not Mapped <?= (int)$site_counts['client_not_mapped'] ?></span>
          </div>
        </div>

        <div class="card-body">
          <div class="mb-2">
            <form method="post" class="d-inline-block mr-2 mb-2" onsubmit="return confirm('Auto-match all exact ITFlow Location to TacticalRMM Site candidates?');">
              <input type="hidden" name="action" value="auto_save_site_location_candidates">
              <button class="btn btn-sm btn-secondary">Auto-match All Locations</button>
            </form>
            <span class="text-muted">
              Manual matching uses TacticalRMM sites from the latest live fetch.
              Source: <code><?= rmm_h($latest_site_preview_file ?: 'No site/location preview found. Run Preview/Sync first.') ?></code>
              | Tactical sites loaded: <?= (int)count($site_location_rows) ?>
            </span>
          </div>

          <div class="alert alert-light border">
            <strong>Save Match</strong> sets or changes the permanent ITFlow Location ↔ TacticalRMM Site mapping.
            The dropdown in <strong>Match to TacticalRMM</strong> selects the TacticalRMM Site for the ITFlow Location in that row.
            <strong>Disable Location Mapping</strong> only disables this integration mapping; it does not disable the ITFlow Location and does not disable the TacticalRMM Site.
          </div>

          <input class="form-control form-control-sm rmm-table-filter" data-target="#rmm-site-location-table" placeholder="Search locations, TacticalRMM sites, Tactical IDs, status, match type...">
        </div>

        <div class="card-body table-responsive p-0 rmm-sticky-table-wrap" style="max-height: 760px;">
          <table id="rmm-site-location-table" class="table table-striped table-sm mb-0 rmm-sortable-table">
            <thead>
              <tr>
                <th data-sort-key="itflow_location">ITFlow Location <span class="rmm-sort-indicator">↕</span></th>
                <th data-sort-key="itflow_client">ITFlow Client <span class="rmm-sort-indicator">↕</span></th>
                <th data-sort-key="trmm_site">TacticalRMM Site <span class="rmm-sort-indicator">↕</span></th>
                <th data-sort-key="trmm_client">TacticalRMM Client <span class="rmm-sort-indicator">↕</span></th>
                <th data-sort-key="trmm_site_id">Tactical ID <span class="rmm-sort-indicator">↕</span></th>
                <th data-sort-key="match_type">Match Type <span class="rmm-sort-indicator">↕</span></th>
                <th data-sort-key="mapping_status">Mapping Status <span class="rmm-sort-indicator">↕</span></th>
                <th class="rmm-no-sort" title="Choose the TacticalRMM Site for this ITFlow Location, or disable the mapping.">Match to TacticalRMM</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($site_location_rows as $sr): ?>
              <?php
                $trmm_site_id = (string)($sr['trmm_site_id'] ?? '');
                $trmm_client_id = (string)($sr['trmm_client_id'] ?? '');
                $site_map = ($trmm_site_id !== '' && isset($site_map_by_site_id[$trmm_site_id])) ? $site_map_by_site_id[$trmm_site_id] : null;

                $mapping_status = $sr['mapping_status'] ?? 'unmatched';
                $mapping_status_label = [
                    'mapped' => 'Mapped',
                    'disabled' => 'Disabled',
                    'auto_match_candidate' => 'Exact Candidate',
                    'client_not_mapped' => 'Client Not Mapped',
                    'unmatched' => 'Unmatched',
                ][$mapping_status] ?? $mapping_status;

                $badge_class = [
                    'mapped' => 'badge-success',
                    'disabled' => 'badge-secondary',
                    'auto_match_candidate' => 'badge-info',
                    'client_not_mapped' => 'badge-danger',
                    'unmatched' => 'badge-warning',
                ][$mapping_status] ?? 'badge-secondary';

                $itflow_client_id = (string)($sr['itflow_client_id'] ?? '');
                $itflow_location_id = (string)($sr['itflow_location_id'] ?? '');
                $itflow_location_name = (string)($sr['itflow_location_name'] ?? '');
                $match_type = (string)($sr['match_type'] ?? '');

                if ($site_map) {
                    $mapping_status = ((int)$site_map['enabled'] === 1) ? 'mapped' : 'disabled';
                    $mapping_status_label = ((int)$site_map['enabled'] === 1) ? 'Mapped' : 'Disabled';
                    $badge_class = ((int)$site_map['enabled'] === 1) ? 'badge-success' : 'badge-secondary';
                    $itflow_client_id = (string)$site_map['itflow_client_id'];
                    $itflow_location_id = (string)$site_map['itflow_location_id'];
                    $itflow_location_name = (string)($site_map['location_name'] ?? '');
                    $match_type = (string)($site_map['match_type'] ?? 'existing');
                }

                $itflow_client_name = '';
                if ($site_map && !empty($site_map['client_name'])) {
                    $itflow_client_name = (string)$site_map['client_name'];
                } elseif ($itflow_client_id !== '' && isset($client_name_by_id[$itflow_client_id])) {
                    $itflow_client_name = (string)$client_name_by_id[$itflow_client_id];
                } elseif ($itflow_client_id !== '') {
                    $itflow_client_name = 'ITFlow ' . $itflow_client_id;
                }

                $client_locations = $locations_by_client[$itflow_client_id] ?? [];
                $trmm_site_options = $trmm_sites_by_client[$trmm_client_id] ?? [];

                $filter_text = strtolower(
                    $mapping_status_label . ' ' .
                    ($sr['trmm_client_name'] ?? '') . ' ' .
                    ($sr['trmm_site_name'] ?? '') . ' ' .
                    $itflow_location_name . ' ' .
                    $itflow_client_name . ' ' .
                    $match_type . ' ' .
                    $trmm_site_id
                );
              ?>
              <tr
                data-filter="<?= rmm_h($filter_text) ?>"
                data-sort-mapping_status="<?= rmm_h($mapping_status) ?>"
                data-sort-itflow_client="<?= rmm_h(strtolower($itflow_client_name)) ?>"
                data-sort-itflow_location="<?= rmm_h(strtolower($itflow_location_name)) ?>"
                data-sort-trmm_client="<?= rmm_h(strtolower($sr['trmm_client_name'] ?? '')) ?>"
                data-sort-trmm_site="<?= rmm_h(strtolower($sr['trmm_site_name'] ?? '')) ?>"
                data-sort-trmm_site_id="<?= rmm_h(strtolower($trmm_site_id)) ?>"
                data-sort-match_type="<?= rmm_h(strtolower($match_type)) ?>"
              >
                <td>
                  <?= rmm_h($itflow_location_name ?: 'No ITFlow Location') ?>
                  <?php if (!empty($itflow_location_id)): ?>
                    <br><small class="text-muted">Location <?= rmm_h($itflow_location_id) ?></small>
                  <?php else: ?>
                    <br><small class="text-muted">Create or select a location</small>
                  <?php endif; ?>
                </td>
                <td>
                  <?= rmm_h($itflow_client_name) ?>
                  <?php if (!empty($itflow_client_id)): ?>
                    <br><small class="text-muted">ITFlow <?= rmm_h($itflow_client_id) ?></small>
                  <?php endif; ?>
                </td>
                <td><?= rmm_h($sr['trmm_site_name'] ?? '') ?></td>
                <td><?= rmm_h($sr['trmm_client_name'] ?? '') ?><br><small class="text-muted">TRMM <?= rmm_h($trmm_client_id) ?></small></td>
                <td><code><?= rmm_h($trmm_site_id) ?></code></td>
                <td><?= rmm_h($match_type ?: ($sr['recommended_action'] ?? '')) ?></td>
                <td><span class="badge <?= rmm_h($badge_class) ?>"><?= rmm_h($mapping_status_label) ?></span></td>
                <td>
                  <?php if ($mapping_status === 'client_not_mapped'): ?>
                    <a href="?tab=clients" class="btn btn-sm btn-danger">Map Client First</a>
                  <?php else: ?>
                    <?php if (!empty($itflow_location_id)): ?>
                      <form method="post" class="form-inline mb-1" onsubmit="return confirm('Save this ITFlow Location to TacticalRMM Site mapping?');">
                        <input type="hidden" name="action" value="manual_site_location_match">
                        <input type="hidden" name="itflow_location_id" value="<?= rmm_h($itflow_location_id) ?>">
                        <select class="form-control form-control-sm mr-1 mb-1" name="trmm_site_select" style="max-width: 360px;" required>
                          <option value="">Select TacticalRMM site...</option>
                          <?php foreach ($trmm_site_options as $site_option): ?>
                            <?php
                              $site_option_payload = base64_encode(json_encode([
                                  'trmm_site_id' => $site_option['trmm_site_id'] ?? '',
                                  'trmm_client_id' => $site_option['trmm_client_id'] ?? '',
                                  'trmm_site_name' => $site_option['trmm_site_name'] ?? '',
                              ]));
                            ?>
                            <option value="<?= rmm_h($site_option_payload) ?>" <?= ((string)($site_option['trmm_site_id'] ?? '') === (string)$trmm_site_id) ? 'selected' : '' ?>>
                              <?= rmm_h(($site_option['trmm_site_name'] ?? 'Unnamed Site') . ' [' . ($site_option['trmm_site_id'] ?? '') . ']') ?>
                            </option>
                          <?php endforeach; ?>
                        </select>
                        <button class="btn btn-sm btn-secondary mb-1">Save Match</button>
                      </form>
                    <?php endif; ?>

                    <?php if (empty($itflow_location_id) && ($mapping_status === 'unmatched' || $mapping_status === 'auto_match_candidate')): ?>
                      <form method="post" class="d-inline mr-1" onsubmit="return confirm('Create a new ITFlow Location with this TRMM Site name and save the mapping?');">
                        <input type="hidden" name="action" value="create_location_and_match_site">
                        <input type="hidden" name="trmm_site_id" value="<?= rmm_h($trmm_site_id) ?>">
                        <input type="hidden" name="trmm_client_id" value="<?= rmm_h($trmm_client_id) ?>">
                        <input type="hidden" name="trmm_site_name" value="<?= rmm_h($sr['trmm_site_name'] ?? '') ?>">
                        <button class="btn btn-sm btn-secondary mb-1">Create Location & Save</button>
                      </form>
                    <?php endif; ?>

                    <div class="mt-1">
                      <?php if ($site_map && (int)$site_map['enabled'] === 1): ?>
                        <form method="post" class="d-inline" onsubmit="return confirm('Disable this Location Mapping? This only stops this TacticalRMM Site from being mapped to this ITFlow Location; it does not disable the ITFlow Location and does not disable the TacticalRMM Site.');">
                          <input type="hidden" name="action" value="disable_site_location_mapping">
                          <input type="hidden" name="trmm_site_id" value="<?= rmm_h($trmm_site_id) ?>">
                          <button class="btn btn-sm btn-danger mb-1" title="Disable this mapping only; this does not disable the ITFlow Location and does not disable the TacticalRMM Site">Disable Location Mapping</button>
                        </form>
                      <?php elseif ($site_map): ?>
                        <form method="post" class="d-inline" onsubmit="return confirm('Enable this Location Mapping?');">
                          <input type="hidden" name="action" value="enable_site_location_mapping">
                          <input type="hidden" name="trmm_site_id" value="<?= rmm_h($trmm_site_id) ?>">
                          <button class="btn btn-sm btn-secondary mb-1" title="Enable this ITFlow Location to TacticalRMM Site mapping">Enable Location Mapping</button>
                        </form>
                      <?php elseif (!empty($itflow_location_id) && !empty($trmm_site_id)): ?>
                        <form method="post" class="d-inline" onsubmit="return confirm('Disable this Location Mapping? This only stops this TacticalRMM Site from being mapped to this ITFlow Location; it does not disable the ITFlow Location and does not disable the TacticalRMM Site.');">
                          <input type="hidden" name="action" value="disable_site_location_mapping">
                          <input type="hidden" name="trmm_site_id" value="<?= rmm_h($trmm_site_id) ?>">
                          <input type="hidden" name="trmm_client_id" value="<?= rmm_h($trmm_client_id) ?>">
                          <input type="hidden" name="trmm_site_name" value="<?= rmm_h($sr['trmm_site_name'] ?? '') ?>">
                          <input type="hidden" name="itflow_location_id" value="<?= rmm_h($itflow_location_id) ?>">
                          <button class="btn btn-sm btn-danger mb-1" title="Disable this mapping only; this does not disable the ITFlow Location and does not disable the TacticalRMM Site">Disable Location Mapping</button>
                        </form>
                      <?php else: ?>
                        <button type="button" class="btn btn-sm btn-danger mb-1" disabled title="Create or select an ITFlow Location before disabling this mapping">Disable Location Mapping</button>
                      <?php endif; ?>
                    </div>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>


    <?php elseif ($active_tab === 'assets'): ?>

      <?php
        $asset_mapping_counts = [
            'mapped' => 0,
            'disabled' => 0,
            'conflict' => 0,
            'unmatched_client' => 0,
        ];

        foreach (($asset_rows_all ?? []) as $arc) {
            if (((int)($arc['sync_enabled'] ?? 1)) === 1) {
                $asset_mapping_counts['mapped']++;
            } else {
                $asset_mapping_counts['disabled']++;
            }
        }

        foreach (($asset_conflicts ?? []) as $acc) {
            if (($acc['reason'] ?? '') === 'client_not_mapped_or_excluded') {
                $asset_mapping_counts['unmatched_client']++;
            } else {
                $asset_mapping_counts['conflict']++;
            }
        }
      ?>


      <div class="card card-dark rmm-asset-card">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-desktop mr-2"></i>Asset Mapping</h3>
          <div class="card-tools">
            <span class="badge badge-success mr-1">Mapped <?= (int)$asset_mapping_counts['mapped'] ?></span>
            <span class="badge badge-secondary mr-1">Disabled <?= (int)$asset_mapping_counts['disabled'] ?></span>
            <span class="badge badge-warning mr-1">Conflicts <?= (int)$asset_mapping_counts['conflict'] ?></span>
            <span class="badge badge-danger">Client Not Mapped <?= (int)$asset_mapping_counts['unmatched_client'] ?></span>
          </div>
        </div>
        <div class="card-body">
          <div class="mb-2">
            <form method="post" class="d-inline-block mr-2 mb-2" onsubmit="return confirm('Auto-match all eligible TacticalRMM agents to ITFlow assets and apply updates now?');">
              <input type="hidden" name="action" value="asset_apply">
              <button class="btn btn-secondary">Auto-match All Assets</button>
            </form>
<span class="text-muted">
              Manual matching uses TacticalRMM agents from the latest live fetch.
              Showing latest <?= (int)$asset_row_limit ?> mapped RMM assets.
              Permanent identity is <code>trmm_agent_id → asset_id</code>.
            </span>
          </div>

          <div class="alert alert-light border mt-3 mb-0 py-2">
            <strong>Save Match</strong> sets or changes the permanent ITFlow Asset ↔ TacticalRMM Agent mapping.
            The dropdown in <strong>Match to TacticalRMM</strong> selects the TacticalRMM Agent for the ITFlow Asset in that row.
            <strong>Disable Asset Mapping</strong> only disables this integration mapping; it does not disable the ITFlow Asset and does not disable the TacticalRMM Agent.
          </div>

          <div class="form-inline mt-3">
            <label class="mr-2 mb-2"><strong>Rows:</strong></label>
            <select id="rmm-asset-row-limit" class="form-control form-control-sm mr-2 mb-2">
              <?php foreach ([50, 100, 200, 500, 1000] as $limit_opt): ?>
                <option value="<?= (int)$limit_opt ?>" <?= ((int)$asset_row_limit === (int)$limit_opt) ? 'selected' : '' ?>><?= (int)$limit_opt ?></option>
              <?php endforeach; ?>
            </select>
            <small class="text-muted mb-2">Lower row counts keep this split-table UI responsive.</small>
          </div>

          <input class="form-control form-control-sm rmm-table-filter rmm-asset-split-filter mt-3" data-target="#rmm-asset-split-wrap" placeholder="Search ITFlow assets, ITFlow clients, TacticalRMM hostnames, Tactical IDs, status, actions...">
        </div>

        <div id="rmm-asset-split-wrap" class="card-body p-0 rmm-asset-split-wrap" style="max-height: 720px;">
          <div id="rmm-asset-left-pane" class="rmm-asset-left-pane">
            <table id="rmm-asset-left-table" class="table table-striped table-sm mb-0 rmm-asset-split-table">
              <thead>
                <tr>
                  <th data-sort-key="asset">ITFlow Asset <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="client">ITFlow Client <span class="rmm-sort-indicator">↕</span></th>
                </tr>
              </thead>
              <tbody>
              <?php foreach (($asset_rows_all ?? []) as $idx => $r): ?>
                <?php
                  $row_status = strtolower($r['last_status'] ?: $r['asset_status']);
                  $row_key = 'assetrow-' . (int)$idx . '-' . (int)$r['itflow_asset_id'];
                  $filter_text = strtolower(
                    ($r['asset_name'] ?? '') . ' ' .
                    ($r['asset_type'] ?? '') . ' ' .
                    ($r['client_name'] ?? '') . ' ' .
                    ($r['last_hostname'] ?? '') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'description') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'logged_username') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'trmm_site_name_raw') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'make_model') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'serial_number_raw') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'operating_system') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'local_ips') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'public_ip') . ' ' .
                    ($r['trmm_agent_id'] ?? '') . ' ' .
                    ($r['last_status'] ?? '') . ' ' .
                    ($r['asset_status'] ?? '') . ' ' .
                    ($r['last_seen'] ?? '') . ' ' .
                    ($r['updated_at'] ?? '')
                  );
                ?>
                <tr
                  data-row-key="<?= rmm_h($row_key) ?>"
                  data-rmm-status="<?= rmm_h($row_status) ?>"
                  data-filter="<?= rmm_h($filter_text) ?>"
                  data-sort-asset="<?= rmm_h(strtolower($r['asset_name'] ?? '')) ?>"
                  data-sort-client="<?= rmm_h(strtolower($r['client_name'] ?? '')) ?>"
                  data-sort-hostname="<?= rmm_h(strtolower($r['last_hostname'] ?? '')) ?>"
                  data-sort-description="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'description'))) ?>"
                  data-sort-user="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'logged_username'))) ?>"
                  data-sort-site="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'trmm_site_name_raw'))) ?>"
                  data-sort-makemodel="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'make_model'))) ?>"
                  data-sort-serial="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'serial_number_raw'))) ?>"
                  data-sort-os="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'operating_system'))) ?>"
                  data-sort-localip="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'local_ips'))) ?>"
                  data-sort-publicip="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'public_ip'))) ?>"
                  data-sort-agent="<?= rmm_h(strtolower($r['trmm_agent_id'] ?? '')) ?>"
                  data-sort-status="<?= rmm_h(strtolower($r['last_status'] ?: $r['asset_status'])) ?>"
                  data-sort-mapping_status="<?= (((int)($r['sync_enabled'] ?? 1)) === 1) ? 'mapped' : 'disabled' ?>"
                  data-sort-lastseen="<?= rmm_h($r['last_seen'] ?? '') ?>"
                  data-sort-updated="<?= rmm_h($r['updated_at'] ?? '') ?>"
                >
                  <td class="rmm-split-asset-cell">
                    <a href="<?= rmm_h(rmm_asset_url($r['itflow_asset_id'])) ?>" target="_blank"><?= rmm_h($r['asset_name']) ?></a>
                    <br><small class="text-muted">Asset <?= rmm_h($r['itflow_asset_id']) ?> / <?= rmm_h($r['asset_type']) ?></small>
                  </td>
                  <td class="rmm-split-client-cell"><span class="rmm-cell-clip"><?= rmm_h($r['client_name']) ?></span></td>
                </tr>
              <?php endforeach; ?>
              
              <?php foreach (($asset_conflicts ?? []) as $cidx => $c): ?>
                <?php
                  $agent_id = $c['trmm_agent_id'] ?? '';
                  if ($agent_id === '') {
                      continue;
                  }

                  $agent = $trmm_agents_by_id[$agent_id] ?? [];
                  $reason = $c['reason'] ?? '';
                  $hostname = $c['hostname'] ?? ($agent['hostname'] ?? '');
                  $trmm_client_name = $c['trmm_client_name'] ?? ($agent['trmm_client_name'] ?? '');
                  $mapping_status_label = ($reason === 'client_not_mapped_or_excluded') ? 'Unmatched Client' : 'Conflict';
                  $mapping_status_key = strtolower(str_replace(' ', '_', $mapping_status_label));
                  $trmm_status = strtolower($agent['status'] ?? ($c['status'] ?? 'unknown'));
                  $row_key = 'assetconflict-' . (int)$cidx . '-' . preg_replace('/[^A-Za-z0-9_-]/', '_', (string)$agent_id);
                  $site_name = ($agent['trmm_site_name_raw'] ?? '') ?: ($agent['trmm_site_name'] ?? ($agent['site_name'] ?? ''));
                  $serial = $agent['serial_number_raw'] ?? ($agent['serial_number'] ?? '');
                  $last_seen = $agent['last_seen'] ?? '';
                  $filter_text = strtolower(
                    $mapping_status_label . ' ' .
                    $reason . ' ' .
                    $hostname . ' ' .
                    $trmm_client_name . ' ' .
                    ($agent['description'] ?? '') . ' ' .
                    ($agent['logged_username'] ?? '') . ' ' .
                    $site_name . ' ' .
                    ($agent['make_model'] ?? '') . ' ' .
                    $serial . ' ' .
                    ($agent['operating_system'] ?? '') . ' ' .
                    ($agent['local_ips'] ?? '') . ' ' .
                    ($agent['public_ip'] ?? '') . ' ' .
                    $agent_id
                  );
                ?>
                <tr
                  class="rmm-unified-conflict-left-row"
                  data-row-key="<?= rmm_h($row_key) ?>"
                  data-rmm-status="<?= rmm_h($trmm_status) ?>"
                  data-filter="<?= rmm_h($filter_text) ?>"
                  data-sort-asset="<?= rmm_h(strtolower($hostname ?: $agent_id)) ?>"
                  data-sort-client="<?= rmm_h(strtolower($trmm_client_name)) ?>"
                  data-sort-hostname="<?= rmm_h(strtolower($hostname)) ?>"
                  data-sort-description="<?= rmm_h(strtolower($agent['description'] ?? '')) ?>"
                  data-sort-user="<?= rmm_h(strtolower($agent['logged_username'] ?? '')) ?>"
                  data-sort-site="<?= rmm_h(strtolower($site_name)) ?>"
                  data-sort-makemodel="<?= rmm_h(strtolower($agent['make_model'] ?? '')) ?>"
                  data-sort-serial="<?= rmm_h(strtolower($serial)) ?>"
                  data-sort-os="<?= rmm_h(strtolower($agent['operating_system'] ?? '')) ?>"
                  data-sort-localip="<?= rmm_h(strtolower($agent['local_ips'] ?? '')) ?>"
                  data-sort-publicip="<?= rmm_h(strtolower($agent['public_ip'] ?? '')) ?>"
                  data-sort-agent="<?= rmm_h(strtolower($agent_id)) ?>"
                  data-sort-mapping_status="<?= rmm_h($mapping_status_key) ?>"
                  data-sort-status="<?= rmm_h($trmm_status) ?>"
                  data-sort-lastseen="<?= rmm_h(strtolower($last_seen)) ?>"
                  data-sort-updated=""
                >
                  <td>
                    <span class="text-danger font-weight-bold"><?= rmm_h($hostname ?: 'Unmapped TacticalRMM Agent') ?></span>
                    <br>
                    <small class="text-muted"><?= rmm_h($mapping_status_label) ?> / <?= rmm_h($reason ?: 'Needs review') ?></small>
                  </td>
                  <td>
                    <?= rmm_h($trmm_client_name ?: 'No mapped ITFlow client') ?>
                    <?php if (!empty($c['trmm_client_id'] ?? ($agent['trmm_client_id'] ?? ''))): ?>
                      <br><small class="text-muted">TRMM <?= rmm_h($c['trmm_client_id'] ?? ($agent['trmm_client_id'] ?? '')) ?></small>
                    <?php endif; ?>
                  </td>
                </tr>
              <?php endforeach; ?>

</tbody>
            </table>
          </div>

          <div id="rmm-asset-right-pane" class="rmm-asset-right-pane">
            <table id="rmm-asset-right-table" class="table table-striped table-sm mb-0 rmm-asset-split-table">
              <thead>
                <tr>
                  <th data-sort-key="hostname">TacticalRMM Hostname <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="description">TacticalRMM Description <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="user">Logged User <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="site">TacticalRMM Site <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="makemodel">Make / Model <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="serial">Serial <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="os">OS <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="localip">Local IP <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="publicip">Public IP <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="agent">Tactical ID <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="mapping_status">Mapping Status <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="status">TacticalRMM Status <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="lastseen">Last Seen <span class="rmm-sort-indicator">↕</span></th>
                  <th data-sort-key="updated">Updated <span class="rmm-sort-indicator">↕</span></th>
                  <th class="rmm-no-sort" title="Choose the TacticalRMM Agent for this ITFlow Asset, or disable the mapping.">Match to TacticalRMM</th>
                </tr>
              </thead>
              <tbody>
              <?php foreach (($asset_rows_all ?? []) as $idx => $r): ?>
                <?php
                  $row_status = strtolower($r['last_status'] ?: $r['asset_status']);
                  $row_key = 'assetrow-' . (int)$idx . '-' . (int)$r['itflow_asset_id'];
                  $filter_text = strtolower(
                    ($r['asset_name'] ?? '') . ' ' .
                    ($r['asset_type'] ?? '') . ' ' .
                    ($r['client_name'] ?? '') . ' ' .
                    ($r['last_hostname'] ?? '') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'description') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'logged_username') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'trmm_site_name_raw') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'make_model') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'serial_number_raw') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'operating_system') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'local_ips') . ' ' .
                    rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'public_ip') . ' ' .
                    ($r['trmm_agent_id'] ?? '') . ' ' .
                    ($r['last_status'] ?? '') . ' ' .
                    ($r['asset_status'] ?? '') . ' ' .
                    ($r['last_seen'] ?? '') . ' ' .
                    ($r['updated_at'] ?? '')
                  );
                ?>
                <tr
                  data-row-key="<?= rmm_h($row_key) ?>"
                  data-rmm-status="<?= rmm_h($row_status) ?>"
                  data-filter="<?= rmm_h($filter_text) ?>"
                  data-sort-asset="<?= rmm_h(strtolower($r['asset_name'] ?? '')) ?>"
                  data-sort-client="<?= rmm_h(strtolower($r['client_name'] ?? '')) ?>"
                  data-sort-hostname="<?= rmm_h(strtolower($r['last_hostname'] ?? '')) ?>"
                  data-sort-description="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'description'))) ?>"
                  data-sort-user="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'logged_username'))) ?>"
                  data-sort-site="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'trmm_site_name_raw'))) ?>"
                  data-sort-makemodel="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'make_model'))) ?>"
                  data-sort-serial="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'serial_number_raw'))) ?>"
                  data-sort-os="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'operating_system'))) ?>"
                  data-sort-localip="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'local_ips'))) ?>"
                  data-sort-publicip="<?= rmm_h(strtolower(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'public_ip'))) ?>"
                  data-sort-agent="<?= rmm_h(strtolower($r['trmm_agent_id'] ?? '')) ?>"
                  data-sort-status="<?= rmm_h(strtolower($r['last_status'] ?: $r['asset_status'])) ?>"
                  data-sort-mapping_status="<?= (((int)($r['sync_enabled'] ?? 1)) === 1) ? 'mapped' : 'disabled' ?>"
                  data-sort-lastseen="<?= rmm_h($r['last_seen'] ?? '') ?>"
                  data-sort-updated="<?= rmm_h($r['updated_at'] ?? '') ?>"
                >
                  <td><span class="rmm-cell-clip"><?= rmm_h($r['last_hostname']) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'description')) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'logged_username')) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'trmm_site_name_raw') ?: rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'trmm_site_name')) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'make_model')) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'serial_number_raw') ?: $r['last_serial']) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'operating_system') ?: $r['last_os']) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'local_ips')) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h(rmm_agent_extra($trmm_agents_by_id, $r['trmm_agent_id'] ?? '', 'public_ip')) ?></span></td>
                  <td><code class="rmm-cell-clip"><?= rmm_h($r['trmm_agent_id']) ?></code></td>
                  <td>
                    <?php $rmm_asset_mapping_enabled = (((int)($r['sync_enabled'] ?? 1)) === 1); ?>
                    <span class="badge <?= $rmm_asset_mapping_enabled ? 'badge-success' : 'badge-secondary' ?> rmm-asset-mapping-status-badge">
                      <?= $rmm_asset_mapping_enabled ? 'Mapped' : 'Disabled' ?>
                    </span>
                  </td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($r['last_status'] ?: $r['asset_status']) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($r['last_seen']) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($r['updated_at']) ?></span></td>
                  <td class="rmm-split-actions-cell">
                    <form method="post" class="rmm-top-asset-linebased-fixmatch-form mb-1" onsubmit="return confirm('Change the TacticalRMM agent permanently mapped to this ITFlow asset?');">
                      <input type="hidden" name="action" value="manual_agent_match_select">
                      <input type="hidden" name="itflow_asset_id" value="<?= rmm_h($r['itflow_asset_id']) ?>">
                      <select
                        name="trmm_agent_id"
                        class="form-control form-control-sm rmm-top-asset-linebased-agent-select mb-1"
                        required
                        data-current-agent-id="<?= rmm_h($r['trmm_agent_id']) ?>"
                      >
                        <option value="<?= rmm_h($r['trmm_agent_id']) ?>" selected>
                          <?= rmm_h(trim(($r['last_hostname'] ?: $r['asset_name'] ?: 'Current TacticalRMM agent') . ' [' . $r['trmm_agent_id'] . ']')) ?>
                        </option>
                      </select>
                      <button type="submit" class="btn btn-sm btn-secondary rmm-top-asset-linebased-save">Save Match</button>
                    </form>

                    <form method="post" class="d-inline" onsubmit="return confirm('Disable this asset mapping in ITFlow sync? This does not disable the ITFlow asset and does not disable the TacticalRMM agent.');">
                      <input type="hidden" name="action" value="disable_agent_sync">
                      <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($r['trmm_agent_id']) ?>">
                      <input type="hidden" name="hostname" value="<?= rmm_h($r['last_hostname']) ?>">
                      <input type="hidden" name="reason" value="Excluded from ITFlow sync from mapped asset row">
                      <button class="btn btn-sm btn-danger" title="Disable this asset mapping in ITFlow sync; this does not disable the ITFlow asset and does not disable the TacticalRMM agent">Disable Asset Mapping</button>
                    </form>
                  </td>
                </tr>
              <?php endforeach; ?>
              
              <?php foreach (($asset_conflicts ?? []) as $cidx => $c): ?>
                <?php
                  $agent_id = $c['trmm_agent_id'] ?? '';
                  if ($agent_id === '') {
                      continue;
                  }

                  $agent = $trmm_agents_by_id[$agent_id] ?? [];
                  $reason = $c['reason'] ?? '';
                  $hostname = $c['hostname'] ?? ($agent['hostname'] ?? '');
                  $trmm_client_name = $c['trmm_client_name'] ?? ($agent['trmm_client_name'] ?? '');
                  $mapping_status_label = ($reason === 'client_not_mapped_or_excluded') ? 'Unmatched Client' : 'Conflict';
                  $mapping_status_key = strtolower(str_replace(' ', '_', $mapping_status_label));
                  $trmm_status = strtolower($agent['status'] ?? ($c['status'] ?? 'unknown'));
                  $row_key = 'assetconflict-' . (int)$cidx . '-' . preg_replace('/[^A-Za-z0-9_-]/', '_', (string)$agent_id);
                  $site_name = ($agent['trmm_site_name_raw'] ?? '') ?: ($agent['trmm_site_name'] ?? ($agent['site_name'] ?? ''));
                  $serial = $agent['serial_number_raw'] ?? ($agent['serial_number'] ?? '');
                  $last_seen = $agent['last_seen'] ?? '';
                  $filter_text = strtolower(
                    $mapping_status_label . ' ' .
                    $reason . ' ' .
                    $hostname . ' ' .
                    $trmm_client_name . ' ' .
                    ($agent['description'] ?? '') . ' ' .
                    ($agent['logged_username'] ?? '') . ' ' .
                    $site_name . ' ' .
                    ($agent['make_model'] ?? '') . ' ' .
                    $serial . ' ' .
                    ($agent['operating_system'] ?? '') . ' ' .
                    ($agent['local_ips'] ?? '') . ' ' .
                    ($agent['public_ip'] ?? '') . ' ' .
                    $agent_id
                  );
                ?>
                <tr
                  class="rmm-unified-conflict-right-row"
                  data-row-key="<?= rmm_h($row_key) ?>"
                  data-rmm-status="<?= rmm_h($trmm_status) ?>"
                  data-filter="<?= rmm_h($filter_text) ?>"
                  data-sort-asset="<?= rmm_h(strtolower($hostname ?: $agent_id)) ?>"
                  data-sort-client="<?= rmm_h(strtolower($trmm_client_name)) ?>"
                  data-sort-hostname="<?= rmm_h(strtolower($hostname)) ?>"
                  data-sort-description="<?= rmm_h(strtolower($agent['description'] ?? '')) ?>"
                  data-sort-user="<?= rmm_h(strtolower($agent['logged_username'] ?? '')) ?>"
                  data-sort-site="<?= rmm_h(strtolower($site_name)) ?>"
                  data-sort-makemodel="<?= rmm_h(strtolower($agent['make_model'] ?? '')) ?>"
                  data-sort-serial="<?= rmm_h(strtolower($serial)) ?>"
                  data-sort-os="<?= rmm_h(strtolower($agent['operating_system'] ?? '')) ?>"
                  data-sort-localip="<?= rmm_h(strtolower($agent['local_ips'] ?? '')) ?>"
                  data-sort-publicip="<?= rmm_h(strtolower($agent['public_ip'] ?? '')) ?>"
                  data-sort-agent="<?= rmm_h(strtolower($agent_id)) ?>"
                  data-sort-mapping_status="<?= rmm_h($mapping_status_key) ?>"
                  data-sort-status="<?= rmm_h($trmm_status) ?>"
                  data-sort-lastseen="<?= rmm_h(strtolower($last_seen)) ?>"
                  data-sort-updated=""
                >
                  <td><span class="rmm-cell-clip"><?= rmm_h($hostname) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($agent['description'] ?? '') ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($agent['logged_username'] ?? '') ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($site_name) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($agent['make_model'] ?? '') ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($serial) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($agent['operating_system'] ?? '') ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($agent['local_ips'] ?? '') ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($agent['public_ip'] ?? '') ?></span></td>
                  <td><code class="rmm-cell-clip"><?= rmm_h($agent_id) ?></code></td>
                  <td>
                    <span class="badge <?= $mapping_status_label === 'Conflict' ? 'badge-warning' : 'badge-danger' ?> rmm-asset-mapping-status-badge">
                      <?= rmm_h($mapping_status_label) ?>
                    </span>
                  </td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($agent['status'] ?? ($c['status'] ?? 'unknown')) ?></span></td>
                  <td><span class="rmm-cell-clip"><?= rmm_h($last_seen) ?></span></td>
                  <td><span class="rmm-cell-clip"></span></td>
                  <td class="rmm-split-actions-cell">
                    <?php if ($reason === 'client_not_mapped_or_excluded'): ?>
                      <a href="?tab=clients" class="btn btn-sm btn-secondary mb-1">Map Client First</a>
                    <?php else: ?>
                      <form method="post" class="form-inline mb-1" onsubmit="return confirm('Manually map this TacticalRMM agent to the selected ITFlow asset?');">
                        <input type="hidden" name="action" value="manual_agent_match_select">
                        <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($agent_id) ?>">
                        <select class="form-control form-control-sm mr-1 mb-1" name="itflow_asset_id" style="max-width: 360px;" required>
                          <option value="">Select existing ITFlow asset...</option>
                          <?php if (!empty($itflow_assets)): ?>
                            <?php
                              if ($itflow_assets instanceof mysqli_result) {
                                  $itflow_assets->data_seek(0);
                              }
                            ?>
                            <?php while ($a = $itflow_assets->fetch_assoc()): ?>
                              <option value="<?= rmm_h($a['asset_id']) ?>">
                                <?= rmm_h(($a['client_name'] ?: 'No Client') . ' / ' . $a['asset_name'] . ' [' . $a['asset_id'] . ']') ?>
                              </option>
                            <?php endwhile; ?>
                          <?php endif; ?>
                        </select>
                        <button class="btn btn-sm btn-secondary mb-1">Save Match</button>
                      </form>
                    <?php endif; ?>

                    <form method="post" class="d-inline" onsubmit="return confirm('Disable this asset mapping in ITFlow sync? This does not disable the ITFlow asset and does not disable the TacticalRMM agent.');">
                      <input type="hidden" name="action" value="disable_agent_sync">
                      <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($agent_id) ?>">
                      <input type="hidden" name="hostname" value="<?= rmm_h($hostname) ?>">
                      <input type="hidden" name="reason" value="Disabled from unified Asset Mapping table">
                      <button class="btn btn-sm btn-danger" title="Disable this asset mapping in ITFlow sync; this does not disable the ITFlow asset and does not disable the TacticalRMM agent">Disable Asset Mapping</button>
                    </form>
                  </td>
                </tr>
              <?php endforeach; ?>

</tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="modal fade" id="rmmFixMatchModal" tabindex="-1" role="dialog" aria-labelledby="rmmFixMatchModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg" role="document">
          <form method="post" class="modal-content" onsubmit="return confirm('Change the TacticalRMM agent mapped to this ITFlow asset?');">
            <input type="hidden" name="action" value="manual_agent_match_select">
            <input type="hidden" name="itflow_asset_id" id="rmmFixMatchAssetId" value="">

            <div class="modal-header">
              <h5 class="modal-title" id="rmmFixMatchModalLabel">Fix Asset Match</h5>
              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                <span aria-hidden="true">&times;</span>
              </button>
            </div>

            <div class="modal-body">
              <div class="alert alert-info">
                <strong>ITFlow Asset:</strong>
                <span id="rmmFixMatchAssetText"></span>
                <br>
                <strong>Current TacticalRMM Agent:</strong>
                <span id="rmmFixMatchCurrentText"></span>
              </div>

              <div class="form-group">
                <label for="rmmFixMatchAgentId">New TacticalRMM Agent</label>
                <button type="button" class="btn btn-sm btn-outline-primary mr-2 rmm-open-fixmatch">Fix Match</button>
                          <span class="rmm-fixmatch-holder"></span>
                          <button type="button" class="btn btn-sm btn-outline-primary mr-2 rmm-open-fixmatch">Fix Match</button>
                          <span class="rmm-fixmatch-holder"></span>
                <small class="form-text text-muted">
                  This changes the permanent mapping for the selected ITFlow asset to the selected TacticalRMM agent ID.
                </small>
              </div>
            </div>

            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Save Match</button>
            </div>
          </form>
        </div>
      </div>

      <div class="card card-warning d-none rmm-legacy-asset-conflict-section">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-exclamation-triangle mr-2"></i>True Tactical Agent Conflicts</h3>
        </div>
        <div class="card-body">
          <p class="text-muted">
            Source: <code><?= rmm_h($latest_conflicts_file ?: 'No conflict report found. Run Preview Asset Sync first.') ?></code>
          </p>
          <input class="form-control form-control-sm rmm-table-filter" data-target="#rmm-conflict-table" placeholder="Search true conflicts, clients, hostname, agent ID, reason...">
        </div>
        <div class="card-body table-responsive p-0 rmm-sticky-table-wrap" style="max-height: 520px;">
          <table id="rmm-conflict-table" class="table table-striped table-sm mb-0 rmm-sortable-table">
            <thead>
              <tr>
                <th>Reason</th>
                <th>Tactical Client</th>
                <th>Hostname</th>
                <th>Agent ID</th>
                <th>Manual Match</th>
                <th>Disable / Enable</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($asset_conflicts as $c): ?>
              <?php
                $reason = $c['reason'] ?? '';
                if ($reason === 'client_not_mapped_or_excluded') {
                    continue;
                }
                $agent_id = $c['trmm_agent_id'] ?? '';
                $agent = $trmm_agents_by_id[$agent_id] ?? [];
                $hostname = $c['hostname'] ?? ($agent['hostname'] ?? '');
              ?>
              <tr>
                <td><?= rmm_h($c['reason'] ?? '') ?></td>
                <td><?= rmm_h($c['trmm_client_name'] ?? ($agent['trmm_client_name'] ?? '')) ?><br><small class="text-muted">TRMM <?= rmm_h($c['trmm_client_id'] ?? ($agent['trmm_client_id'] ?? '')) ?></small></td>
                <td><?= rmm_h($hostname) ?></td>
                <td><code><?= rmm_h($agent_id) ?></code></td>
                <td>
                  <?php if (!empty($agent_id)): ?>
                    <form method="post" class="form-inline" onsubmit="return confirm('Manually map this TacticalRMM agent to the selected ITFlow asset?');">
                      <input type="hidden" name="action" value="manual_agent_match_select">
                      <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($agent_id) ?>">
                      <select class="form-control form-control-sm mr-1" name="itflow_asset_id" style="max-width: 360px;" required>
                        <option value="">Select existing ITFlow asset...</option>
                        <?php if (!empty($itflow_assets)): ?>
                          <?php
                            if ($itflow_assets instanceof mysqli_result) {
                              $itflow_assets->data_seek(0);
                            }
                          ?>
                          <?php while ($a = $itflow_assets->fetch_assoc()): ?>
                            <option value="<?= rmm_h($a['asset_id']) ?>">
                              <?= rmm_h(($a['client_name'] ?: 'No Client') . ' / ' . $a['asset_name'] . ' [' . $a['asset_id'] . ']') ?>
                            </option>
                          <?php endwhile; ?>
                        <?php endif; ?>
                      </select>
                      <button type="button" class="btn btn-sm btn-outline-primary mr-2 rmm-open-fixmatch">Fix Match</button>
                          <span class="rmm-fixmatch-holder"></span>
                          <button class="btn btn-sm btn-secondary">Save Agent Match</button>
                    </form>
                  <?php endif; ?>
                </td>
                <td>
                  <?php if (!empty($agent_id)): ?>
                    <form method="post" class="mb-1" onsubmit="return confirm('Exclude this TacticalRMM agent from ITFlow sync? This does not disable the ITFlow asset and does not disable the agent in TacticalRMM.');">
                      <input type="hidden" name="action" value="disable_agent_sync">
                      <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($agent_id) ?>">
                      <input type="hidden" name="hostname" value="<?= rmm_h($hostname) ?>">
                      <input type="hidden" name="reason" value="Excluded from ITFlow sync from conflict row">
                      <button class="btn btn-sm btn-danger" title="Exclude this TacticalRMM agent from ITFlow sync; does not disable the asset or the agent in TacticalRMM">Exclude TRMM Agent</button>
                    </form>
                    <form method="post">
                      <input type="hidden" name="action" value="enable_agent_sync">
                      <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($agent_id) ?>">
                      <button class="btn btn-sm btn-outline-secondary">Enable</button>
                    </form>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
            <?php if (empty($asset_conflicts)): ?>
              <tr><td colspan="6" class="text-muted">No conflicts found in latest sync report.</td></tr>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>


      <div class="card card-info">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-link mr-2"></i>Unmatched Tactical Agents</h3>
        </div>
        <div class="card-body">
          <p class="text-muted mb-2">
            These TacticalRMM agents are not asset conflicts. They are attached to TacticalRMM clients that are not mapped or are intentionally excluded.
            Handle these the same way as unmatched clients: map the TacticalRMM client on the Client Mapping tab, or leave/exclude it intentionally.
          </p>
          <input class="form-control form-control-sm rmm-table-filter" data-target="#rmm-unmatched-agent-table" placeholder="Search unmatched Tactical agents, clients, hostname, description, user, agent ID...">
        </div>
        <div class="card-body table-responsive p-0 rmm-sticky-table-wrap" style="max-height: 420px;">
          <table id="rmm-unmatched-agent-table" class="table table-striped table-sm mb-0 rmm-sortable-table">
            <thead>
              <tr>
                <th>Tactical Client</th>
                <th>Hostname</th>
                <th>Description</th>
                <th>Logged User</th>
                <th>Site</th>
                <th>Agent ID</th>
                <th>Recommended Next Step</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($asset_conflicts as $c): ?>
              <?php
                $reason = $c['reason'] ?? '';
                if ($reason !== 'client_not_mapped_or_excluded') {
                    continue;
                }
                $agent_id = $c['trmm_agent_id'] ?? '';
                $agent = $trmm_agents_by_id[$agent_id] ?? [];
                $hostname = $c['hostname'] ?? ($agent['hostname'] ?? '');
              ?>
              <tr>
                <td><?= rmm_h($c['trmm_client_name'] ?? ($agent['trmm_client_name'] ?? '')) ?><br><small class="text-muted">TRMM <?= rmm_h($c['trmm_client_id'] ?? ($agent['trmm_client_id'] ?? '')) ?></small></td>
                <td><?= rmm_h($hostname) ?></td>
                <td><?= rmm_h($agent['description'] ?? '') ?></td>
                <td><?= rmm_h($agent['logged_username'] ?? '') ?></td>
                <td><?= rmm_h(($agent['trmm_site_name_raw'] ?? '') ?: ($agent['trmm_site_name'] ?? '')) ?></td>
                <td><code><?= rmm_h($agent_id) ?></code></td>
                <td>Map or exclude this Tactical client on <a href="?tab=clients">Client Mapping</a>.</td>
                <td>
                  <?php if (!empty($agent_id)): ?>
                    <form method="post" onsubmit="return confirm('Exclude this TacticalRMM agent from ITFlow sync? This does not disable the ITFlow asset and does not disable the agent in TacticalRMM.');">
                      <input type="hidden" name="action" value="disable_agent_sync">
                      <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($agent_id) ?>">
                      <input type="hidden" name="hostname" value="<?= rmm_h($hostname) ?>">
                      <input type="hidden" name="reason" value="Excluded from ITFlow sync from unmatched Tactical agent row">
                      <button class="btn btn-sm btn-danger" title="Exclude this TacticalRMM agent from ITFlow sync; does not disable the asset or the agent in TacticalRMM">Exclude TRMM Agent</button>
                    </form>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card card-secondary">
        <div class="card-header">
          <h3 class="card-title"><i class="fas fa-ban mr-2"></i>Agent Exclusions</h3>
        </div>
        <div class="card-body table-responsive p-0 rmm-sticky-table-wrap" style="max-height: 420px;">
          <table id="rmm-exclusion-table" class="table table-striped table-sm mb-0 rmm-sortable-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Agent ID</th>
                <th>Name</th>
                <th>Reason</th>
                <th>Updated</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
            <?php if (!empty($exclusions)): ?>
              <?php while ($ex = $exclusions->fetch_assoc()): ?>
                <tr>
                  <td><?= !empty($ex['enabled']) ? '<span class="badge badge-danger">Excluded</span>' : '<span class="badge badge-secondary">Disabled</span>' ?></td>
                  <td><code><?= rmm_h($ex['external_id']) ?></code></td>
                  <td><?= rmm_h($ex['external_name']) ?></td>
                  <td><?= rmm_h($ex['reason']) ?></td>
                  <td><?= rmm_h($ex['updated_at'] ?: $ex['created_at']) ?></td>
                  <td>
                    <?php if (!empty($ex['external_id']) && !empty($ex['enabled'])): ?>
                      <form method="post">
                        <input type="hidden" name="action" value="enable_agent_sync">
                        <input type="hidden" name="trmm_agent_id" value="<?= rmm_h($ex['external_id']) ?>">
                        <button class="btn btn-sm btn-outline-secondary">Enable</button>
                      </form>
                    <?php endif; ?>
                  </td>
                </tr>
              <?php endwhile; ?>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>

    <?php elseif ($active_tab === 'jobs'): ?>

      <div class="card card-dark">
        <div class="card-header"><h3 class="card-title"><i class="fas fa-tasks mr-2"></i>Jobs</h3></div>
        <div class="card-body"><input class="form-control form-control-sm rmm-table-filter" data-target="#rmm-job-table" placeholder="Search jobs, status, summary..."></div>
        <div class="card-body table-responsive p-0 rmm-sticky-table-wrap" style="max-height: 720px;">
          <table id="rmm-job-table" class="table table-striped table-sm mb-0 rmm-sortable-table">
            <thead>
              <tr>
                <th>ID</th><th>Type</th><th>Status</th><th>Requested By</th><th>Created</th><th>Started</th><th>Finished</th><th>Summary</th>
              </tr>
            </thead>
            <tbody>
            <?php if (!empty($jobs)): ?>
              <?php while ($j = $jobs->fetch_assoc()): ?>
                <tr>
                  <td><?= rmm_h($j['job_id']) ?></td>
                  <td><?= rmm_h($j['job_type']) ?></td>
                  <td><?= rmm_h($j['job_status']) ?></td>
                  <td><?= rmm_h($j['requested_by']) ?></td>
                  <td><?= rmm_h($j['created_at']) ?></td>
                  <td><?= rmm_h($j['started_at']) ?></td>
                  <td><?= rmm_h($j['finished_at']) ?></td>
                  <td><pre style="max-height: 220px; overflow:auto; white-space:pre-wrap;"><?= rmm_h($j['result_summary']) ?></pre></td>
                </tr>
              <?php endwhile; ?>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>

    <?php elseif ($active_tab === 'logs'): ?>

      <div class="card card-dark">
        <div class="card-header"><h3 class="card-title"><i class="fas fa-list mr-2"></i>Job Logs</h3></div>
        <div class="card-body"><input class="form-control form-control-sm rmm-table-filter" data-target="#rmm-log-table" placeholder="Search logs..."></div>
        <div class="card-body table-responsive p-0 rmm-sticky-table-wrap" style="max-height: 720px;">
          <table id="rmm-log-table" class="table table-striped table-sm mb-0 rmm-sortable-table">
            <thead>
              <tr>
                <th>ID</th><th>Job</th><th>Type</th><th>Level</th><th>Created</th><th>Message</th>
              </tr>
            </thead>
            <tbody>
            <?php if (!empty($logs)): ?>
              <?php while ($l = $logs->fetch_assoc()): ?>
                <tr>
                  <td><?= rmm_h($l['log_id']) ?></td>
                  <td><?= rmm_h($l['job_id']) ?></td>
                  <td><?= rmm_h($l['job_type']) ?></td>
                  <td><?= rmm_h($l['level']) ?></td>
                  <td><?= rmm_h($l['created_at']) ?></td>
                  <td><pre style="max-height: 180px; overflow:auto; white-space:pre-wrap;"><?= rmm_h($l['message']) ?></pre></td>
                </tr>
              <?php endwhile; ?>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>

    <?php endif; ?>

  </div>
</section>

<style>
  .rmm-sortable-table th {
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }
  .rmm-sortable-table th.rmm-no-sort {
    cursor: default;
  }
  .rmm-sortable-table th .rmm-sort-indicator {
    opacity: 0.45;
    font-size: 0.75em;
    margin-left: 6px;
  }
  .rmm-sort-active {
    background: rgba(0,0,0,.04);
  }
  .rmm-sticky-table-wrap {
    position: relative;
  }
  .rmm-sticky-table-wrap table thead th {
    position: sticky;
    top: 0;
    z-index: 5;
    background: #fff;
    box-shadow: inset 0 -1px 0 rgba(0,0,0,.12);
  }
  .rmm-sticky-table-wrap table thead th.rmm-sort-active {
    background: #f1f3f5;
  }
</style>
<script>
  window.rmmAgentOptions = <?= json_encode($rmm_agent_options ?? [], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
</script>

<script>
(function () {
  function cellText(row, index) {
    var cell = row.children[index];
    if (!cell) return "";
    return (cell.innerText || cell.textContent || "").trim();
  }

  function normalizeValue(value) {
    var text = (value || "").trim();
    var numeric = text.replace(/[, ]+/g, "");
    if (/^-?\d+(\.\d+)?$/.test(numeric)) {
      return { type: "number", value: parseFloat(numeric) };
    }
    var date = Date.parse(text);
    if (!Number.isNaN(date) && /\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}/.test(text)) {
      return { type: "date", value: date };
    }
    return { type: "text", value: text.toLowerCase() };
  }

  function compareValues(a, b, direction) {
    var av = normalizeValue(a);
    var bv = normalizeValue(b);

    if (av.type === bv.type && av.value < bv.value) return -1 * direction;
    if (av.type === bv.type && av.value > bv.value) return 1 * direction;

    var at = String(av.value);
    var bt = String(bv.value);
    if (at < bt) return -1 * direction;
    if (at > bt) return 1 * direction;
    return 0;
  }

  function initSortableTable(table) {
    var thead = table.tHead;
    var tbody = table.tBodies[0];
    if (!thead || !tbody) return;

    var headers = Array.prototype.slice.call(thead.querySelectorAll("th"));

    headers.forEach(function (th, index) {
      if (th.classList.contains("rmm-no-sort")) return;

      if (!th.querySelector(".rmm-sort-indicator")) {
        var indicator = document.createElement("span");
        indicator.className = "rmm-sort-indicator";
        indicator.textContent = "↕";
        th.appendChild(indicator);
      }

      th.addEventListener("click", function () {
        var currentDirection = th.getAttribute("data-sort-direction") === "asc" ? "desc" : "asc";
        var direction = currentDirection === "asc" ? 1 : -1;

        headers.forEach(function (h) {
          h.removeAttribute("data-sort-direction");
          h.classList.remove("rmm-sort-active");
          var i = h.querySelector(".rmm-sort-indicator");
          if (i) i.textContent = "↕";
        });

        th.setAttribute("data-sort-direction", currentDirection);
        th.classList.add("rmm-sort-active");
        var activeIndicator = th.querySelector(".rmm-sort-indicator");
        if (activeIndicator) activeIndicator.textContent = currentDirection === "asc" ? "▲" : "▼";

        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
        rows.sort(function (ra, rb) {
          return compareValues(cellText(ra, index), cellText(rb, index), direction);
        });

        rows.forEach(function (row) {
          tbody.appendChild(row);
        
      if (typeof window.rmmFinalClientSearch === "function") { window.setTimeout(window.rmmFinalClientSearch, 0); }
});
      });
    });
  }

  function applyFilters(table) {
    if (!table) return;
    var textFilter = "";
    var input = document.querySelector('.rmm-table-filter[data-target="#' + table.id + '"]');
    if (input) textFilter = input.value.trim().toLowerCase();

    var activeStatus = "";
    var statusGroup = document.querySelector('.rmm-status-filter[data-target="#' + table.id + '"]');
    if (statusGroup) {
      var activeButton = statusGroup.querySelector("button.active");
      if (activeButton) activeStatus = (activeButton.getAttribute("data-status") || "").toLowerCase();
    }

    Array.prototype.slice.call(table.tBodies[0].querySelectorAll("tr")).forEach(function (row) {
      var rowText = (row.innerText || row.textContent || "").toLowerCase();
      var rowStatus = (row.getAttribute("data-rmm-status") || "").toLowerCase();
      var textOk = !textFilter || rowText.indexOf(textFilter) !== -1;
      var statusOk = !activeStatus || rowStatus === activeStatus;
      row.style.display = (textOk && statusOk) ? "" : "none";
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("table.rmm-sortable-table").forEach(initSortableTable);

    document.querySelectorAll(".rmm-table-filter").forEach(function (input) {
      input.addEventListener("input", function () {
        var target = document.querySelector(input.getAttribute("data-target"));
        applyFilters(target);
      });
    });

    document.querySelectorAll(".rmm-status-filter").forEach(function (group) {
      group.querySelectorAll("button").forEach(function (button) {
        button.addEventListener("click", function () {
          group.querySelectorAll("button").forEach(function (b) { b.classList.remove("active"); });
          button.classList.add("active");
          var target = document.querySelector(group.getAttribute("data-target"));
          applyFilters(target);
        });
      });
    });


  function rmmBindFixMatchModal() {
    if (window.rmmFixMatchModalBound) return;
    window.rmmFixMatchModalBound = true;

    document.addEventListener("click", function (event) {
      var button = event.target.closest(".rmm-open-fixmatch");
      if (!button) return;

      event.preventDefault();

      var assetId = button.getAttribute("data-asset-id") || "";
      var assetName = button.getAttribute("data-asset-name") || "";
      var clientName = button.getAttribute("data-client-name") || "";
      var currentAgentId = button.getAttribute("data-current-agent-id") || "";
      var currentHostname = button.getAttribute("data-current-hostname") || "";

      var assetInput = document.getElementById("rmmFixMatchAssetId");
      var assetText = document.getElementById("rmmFixMatchAssetText");
      var currentText = document.getElementById("rmmFixMatchCurrentText");
      var agentSelect = document.getElementById("rmmFixMatchAgentId");

      if (!assetInput || !assetText || !currentText || !agentSelect) {
        alert("Fix Match modal is missing required fields. Refresh the page and try again.");
        return;
      }

      assetInput.value = assetId;
      assetText.textContent = clientName + " / " + assetName + " [" + assetId + "]";
      currentText.textContent = (currentHostname || "No hostname") + " [" + currentAgentId + "]";
      agentSelect.value = currentAgentId;

      if (window.jQuery && window.jQuery.fn && window.jQuery.fn.modal) {
        window.jQuery("#rmmFixMatchModal").modal("show");
        return;
      }

      var modal = document.getElementById("rmmFixMatchModal");
      if (modal) {
        modal.classList.add("show");
        modal.style.display = "block";
        modal.removeAttribute("aria-hidden");
        modal.setAttribute("aria-modal", "true");
        document.body.classList.add("modal-open");
      }
    });
  }
      var button = event.target.closest(".rmm-open-fixmatch");
      if (!button) return;

      event.preventDefault();

      var holder = button.parentElement.querySelector(".rmm-inline-fixmatch-holder");
      if (!holder) {
        holder = document.createElement("div");
        holder.className = "rmm-inline-fixmatch-holder mt-1";
        button.insertAdjacentElement("afterend", holder);
      }

      document.querySelectorAll(".rmm-inline-fixmatch-holder").forEach(function (h) {
        if (h !== holder) h.innerHTML = "";
      });

      if (holder.getAttribute("data-open") === "1") {
        holder.innerHTML = "";
        holder.removeAttribute("data-open");
        return;
      }

      var assetId = button.getAttribute("data-asset-id") || "";
      var assetName = button.getAttribute("data-asset-name") || "";
      var clientName = button.getAttribute("data-client-name") || "";
      var currentAgentId = button.getAttribute("data-current-agent-id") || "";
      var currentHostname = button.getAttribute("data-current-hostname") || "";
      var options = window.rmmAgentOptions || [];

      var form = document.createElement("form");
      form.method = "post";
      form.className = "rmm-inline-fixmatch-form";
      form.onsubmit = function () {
        return confirm(
          "Change ITFlow mapping for " + assetName + " to the selected TacticalRMM agent?\\n\\n" +
          "This changes ITFlow's permanent trmm_agent_id -> asset_id mapping only. It does not change TacticalRMM."
        );
      };

      var action = document.createElement("input");
      action.type = "hidden";
      action.name = "action";
      action.value = "manual_agent_match_select";
      form.appendChild(action);

      var assetInput = document.createElement("input");
      assetInput.type = "hidden";
      assetInput.name = "itflow_asset_id";
      assetInput.value = assetId;
      form.appendChild(assetInput);

      var label = document.createElement("div");
      label.className = "small text-muted mb-1";
      label.textContent = "Fix: " + clientName + " / " + assetName + " | Current: " + (currentHostname || "No hostname");
      form.appendChild(label);

      var select = document.createElement("select");
      select.name = "trmm_agent_id";
      select.className = "form-control form-control-sm mb-1";
      select.required = true;

      var blank = document.createElement("option");
      blank.value = "";
      blank.textContent = "Select TacticalRMM agent...";
      select.appendChild(blank);

      options.forEach(function (opt) {
        var option = document.createElement("option");
        option.value = opt.id || "";
        option.textContent = opt.label || opt.id || "";
        if (opt.id === currentAgentId) option.selected = true;
        select.appendChild(option);
      });

      form.appendChild(select);

      var save = document.createElement("button");
      save.type = "submit";
      save.className = "btn btn-sm btn-primary mr-1";
      save.textContent = "Save Match";
      form.appendChild(save);

      var close = document.createElement("button");
      close.type = "button";
      close.className = "btn btn-sm btn-outline-secondary rmm-cancel-inline-fixmatch";
      close.textContent = "Cancel";
      form.appendChild(close);

      holder.innerHTML = "";
      holder.appendChild(form);
      holder.setAttribute("data-open", "1");
      select.focus();
    });
  }


  function rmmInitNormalTableSorting() {
    if (window.rmmNormalTableSortingBound) return;
    window.rmmNormalTableSortingBound = true;

    function rmmCellText(row, index) {
      var cell = row.children[index];
      if (!cell) return "";
      return (cell.innerText || cell.textContent || "").trim();
    }

    function rmmNormalizeSortValue(value) {
      var text = (value || "").trim();
      var numeric = text.replace(/[, ]+/g, "");
      if (/^-?\d+(\.\d+)?$/.test(numeric)) {
        return { type: "number", value: parseFloat(numeric) };
      }

      var parsedDate = Date.parse(text);
      if (!Number.isNaN(parsedDate) && /\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}/.test(text)) {
        return { type: "date", value: parsedDate };
      }

      return { type: "text", value: text.toLowerCase() };
    }

    function rmmCompareSortValues(a, b, direction) {
      var av = rmmNormalizeSortValue(a);
      var bv = rmmNormalizeSortValue(b);

      if (av.type === bv.type && av.value < bv.value) return -1 * direction;
      if (av.type === bv.type && av.value > bv.value) return 1 * direction;

      var at = String(av.value);
      var bt = String(bv.value);
      if (at < bt) return -1 * direction;
      if (at > bt) return 1 * direction;
      return 0;
    }

    document.querySelectorAll("table.rmm-sortable-table").forEach(function (table) {
      /*
       * Do not bind this generic sorter to the split Asset Mapping tables.
       * They have their own synchronized left/right sorter.
       */
      if (
        table.id === "rmm-asset-left-table" ||
        table.id === "rmm-asset-right-table" ||
        table.closest("#rmm-asset-split-wrap")
      ) {
        return;
      }

      var thead = table.tHead;
      var tbody = table.tBodies[0];
      if (!thead || !tbody) return;

      Array.prototype.slice.call(thead.querySelectorAll("th")).forEach(function (th, index) {
        if (th.classList.contains("rmm-no-sort")) return;
        if (th.getAttribute("data-rmm-sort-bound") === "1") return;

        th.setAttribute("data-rmm-sort-bound", "1");
        th.style.cursor = "pointer";
        th.style.userSelect = "none";

        if (!th.querySelector(".rmm-sort-indicator")) {
          var indicator = document.createElement("span");
          indicator.className = "rmm-sort-indicator";
          indicator.textContent = "↕";
          indicator.style.opacity = "0.45";
          indicator.style.fontSize = "0.75em";
          indicator.style.marginLeft = "6px";
          th.appendChild(indicator);
        }

        th.addEventListener("click", function () {
          var headers = Array.prototype.slice.call(thead.querySelectorAll("th"));
          var directionText = th.getAttribute("data-sort-direction") === "asc" ? "desc" : "asc";
          var direction = directionText === "asc" ? 1 : -1;

          headers.forEach(function (h) {
            h.removeAttribute("data-sort-direction");
            h.classList.remove("rmm-sort-active");
            var i = h.querySelector(".rmm-sort-indicator");
            if (i) i.textContent = "↕";
          });

          th.setAttribute("data-sort-direction", directionText);
          th.classList.add("rmm-sort-active");

          var activeIndicator = th.querySelector(".rmm-sort-indicator");
          if (activeIndicator) activeIndicator.textContent = directionText === "asc" ? "▲" : "▼";

          var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));

          rows.sort(function (ra, rb) {
            return rmmCompareSortValues(rmmCellText(ra, index), rmmCellText(rb, index), direction);
          });

          rows.forEach(function (row) {
            tbody.appendChild(row);
          
      if (typeof window.rmmFinalClientSearch === "function") { window.setTimeout(window.rmmFinalClientSearch, 0); }
});
        });
      });
    });
  }

  function initAssetSplitTable() {
    var wrap = document.getElementById("rmm-asset-split-wrap");
    var leftPane = document.getElementById("rmm-asset-left-pane");
    var rightPane = document.getElementById("rmm-asset-right-pane");
    var leftTable = document.getElementById("rmm-asset-left-table");
    var rightTable = document.getElementById("rmm-asset-right-table");

    if (!wrap || !leftPane || !rightPane || !leftTable || !rightTable) return;

    var leftBody = leftTable.tBodies[0];
    var rightBody = rightTable.tBodies[0];

    function getRows() {
      var leftRows = Array.prototype.slice.call(leftBody.querySelectorAll("tr"));
      var rightRowsByKey = {};
      Array.prototype.slice.call(rightBody.querySelectorAll("tr")).forEach(function (row) {
        rightRowsByKey[row.getAttribute("data-row-key")] = row;
      });
      return { leftRows: leftRows, rightRowsByKey: rightRowsByKey };
    }

    function syncHeights() {
      var rows = getRows();
      rows.leftRows.forEach(function (leftRow) {
        var key = leftRow.getAttribute("data-row-key");
        var rightRow = rows.rightRowsByKey[key];
        if (!rightRow) return;

        leftRow.style.height = "";
        rightRow.style.height = "";

        var h = Math.max(leftRow.offsetHeight, rightRow.offsetHeight);
        leftRow.style.height = h + "px";
        rightRow.style.height = h + "px";
      });
    }

    function normalizeSortValue(value) {
      var text = (value || "").trim();
      var numberText = text.replace(/[, ]+/g, "");
      if (/^-?\d+(\.\d+)?$/.test(numberText)) {
        return { type: "number", value: parseFloat(numberText) };
      }
      var parsedDate = Date.parse(text);
      if (!Number.isNaN(parsedDate) && /\d{4}-\d{2}-\d{2}/.test(text)) {
        return { type: "date", value: parsedDate };
      }
      return { type: "text", value: text.toLowerCase() };
    }

    function compareSortValues(a, b, direction) {
      var av = normalizeSortValue(a);
      var bv = normalizeSortValue(b);

      if (av.type === bv.type && av.value < bv.value) return -1 * direction;
      if (av.type === bv.type && av.value > bv.value) return 1 * direction;

      var at = String(av.value);
      var bt = String(bv.value);
      if (at < bt) return -1 * direction;
      if (at > bt) return 1 * direction;
      return 0;
    }

    function sortBy(key, header) {
      var allHeaders = wrap.querySelectorAll("th[data-sort-key]");
      var directionText = header.getAttribute("data-sort-direction") === "asc" ? "desc" : "asc";
      var direction = directionText === "asc" ? 1 : -1;

      allHeaders.forEach(function (h) {
        h.removeAttribute("data-sort-direction");
        h.classList.remove("rmm-sort-active");
        var indicator = h.querySelector(".rmm-sort-indicator");
        if (indicator) indicator.textContent = "↕";
      });

      header.setAttribute("data-sort-direction", directionText);
      header.classList.add("rmm-sort-active");
      var activeIndicator = header.querySelector(".rmm-sort-indicator");
      if (activeIndicator) activeIndicator.textContent = directionText === "asc" ? "▲" : "▼";

      var rows = getRows();
      rows.leftRows.sort(function (a, b) {
        return compareSortValues(a.getAttribute("data-sort-" + key) || "", b.getAttribute("data-sort-" + key) || "", direction);
      });

      rows.leftRows.forEach(function (leftRow) {
        var keyValue = leftRow.getAttribute("data-row-key");
        var rightRow = rows.rightRowsByKey[keyValue];
        leftBody.appendChild(leftRow);
        if (rightRow) rightBody.appendChild(rightRow);
      });

      syncHeights();
    }

    function applySplitFilter() {
      var input = document.querySelector('.rmm-asset-split-filter[data-target="#rmm-asset-split-wrap"]');
      var textFilter = input ? input.value.trim().toLowerCase() : "";

      var activeStatus = "";
      var statusGroup = document.querySelector('.rmm-asset-split-status[data-target="#rmm-asset-split-wrap"]');
      if (statusGroup) {
        var activeButton = statusGroup.querySelector("button.active");
        activeStatus = activeButton ? (activeButton.getAttribute("data-status") || "").toLowerCase() : "";
      }

      var rows = getRows();

      rows.leftRows.forEach(function (leftRow) {
        var key = leftRow.getAttribute("data-row-key");
        var rightRow = rows.rightRowsByKey[key];
        var rowText = leftRow.getAttribute("data-filter") || "";
        var rowStatus = leftRow.getAttribute("data-rmm-status") || "";
        var textOk = !textFilter || rowText.indexOf(textFilter) !== -1;
        var statusOk = !activeStatus || rowStatus === activeStatus;
        var hidden = !(textOk && statusOk);

        leftRow.classList.toggle("rmm-filter-hidden", hidden);
        if (rightRow) rightRow.classList.toggle("rmm-filter-hidden", hidden);
      });

      syncHeights();
    }

    rightPane.addEventListener("scroll", function () {
      leftPane.scrollTop = rightPane.scrollTop;
    });

    wrap.querySelectorAll("th[data-sort-key]").forEach(function (header) {
      header.addEventListener("click", function () {
        sortBy(header.getAttribute("data-sort-key"), header);
      });
    });

    document.querySelectorAll(".rmm-asset-split-filter").forEach(function (input) {
      input.addEventListener("input", applySplitFilter);
    });

    document.querySelectorAll(".rmm-asset-split-status").forEach(function (group) {
      group.querySelectorAll("button").forEach(function (button) {
        button.addEventListener("click", function () {
          group.querySelectorAll("button").forEach(function (b) { b.classList.remove("active"); });
          button.classList.add("active");
          applySplitFilter();
        });
      });
    });

    syncHeights();
    window.addEventListener("resize", syncHeights);
    setTimeout(syncHeights, 100);
    setTimeout(syncHeights, 500);
  }

  rmmInitNormalTableSorting();
  // initAssetSplitTable disabled for performance; rmm-asset-split-sort-hardfix owns split-table sort/filter/scroll.
  // rmmBindLazyFixMatch disabled; Asset Fix Match v4 owns this.
  // rmmBindFixMatchModal disabled; lazy inline Fix Match is now used.
});
  });
})();
</script>


<style>
  .rmm-asset-card .rmm-col-actions {
    min-width: 150px;
  }

  .rmm-asset-card .rmm-fixmatch-form {
    display: flex !important;
    flex-wrap: nowrap;
    align-items: center;
    gap: .25rem;
  }

  .rmm-asset-card .rmm-fixmatch-form select {
    min-width: 0;
    max-width: 100%;
    flex: 1 1 auto;
  }

  .rmm-asset-card .rmm-fixmatch-form button {
    flex: 0 0 auto;
  }

  .rmm-asset-card td,
  .rmm-asset-card th {
    vertical-align: top;
  }

  .rmm-asset-card .rmm-col-agentid code {
    display: inline-block;
    max-width: 260px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  @media (max-width: 1400px) {
    .rmm-asset-card table {
      font-size: 12px;
    }

    .rmm-asset-card .rmm-col-agentid code {
      max-width: 170px;
    }

    .rmm-asset-card .rmm-col-actions {
      min-width: 280px;
    }
  }

</style>



<style>
  /*
   * Asset Mapping horizontal-scroll helper:
   * keep the first two columns visible while scrolling right.
   */
  #rmm-asset-table {
    border-collapse: separate;
    border-spacing: 0;
  }

  #rmm-asset-table .rmm-col-asset {
    position: sticky;
    left: 0;
    z-index: 7;
    background: #fff;
    min-width: 190px;
    max-width: 240px;
  }

  #rmm-asset-table .rmm-col-client {
    position: sticky;
    left: 190px;
    z-index: 7;
    background: #fff;
    min-width: 170px;
    max-width: 220px;
    box-shadow: 2px 0 4px rgba(0,0,0,.08);
  }

  #rmm-asset-table thead .rmm-col-asset,
  #rmm-asset-table thead .rmm-col-client {
    z-index: 12;
    background: #fff;
  }

  #rmm-asset-table tbody tr:nth-of-type(odd) .rmm-col-asset,
  #rmm-asset-table tbody tr:nth-of-type(odd) .rmm-col-client {
    background: rgba(0,0,0,.03);
  }

  #rmm-asset-table tbody tr:nth-of-type(even) .rmm-col-asset,
  #rmm-asset-table tbody tr:nth-of-type(even) .rmm-col-client {
    background: #fff;
  }

  #rmm-asset-table .rmm-col-asset,
  #rmm-asset-table .rmm-col-client {
    overflow-wrap: anywhere;
  }

  @media (max-width: 1200px) {
    #rmm-asset-table .rmm-col-asset {
      min-width: 165px;
      max-width: 190px;
    }

    #rmm-asset-table .rmm-col-client {
      left: 165px;
      min-width: 145px;
      max-width: 170px;
    }
  }
</style>



<style>
  #rmm-asset-table {
    table-layout: fixed;
    min-width: 1250px;
  }

  #rmm-asset-table .rmm-col-asset {
    width: 210px;
  }

  #rmm-asset-table .rmm-col-client {
    width: 185px;
  }

  #rmm-asset-table .rmm-col-hostname {
    width: 180px;
  }

  #rmm-asset-table .rmm-col-agentid {
    width: 230px;
  }

  #rmm-asset-table .rmm-col-status {
    width: 95px;
  }

  #rmm-asset-table .rmm-col-lastseen {
    width: 130px;
  }

  #rmm-asset-table .rmm-col-updated {
    width: 115px;
  }

  #rmm-asset-table .rmm-col-actions {
    width: 170px;
  }
</style>



<style>
  /*
   * Final Asset Mapping table layout:
   * - fixed widths via colgroup
   * - first two columns frozen
   * - no text bleed/overlap across columns
   */
  #rmm-asset-table {
    table-layout: fixed !important;
    border-collapse: separate !important;
    border-spacing: 0 !important;
    min-width: 1380px !important;
    width: 1380px !important;
  }

  #rmm-asset-table .rmm-colgroup-asset {
    width: 220px !important;
  }

  #rmm-asset-table .rmm-colgroup-client {
    width: 220px !important;
  }

  #rmm-asset-table .rmm-colgroup-hostname {
    width: 190px !important;
  }

  #rmm-asset-table .rmm-colgroup-agentid {
    width: 260px !important;
  }

  #rmm-asset-table .rmm-colgroup-status {
    width: 90px !important;
  }

  #rmm-asset-table .rmm-colgroup-lastseen {
    width: 130px !important;
  }

  #rmm-asset-table .rmm-colgroup-updated {
    width: 120px !important;
  }

  #rmm-asset-table .rmm-colgroup-actions {
    width: 150px !important;
  }

  #rmm-asset-table th,
  #rmm-asset-table td {
    box-sizing: border-box !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    vertical-align: top !important;
  }

  #rmm-asset-table th {
    white-space: nowrap !important;
  }

  #rmm-asset-table td {
    white-space: normal !important;
  }

  #rmm-asset-table .rmm-col-hostname,
  #rmm-asset-table .rmm-col-agentid,
  #rmm-asset-table .rmm-col-status,
  #rmm-asset-table .rmm-col-lastseen,
  #rmm-asset-table .rmm-col-updated {
    white-space: nowrap !important;
  }

  #rmm-asset-table .rmm-col-agentid code {
    display: block !important;
    width: 100% !important;
    max-width: 100% !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: nowrap !important;
  }

  #rmm-asset-table .rmm-col-asset {
    position: sticky !important;
    left: 0 !important;
    width: 220px !important;
    min-width: 220px !important;
    max-width: 220px !important;
    z-index: 30 !important;
    background: #fff !important;
    box-shadow: none !important;
  }

  #rmm-asset-table .rmm-col-client {
    position: sticky !important;
    left: 220px !important;
    width: 220px !important;
    min-width: 220px !important;
    max-width: 220px !important;
    z-index: 31 !important;
    background: #fff !important;
    box-shadow: 3px 0 5px rgba(0,0,0,.10) !important;
  }

  #rmm-asset-table thead .rmm-col-asset,
  #rmm-asset-table thead .rmm-col-client {
    z-index: 60 !important;
    background: #fff !important;
  }

  #rmm-asset-table tbody tr:nth-of-type(odd) .rmm-col-asset,
  #rmm-asset-table tbody tr:nth-of-type(odd) .rmm-col-client {
    background: rgba(0,0,0,.035) !important;
  }

  #rmm-asset-table tbody tr:nth-of-type(even) .rmm-col-asset,
  #rmm-asset-table tbody tr:nth-of-type(even) .rmm-col-client {
    background: #fff !important;
  }

  #rmm-asset-table .rmm-col-actions {
    white-space: normal !important;
  }

  #rmm-asset-table .rmm-col-actions .btn {
    margin-bottom: .25rem !important;
  }

  #rmm-asset-table tbody tr {
    height: auto !important;
  }

  @media (max-width: 1200px) {
    #rmm-asset-table {
      min-width: 1320px !important;
      width: 1320px !important;
    }

    #rmm-asset-table .rmm-colgroup-asset,
    #rmm-asset-table .rmm-col-asset {
      width: 200px !important;
      min-width: 200px !important;
      max-width: 200px !important;
    }

    #rmm-asset-table .rmm-colgroup-client,
    #rmm-asset-table .rmm-col-client {
      width: 200px !important;
      min-width: 200px !important;
      max-width: 200px !important;
    }

    #rmm-asset-table .rmm-col-client {
      left: 200px !important;
    }
  }
</style>



<style>
  /*
   * Asset Mapping sticky-column bleed fix:
   * block-level clipping prevents moving columns from visually painting under frozen columns.
   */
  .rmm-sticky-table-wrap {
    isolation: isolate !important;
  }

  #rmm-asset-table th,
  #rmm-asset-table td {
    position: relative;
    overflow: hidden !important;
  }

  #rmm-asset-table .rmm-cell-clip {
    display: block !important;
    width: 100% !important;
    max-width: 100% !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: nowrap !important;
  }

  #rmm-asset-table .rmm-col-asset,
  #rmm-asset-table .rmm-col-client {
    position: sticky !important;
    background-clip: padding-box !important;
    overflow: hidden !important;
  }

  #rmm-asset-table .rmm-col-asset {
    left: 0 !important;
    z-index: 200 !important;
  }

  #rmm-asset-table .rmm-col-client {
    left: 220px !important;
    z-index: 210 !important;
  }

  #rmm-asset-table thead .rmm-col-asset {
    z-index: 300 !important;
  }

  #rmm-asset-table thead .rmm-col-client {
    z-index: 310 !important;
  }

  #rmm-asset-table .rmm-col-client::after {
    content: "";
    position: absolute;
    top: 0;
    right: -1px;
    bottom: 0;
    width: 10px;
    background: inherit;
    box-shadow: 4px 0 6px rgba(0,0,0,.12);
    pointer-events: none;
  }

  #rmm-asset-table .rmm-col-hostname,
  #rmm-asset-table .rmm-col-agentid,
  #rmm-asset-table .rmm-col-status,
  #rmm-asset-table .rmm-col-lastseen,
  #rmm-asset-table .rmm-col-updated,
  #rmm-asset-table .rmm-col-actions {
    z-index: 1 !important;
  }

  @media (max-width: 1200px) {
    #rmm-asset-table .rmm-col-client {
      left: 200px !important;
    }
  }
</style>



<style>
  /*
   * Asset Mapping final layout:
   * two frozen columns, fixed widths, clipped moving cells.
   */
  .rmm-sticky-table-wrap {
    isolation: isolate !important;
  }

  #rmm-asset-table {
    table-layout: fixed !important;
    border-collapse: separate !important;
    border-spacing: 0 !important;
    min-width: 1400px !important;
    width: 1400px !important;
  }

  #rmm-asset-table .rmm-colgroup-asset {
    width: 230px !important;
  }

  #rmm-asset-table .rmm-colgroup-client {
    width: 245px !important;
  }

  #rmm-asset-table .rmm-colgroup-hostname {
    width: 210px !important;
  }

  #rmm-asset-table .rmm-colgroup-agentid {
    width: 285px !important;
  }

  #rmm-asset-table .rmm-colgroup-status {
    width: 95px !important;
  }

  #rmm-asset-table .rmm-colgroup-lastseen {
    width: 135px !important;
  }

  #rmm-asset-table .rmm-colgroup-updated {
    width: 125px !important;
  }

  #rmm-asset-table .rmm-colgroup-actions {
    width: 175px !important;
  }

  #rmm-asset-table th,
  #rmm-asset-table td {
    box-sizing: border-box !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    vertical-align: top !important;
  }

  #rmm-asset-table th {
    white-space: nowrap !important;
  }

  #rmm-asset-table .rmm-cell-clip,
  #rmm-asset-table .rmm-col-agentid code {
    display: block !important;
    width: 100% !important;
    max-width: 100% !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: nowrap !important;
  }

  #rmm-asset-table .rmm-col-hostname,
  #rmm-asset-table .rmm-col-agentid,
  #rmm-asset-table .rmm-col-status,
  #rmm-asset-table .rmm-col-lastseen,
  #rmm-asset-table .rmm-col-updated {
    white-space: nowrap !important;
  }

  #rmm-asset-table .rmm-col-hostname,
  #rmm-asset-table .rmm-col-agentid,
  #rmm-asset-table .rmm-col-status,
  #rmm-asset-table .rmm-col-lastseen,
  #rmm-asset-table .rmm-col-updated,
  #rmm-asset-table .rmm-col-actions {
    position: relative !important;
    z-index: 1 !important;
    background: transparent !important;
  }

  #rmm-asset-table .rmm-col-asset,
  #rmm-asset-table .rmm-col-client {
    position: sticky !important;
    background-clip: padding-box !important;
    overflow: hidden !important;
    transform: translateZ(0) !important;
  }

  #rmm-asset-table .rmm-col-asset {
    left: 0 !important;
    width: 230px !important;
    min-width: 230px !important;
    max-width: 230px !important;
    z-index: 400 !important;
    background: #fff !important;
  }

  #rmm-asset-table .rmm-col-client {
    left: 230px !important;
    width: 245px !important;
    min-width: 245px !important;
    max-width: 245px !important;
    z-index: 450 !important;
    background: #fff !important;
    box-shadow: 5px 0 8px rgba(0,0,0,.16) !important;
  }

  #rmm-asset-table thead .rmm-col-asset {
    z-index: 700 !important;
    background: #fff !important;
  }

  #rmm-asset-table thead .rmm-col-client {
    z-index: 750 !important;
    background: #fff !important;
  }

  #rmm-asset-table tbody tr:nth-of-type(odd) .rmm-col-asset,
  #rmm-asset-table tbody tr:nth-of-type(odd) .rmm-col-client {
    background: rgba(0,0,0,.035) !important;
  }

  #rmm-asset-table tbody tr:nth-of-type(even) .rmm-col-asset,
  #rmm-asset-table tbody tr:nth-of-type(even) .rmm-col-client {
    background: #fff !important;
  }

  #rmm-asset-table .rmm-col-client::after {
    content: "";
    position: absolute;
    top: 0;
    right: -14px;
    bottom: 0;
    width: 18px;
    background: inherit;
    box-shadow: 6px 0 10px rgba(0,0,0,.14);
    pointer-events: none;
    z-index: 999;
  }

  #rmm-asset-table .rmm-col-actions .btn {
    margin-bottom: .25rem !important;
  }
</style>



<style>
  /*
   * Asset Mapping split-table layout:
   * Left table is fixed/frozen. Right table scrolls.
   * This avoids browser sticky <td> paint-order bugs.
   */
  .rmm-asset-split-wrap {
    display: flex;
    align-items: stretch;
    border-top: 1px solid #dee2e6;
    overflow: hidden;
  }

  .rmm-asset-left-pane {
    flex: 0 0 475px;
    width: 475px;
    max-width: 475px;
    overflow: hidden;
    background: #fff;
    box-shadow: 5px 0 9px rgba(0,0,0,.14);
    z-index: 5;
  }

  .rmm-asset-right-pane {
    flex: 1 1 auto;
    min-width: 0;
    overflow: auto;
    background: #fff;
  }

  .rmm-asset-split-table {
    table-layout: fixed;
    border-collapse: separate;
    border-spacing: 0;
    margin-bottom: 0;
  }

  #rmm-asset-left-table {
    width: 475px;
  }

  #rmm-asset-left-table th:nth-child(1),
  #rmm-asset-left-table td:nth-child(1) {
    width: 230px;
  }

  #rmm-asset-left-table th:nth-child(2),
  #rmm-asset-left-table td:nth-child(2) {
    width: 245px;
  }

  #rmm-asset-right-table {
    min-width: 2015px;
    width: 2015px;
  }

  #rmm-asset-right-table th:nth-child(1),
  #rmm-asset-right-table td:nth-child(1) {
    width: 190px;
  }

  #rmm-asset-right-table th:nth-child(2),
  #rmm-asset-right-table td:nth-child(2) {
    width: 245px;
  }

  #rmm-asset-right-table th:nth-child(3),
  #rmm-asset-right-table td:nth-child(3) {
    width: 150px;
  }

  #rmm-asset-right-table th:nth-child(4),
  #rmm-asset-right-table td:nth-child(4) {
    width: 145px;
  }

  #rmm-asset-right-table th:nth-child(5),
  #rmm-asset-right-table td:nth-child(5) {
    width: 245px;
  }

  #rmm-asset-right-table th:nth-child(6),
  #rmm-asset-right-table td:nth-child(6) {
    width: 125px;
  }

  #rmm-asset-right-table th:nth-child(7),
  #rmm-asset-right-table td:nth-child(7) {
    width: 260px;
  }

  #rmm-asset-right-table th:nth-child(8),
  #rmm-asset-right-table td:nth-child(8) {
    width: 170px;
  }

  #rmm-asset-right-table th:nth-child(9),
  #rmm-asset-right-table td:nth-child(9) {
    width: 145px;
  }

  #rmm-asset-right-table th:nth-child(10),
  #rmm-asset-right-table td:nth-child(10) {
    width: 260px;
  }

  #rmm-asset-right-table th:nth-child(11),
  #rmm-asset-right-table td:nth-child(11) {
    width: 90px;
  }

  #rmm-asset-right-table th:nth-child(12),
  #rmm-asset-right-table td:nth-child(12) {
    width: 135px;
  }

  #rmm-asset-right-table th:nth-child(13),
  #rmm-asset-right-table td:nth-child(13) {
    width: 125px;
  }

  #rmm-asset-right-table th:nth-child(14),
  #rmm-asset-right-table td:nth-child(14) {
    width: 175px;
  }

  .rmm-asset-split-table thead th {
    position: sticky;
    top: 0;
    z-index: 20;
    background: #fff;
    white-space: nowrap;
    cursor: pointer;
    box-shadow: inset 0 -1px 0 rgba(0,0,0,.12);
  }

  .rmm-asset-split-table th,
  .rmm-asset-split-table td {
    box-sizing: border-box;
    overflow: hidden;
    text-overflow: ellipsis;
    vertical-align: top;
  }

  .rmm-cell-clip {
    display: block;
    width: 100%;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .rmm-split-asset-cell,
  .rmm-split-client-cell {
    background-clip: padding-box;
  }

  .rmm-split-actions-cell .btn {
    margin-bottom: .25rem;
  }

  .rmm-asset-split-table tr.rmm-filter-hidden {
    display: none !important;
  }

  .rmm-asset-split-table th.rmm-sort-active {
    background: #f1f3f5;
  }

  @media (max-width: 1200px) {
    .rmm-asset-left-pane {
      flex-basis: 430px;
      width: 430px;
      max-width: 430px;
    }

    #rmm-asset-left-table {
      width: 430px;
    }

    #rmm-asset-left-table th:nth-child(1),
    #rmm-asset-left-table td:nth-child(1) {
      width: 210px;
    }

    #rmm-asset-left-table th:nth-child(2),
    #rmm-asset-left-table td:nth-child(2) {
      width: 220px;
    }
  }
</style>



<style>
  .rmm-inline-fixmatch-form {
    min-width: 360px;
    max-width: 520px;
    padding: .5rem;
    border: 1px solid #dee2e6;
    border-radius: .25rem;
    background: #fff;
    box-shadow: 0 2px 8px rgba(0,0,0,.08);
  }

  .rmm-inline-fixmatch-form select {
    max-width: 100%;
  }
</style>



<script id="rmm-client-sort-hardfix2">
(function () {
  function textAt(row, index) {
    var cell = row.children[index];
    if (!cell) return "";
    return (cell.innerText || cell.textContent || "").replace(/\s+/g, " ").trim();
  }

  function normalize(value) {
    var text = (value || "").trim();

    var firstNumber = text.match(/^-?\d+(\.\d+)?/);
    if (firstNumber) {
      return { type: "number", value: parseFloat(firstNumber[0]) };
    }

    var compact = text.replace(/[, ]+/g, "");
    if (/^-?\d+(\.\d+)?$/.test(compact)) {
      return { type: "number", value: parseFloat(compact) };
    }

    var parsed = Date.parse(text);
    if (!Number.isNaN(parsed) && /\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}/.test(text)) {
      return { type: "date", value: parsed };
    }

    return { type: "text", value: text.toLowerCase() };
  }

  function compare(a, b, direction) {
    var av = normalize(a);
    var bv = normalize(b);

    if (av.type === bv.type) {
      if (av.value < bv.value) return -1 * direction;
      if (av.value > bv.value) return 1 * direction;
      return 0;
    }

    var at = String(av.value);
    var bt = String(bv.value);

    if (at < bt) return -1 * direction;
    if (at > bt) return 1 * direction;
    return 0;
  }

  function sortClientTable(header) {
    var table = document.getElementById("rmm-client-table");
    if (!table || !table.tBodies || !table.tBodies[0]) return;

    var index = parseInt(header.getAttribute("data-client-sort-index"), 10);
    if (Number.isNaN(index)) return;

    var tbody = table.tBodies[0];
    var headers = Array.prototype.slice.call(table.querySelectorAll("thead th[data-client-sort-index]"));
    var nextDirection = header.getAttribute("data-client-sort-direction") === "asc" ? "desc" : "asc";
    var direction = nextDirection === "asc" ? 1 : -1;

    headers.forEach(function (h) {
      h.removeAttribute("data-client-sort-direction");
      h.classList.remove("rmm-sort-active");
      var i = h.querySelector(".rmm-client-sort-indicator");
      if (i) i.textContent = "↕";
    });

    header.setAttribute("data-client-sort-direction", nextDirection);
    header.classList.add("rmm-sort-active");

    var indicator = header.querySelector(".rmm-client-sort-indicator");
    if (indicator) indicator.textContent = nextDirection === "asc" ? "▲" : "▼";

    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));

    rows.sort(function (ra, rb) {
      return compare(textAt(ra, index), textAt(rb, index), direction);
    });

    rows.forEach(function (row) {
      tbody.appendChild(row);
    
      if (typeof window.rmmFinalClientSearch === "function") { window.setTimeout(window.rmmFinalClientSearch, 0); }
});
  }

  function bindClientSorter() {
    var table = document.getElementById("rmm-client-table");
    if (!table) return;

    table.querySelectorAll("thead th[data-client-sort-index]").forEach(function (th) {
      th.style.cursor = "pointer";
      th.style.userSelect = "none";
      th.title = "Click to sort";

      if (th.getAttribute("data-client-sort-hardbound") === "1") return;
      th.setAttribute("data-client-sort-hardbound", "1");

      th.addEventListener("click", function (event) {
        event.preventDefault();
        event.stopPropagation();
        if (typeof event.stopImmediatePropagation === "function") {
          event.stopImmediatePropagation();
        }
        sortClientTable(th);
        return false;
      }, true);
    });
  }

  document.addEventListener("click", function (event) {
    var th = event.target.closest && event.target.closest("#rmm-client-table thead th[data-client-sort-index]");
    if (!th) return;

    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }

    sortClientTable(th);
    
      if (typeof window.rmmFinalClientSearch === "function") { window.setTimeout(window.rmmFinalClientSearch, 0); window.setTimeout(window.rmmFinalClientSearch, 50); }
return false;
  }, true);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindClientSorter);
  } else {
    bindClientSorter();
  }

  setTimeout(bindClientSorter, 250);
  setTimeout(bindClientSorter, 1000);
  setTimeout(bindClientSorter, 2000);
})();
</script>

<style id="rmm-client-sort-hardfix2-style">
  #rmm-client-table thead th[data-client-sort-index] {
    cursor: pointer !important;
    user-select: none !important;
    white-space: nowrap;
  }

  #rmm-client-table thead th[data-client-sort-index]:hover {
    background: rgba(0,0,0,.04);
  }

  #rmm-client-table thead th.rmm-sort-active {
    background: #f1f3f5 !important;
  }

  .rmm-client-sort-indicator {
    opacity: .55;
    font-size: .72em;
    margin-left: 6px;
    font-weight: normal;
  }
</style>


<script id="rmm-asset-split-sort-hardfix">
(function () {
  function normalizeSortValue(value) {
    var text = (value || "").replace(/\s+/g, " ").trim();

    var firstNumber = text.match(/^-?\d+(\.\d+)?/);
    if (firstNumber) {
      return { type: "number", value: parseFloat(firstNumber[0]) };
    }

    var compact = text.replace(/[, ]+/g, "");
    if (/^-?\d+(\.\d+)?$/.test(compact)) {
      return { type: "number", value: parseFloat(compact) };
    }

    var parsedDate = Date.parse(text);
    if (!Number.isNaN(parsedDate) && /\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}/.test(text)) {
      return { type: "date", value: parsedDate };
    }

    return { type: "text", value: text.toLowerCase() };
  }

  function compareValues(a, b, direction) {
    var av = normalizeSortValue(a);
    var bv = normalizeSortValue(b);

    if (av.type === bv.type) {
      if (av.value < bv.value) return -1 * direction;
      if (av.value > bv.value) return 1 * direction;
      return 0;
    }

    var at = String(av.value);
    var bt = String(bv.value);

    if (at < bt) return -1 * direction;
    if (at > bt) return 1 * direction;
    return 0;
  }

  function getAssetSplitParts() {
    var wrap = document.getElementById("rmm-asset-split-wrap");
    var leftPane = document.getElementById("rmm-asset-left-pane");
    var rightPane = document.getElementById("rmm-asset-right-pane");
    var leftTable = document.getElementById("rmm-asset-left-table");
    var rightTable = document.getElementById("rmm-asset-right-table");

    if (!wrap || !leftPane || !rightPane || !leftTable || !rightTable) return null;
    if (!leftTable.tBodies[0] || !rightTable.tBodies[0]) return null;

    return {
      wrap: wrap,
      leftPane: leftPane,
      rightPane: rightPane,
      leftTable: leftTable,
      rightTable: rightTable,
      leftBody: leftTable.tBodies[0],
      rightBody: rightTable.tBodies[0]
    };
  }

  function buildRightRowMap(parts) {
    var map = {};
    Array.prototype.slice.call(parts.rightBody.querySelectorAll("tr[data-row-key]")).forEach(function (row) {
      map[row.getAttribute("data-row-key")] = row;
    });
    return map;
  }

  var rmmAssetHeightSyncPending = false;

  function syncAssetSplitRowHeights() {
    /*
     * Lightweight alignment sync:
     * - runs only when explicitly called
     * - batches in requestAnimationFrame
     * - skips hidden filtered rows
     * This keeps the split table aligned without the old constant measuring loop.
     */
    if (rmmAssetHeightSyncPending) return;
    rmmAssetHeightSyncPending = true;

    window.requestAnimationFrame(function () {
      rmmAssetHeightSyncPending = false;

      var parts = getAssetSplitParts();
      if (!parts) return;

      var rightByKey = buildRightRowMap(parts);
      var leftRows = Array.prototype.slice.call(parts.leftBody.querySelectorAll("tr[data-row-key]"));

      leftRows.forEach(function (leftRow) {
        var key = leftRow.getAttribute("data-row-key");
        var rightRow = rightByKey[key];
        if (!rightRow) return;

        leftRow.style.height = "";
        rightRow.style.height = "";

        if (
          leftRow.classList.contains("rmm-filter-hidden") ||
          rightRow.classList.contains("rmm-filter-hidden")
        ) {
          return;
        }

        var h = Math.max(leftRow.getBoundingClientRect().height, rightRow.getBoundingClientRect().height);
        h = Math.ceil(h);

        if (h > 0) {
          leftRow.style.height = h + "px";
          rightRow.style.height = h + "px";
        }
      });
    });
  }

  function sortAssetSplitBy(key, header) {
    var parts = getAssetSplitParts();
    if (!parts || !key) return;

    var rightByKey = buildRightRowMap(parts);
    var leftRows = Array.prototype.slice.call(parts.leftBody.querySelectorAll("tr[data-row-key]"));

    var nextDirection = header.getAttribute("data-asset-sort-direction") === "asc" ? "desc" : "asc";
    var direction = nextDirection === "asc" ? 1 : -1;

    parts.wrap.querySelectorAll("th[data-sort-key]").forEach(function (h) {
      h.removeAttribute("data-asset-sort-direction");
      h.classList.remove("rmm-sort-active");
      var indicator = h.querySelector(".rmm-sort-indicator");
      if (indicator) indicator.textContent = "↕";
    });

    header.setAttribute("data-asset-sort-direction", nextDirection);
    header.classList.add("rmm-sort-active");

    var activeIndicator = header.querySelector(".rmm-sort-indicator");
    if (activeIndicator) activeIndicator.textContent = nextDirection === "asc" ? "▲" : "▼";

    leftRows.sort(function (a, b) {
      var av = a.getAttribute("data-sort-" + key) || "";
      var bv = b.getAttribute("data-sort-" + key) || "";
      return compareValues(av, bv, direction);
    });

    leftRows.forEach(function (leftRow) {
      var rowKey = leftRow.getAttribute("data-row-key");
      var rightRow = rightByKey[rowKey];

      parts.leftBody.appendChild(leftRow);
      if (rightRow) parts.rightBody.appendChild(rightRow);
    });

    syncAssetSplitRowHeights();
  }

  function applyAssetSplitFilters() {
    var parts = getAssetSplitParts();
    if (!parts) return;

    var input = document.querySelector('.rmm-asset-split-filter[data-target="#rmm-asset-split-wrap"]');
    var textFilter = input ? input.value.trim().toLowerCase() : "";

    var activeStatus = "";
    var statusGroup = document.querySelector('.rmm-asset-split-status[data-target="#rmm-asset-split-wrap"]');
    if (statusGroup) {
      var activeButton = statusGroup.querySelector("button.active");
      if (activeButton) activeStatus = (activeButton.getAttribute("data-status") || "").toLowerCase();
    }

    var rightByKey = buildRightRowMap(parts);
    var leftRows = Array.prototype.slice.call(parts.leftBody.querySelectorAll("tr[data-row-key]"));

    leftRows.forEach(function (leftRow) {
      var rowKey = leftRow.getAttribute("data-row-key");
      var rightRow = rightByKey[rowKey];

      var filterText = (leftRow.getAttribute("data-filter") || "").toLowerCase();
      var status = (leftRow.getAttribute("data-rmm-status") || "").toLowerCase();

      var textOk = !textFilter || filterText.indexOf(textFilter) !== -1;
      var statusOk = !activeStatus || status === activeStatus;
      var hidden = !(textOk && statusOk);

      leftRow.classList.toggle("rmm-filter-hidden", hidden);
      if (rightRow) rightRow.classList.toggle("rmm-filter-hidden", hidden);
    });

    syncAssetSplitRowHeights();
  }

  function bindAssetSplitSorter() {
    var parts = getAssetSplitParts();
    if (!parts) return;

    parts.wrap.querySelectorAll("th[data-sort-key]").forEach(function (th) {
      var key = th.getAttribute("data-sort-key");
      if (!key || key === "actions") return;

      th.style.cursor = "pointer";
      th.style.userSelect = "none";
      th.title = "Click to sort";

      if (!th.querySelector(".rmm-sort-indicator")) {
        var indicator = document.createElement("span");
        indicator.className = "rmm-sort-indicator";
        indicator.textContent = "↕";
        th.appendChild(indicator);
      }

      if (th.getAttribute("data-asset-sort-hardbound") === "1") return;
      th.setAttribute("data-asset-sort-hardbound", "1");

      th.addEventListener("click", function (event) {
        event.preventDefault();
        event.stopPropagation();
        if (typeof event.stopImmediatePropagation === "function") {
          event.stopImmediatePropagation();
        }

        sortAssetSplitBy(key, th);
        return false;
      }, true);
    });

    if (parts.rightPane.getAttribute("data-asset-scroll-sync-bound") !== "1") {
      parts.rightPane.setAttribute("data-asset-scroll-sync-bound", "1");
      parts.rightPane.addEventListener("scroll", function () {
        parts.leftPane.scrollTop = parts.rightPane.scrollTop;
      });
    }

    document.querySelectorAll(".rmm-asset-split-filter").forEach(function (input) {
      if (input.getAttribute("data-asset-filter-hardbound") === "1") return;
      input.setAttribute("data-asset-filter-hardbound", "1");
      input.addEventListener("input", applyAssetSplitFilters);
    });

    document.querySelectorAll(".rmm-asset-split-status").forEach(function (group) {
      if (group.getAttribute("data-asset-status-hardbound") === "1") return;
      group.setAttribute("data-asset-status-hardbound", "1");

      group.querySelectorAll("button").forEach(function (button) {
        button.addEventListener("click", function (event) {
          event.preventDefault();

          group.querySelectorAll("button").forEach(function (b) {
            b.classList.remove("active");
          });

          button.classList.add("active");
          applyAssetSplitFilters();
        });
      });
    });

    syncAssetSplitRowHeights();
  }

  document.addEventListener("click", function (event) {
    var th = event.target.closest && event.target.closest("#rmm-asset-split-wrap th[data-sort-key]");
    if (!th) return;

    var key = th.getAttribute("data-sort-key");
    if (!key || key === "actions") return;

    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }

    sortAssetSplitBy(key, th);
    return false;
  }, true);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindAssetSplitSorter);
  } else {
    bindAssetSplitSorter();
  }

  setTimeout(bindAssetSplitSorter, 250);
  setTimeout(bindAssetSplitSorter, 1000);
  setTimeout(syncAssetSplitRowHeights, 250);
  setTimeout(syncAssetSplitRowHeights, 1000);
  setTimeout(syncAssetSplitRowHeights, 2000);
  window.addEventListener("resize", syncAssetSplitRowHeights);
})();
</script>

<style id="rmm-asset-split-sort-hardfix-style">
  #rmm-asset-split-wrap th[data-sort-key] {
    cursor: pointer !important;
    user-select: none !important;
    white-space: nowrap;
  }

  #rmm-asset-split-wrap th[data-sort-key]:hover {
    background: rgba(0,0,0,.04) !important;
  }

  #rmm-asset-split-wrap th.rmm-sort-active {
    background: #f1f3f5 !important;
  }

  #rmm-asset-split-wrap .rmm-sort-indicator {
    opacity: .55;
    font-size: .72em;
    margin-left: 6px;
    font-weight: normal;
  }

  #rmm-asset-split-wrap tr.rmm-filter-hidden {
    display: none !important;
  }
</style>

<style id="rmm-asset-performance-style">
  /*
   * Asset Mapping split-table alignment mode:
   * rows are allowed to size naturally, then the lightweight JS sync
   * gives the matching frozen/right rows the same height.
   */
  #rmm-asset-split-wrap {
    contain: layout paint;
  }

  #rmm-asset-left-table,
  #rmm-asset-right-table {
    table-layout: auto;
  }

  #rmm-asset-left-table tbody td,
  #rmm-asset-right-table tbody td {
    vertical-align: top !important;
    padding-top: .45rem !important;
    padding-bottom: .45rem !important;
  }

  #rmm-asset-left-table tbody tr,
  #rmm-asset-right-table tbody tr {
    min-height: 52px;
  }

  #rmm-asset-left-table .rmm-split-asset-cell,
  #rmm-asset-left-table .rmm-split-client-cell,
  #rmm-asset-right-table .rmm-cell-clip {
    line-height: 1.2 !important;
  }

  #rmm-asset-left-table .rmm-split-asset-cell small {
    display: block;
  }

  #rmm-asset-right-table .rmm-split-actions-cell {
    white-space: nowrap;
  }

  .rmm-inline-fixmatch-form {
    position: relative;
    z-index: 20;
  }
</style>

<template id="rmm-agent-options-template-top-linebased">
  <option value="">Select TacticalRMM agent...</option>
  <?php foreach (($trmm_agents ?? []) as $lazy_agent): ?>
    <?php
      $lazy_agent_id = $lazy_agent['trmm_agent_id'] ?? $lazy_agent['agent_id'] ?? '';
      if ($lazy_agent_id === '') {
          continue;
      }

      $lazy_hostname = $lazy_agent['hostname'] ?? $lazy_agent['name'] ?? 'Unknown Host';
      $lazy_description = $lazy_agent['description'] ?? '';
      $lazy_client = $lazy_agent['trmm_client_name'] ?? $lazy_agent['client_name'] ?? '';
      $lazy_site = $lazy_agent['trmm_site_name'] ?? $lazy_agent['site_name'] ?? '';
      $lazy_status = $lazy_agent['status'] ?? '';

      $lazy_label_parts = [];
      $lazy_label_parts[] = $lazy_hostname;
      if ($lazy_description !== '') {
          $lazy_label_parts[] = '- ' . $lazy_description;
      }
      if ($lazy_client !== '' || $lazy_site !== '') {
          $lazy_label_parts[] = '(' . trim($lazy_client . ($lazy_site !== '' ? ' / ' . $lazy_site : '')) . ')';
      }
      if ($lazy_status !== '') {
          $lazy_label_parts[] = '[' . $lazy_status . ']';
      }
      $lazy_label_parts[] = '[' . $lazy_agent_id . ']';
      $lazy_label = trim(implode(' ', $lazy_label_parts));
    ?>
    <option value="<?= rmm_h($lazy_agent_id) ?>"><?= rmm_h($lazy_label) ?></option>
  <?php endforeach; ?>
</template>

<script id="rmm-top-asset-linebased-fix">
(function () {
  function qsa(root, selector) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function populate(select) {
    if (!select || select.getAttribute("data-full-agent-options-loaded") === "1") return;

    var currentValue = select.value || select.getAttribute("data-current-agent-id") || "";
    var currentLabel = select.options.length ? select.options[0].textContent : "Current TacticalRMM agent";

    while (select.firstChild) {
      select.removeChild(select.firstChild);
    }

    var template = document.getElementById("rmm-agent-options-template-top-linebased");
    if (template && template.content) {
      select.appendChild(template.content.cloneNode(true));
    }

    if (select.options.length <= 1 && Array.isArray(window.rmmAgentOptions)) {
      var blank = document.createElement("option");
      blank.value = "";
      blank.textContent = "Select TacticalRMM agent...";
      select.appendChild(blank);

      window.rmmAgentOptions.forEach(function (agent) {
        var value = String(agent.value || agent.id || agent.trmm_agent_id || agent.agent_id || "");
        if (!value) return;

        var hostname = agent.hostname || agent.name || "Unknown Host";
        var desc = agent.description ? " - " + agent.description : "";
        var client = agent.client || agent.client_name || agent.trmm_client_name || "";
        var site = agent.site || agent.site_name || agent.trmm_site_name || "";
        var status = agent.status ? " [" + agent.status + "]" : "";
        var where = (client || site) ? " (" + [client, site].filter(Boolean).join(" / ") + ")" : "";

        var opt = document.createElement("option");
        opt.value = value;
        opt.textContent = hostname + desc + where + status + " [" + value + "]";
        select.appendChild(opt);
      });
    }

    var found = false;
    qsa(select, "option").forEach(function (opt) {
      if (opt.value === currentValue) {
        opt.selected = true;
        found = true;
      }
    });

    if (currentValue && !found) {
      var current = document.createElement("option");
      current.value = currentValue;
      current.textContent = currentLabel;
      current.selected = true;
      select.insertBefore(current, select.firstChild);
    }

    select.value = currentValue;
    select.setAttribute("data-full-agent-options-loaded", "1");
  }

  function bind() {
    var selects = qsa(document, "#rmm-asset-split-wrap .rmm-top-asset-linebased-agent-select");

    selects.forEach(function (select) {
      if (select.getAttribute("data-top-linebased-bound") === "1") return;
      select.setAttribute("data-top-linebased-bound", "1");

      ["pointerdown", "mousedown", "focus", "click"].forEach(function (eventName) {
        select.addEventListener(eventName, function () {
          populate(select);
        });
      });
    });

    document.documentElement.setAttribute("data-rmm-top-linebased-select-count", String(selects.length));

    if (typeof window.syncAssetSplitRowHeights === "function") {
      setTimeout(window.syncAssetSplitRowHeights, 50);
      setTimeout(window.syncAssetSplitRowHeights, 500);
    }
  }

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !form.classList || !form.classList.contains("rmm-top-asset-linebased-fixmatch-form")) return;

    var select = form.querySelector('select[name="trmm_agent_id"]');
    if (!select || !select.value) {
      event.preventDefault();
      alert("Select a TacticalRMM agent before saving.");
      return false;
    }
  }, true);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }

  setTimeout(bind, 250);
  setTimeout(bind, 1000);

  window.rmmTopAssetLinebasedFix = {
    bind: bind,
    populate: populate
  };
})();
</script>

<style id="rmm-top-asset-linebased-fix-style">
  #rmm-asset-split-wrap .rmm-top-asset-linebased-fixmatch-form {
    display: block;
    min-width: 430px;
    max-width: 760px;
    margin-bottom: .35rem;
  }

  #rmm-asset-split-wrap .rmm-top-asset-linebased-agent-select {
    min-width: 420px;
    max-width: 620px;
  }

  #rmm-asset-split-wrap .rmm-top-asset-linebased-save {
    display: inline-block;
    margin-bottom: .35rem;
  }
</style>


<script id="rmm-client-current-only-lazy-selects">
(function () {
  function qsa(root, selector) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function actionValue(form) {
    var action = form ? form.querySelector('input[name="action"]') : null;
    return action ? action.value : "";
  }

  function isClientMappingSelect(select) {
    if (!select || select.name !== "trmm_client_id") return false;
    var form = select.closest("form");
    if (!form) return false;

    /*
     * Keep this scoped to Client Mapping manual mapping forms.
     * Asset Mapping uses trmm_agent_id and is not touched.
     */
    var action = actionValue(form);
    return action === "manual_client_match_select" ||
           action === "client_manual_match" ||
           action === "save_client_mapping" ||
           !!form.closest("#rmm-client-map-table") ||
           !!select.closest("#rmm-client-map-table");
  }

  function optionKey(opt) {
    return String(opt.value || "") + "\\n" + String(opt.textContent || "");
  }

  function harvestOptions() {
    if (window.rmmClientLazyOptionTemplate && window.rmmClientLazyOptionTemplate.length) {
      return window.rmmClientLazyOptionTemplate;
    }

    var seen = {};
    var template = [];

    qsa(document, 'select[name="trmm_client_id"]').forEach(function (select) {
      if (!isClientMappingSelect(select)) return;

      qsa(select, "option").forEach(function (opt) {
        var key = optionKey(opt);
        if (seen[key]) return;
        seen[key] = true;

        template.push({
          value: opt.value,
          text: opt.textContent,
          disabled: !!opt.disabled
        });
      });
    });

    window.rmmClientLazyOptionTemplate = template;
    return template;
  }

  function collapseToCurrent(select) {
    if (select.getAttribute("data-client-current-only-ready") === "1") return;

    var selected = select.options[select.selectedIndex] || null;
    var currentValue = select.value || "";
    var currentText = selected ? selected.textContent : "";

    if (!currentText || !currentText.trim()) {
      currentText = currentValue ? ("Current TacticalRMM client [" + currentValue + "]") : "Select TacticalRMM client...";
    }

    while (select.firstChild) {
      select.removeChild(select.firstChild);
    }

    var opt = document.createElement("option");
    opt.value = currentValue;
    opt.textContent = currentText;
    opt.selected = true;
    select.appendChild(opt);

    select.setAttribute("data-client-current-value", currentValue);
    select.setAttribute("data-client-current-text", currentText);
    select.setAttribute("data-client-full-loaded", "0");
    select.setAttribute("data-client-current-only-ready", "1");
  }

  function loadFull(select) {
    if (!select || select.getAttribute("data-client-full-loaded") === "1") return;

    var currentValue = select.value || select.getAttribute("data-client-current-value") || "";
    var currentText = select.getAttribute("data-client-current-text") || "Current TacticalRMM client";
    var template = harvestOptions();

    while (select.firstChild) {
      select.removeChild(select.firstChild);
    }

    var found = false;

    template.forEach(function (item) {
      var opt = document.createElement("option");
      opt.value = item.value;
      opt.textContent = item.text;
      opt.disabled = !!item.disabled;

      if (item.value === currentValue) {
        opt.selected = true;
        found = true;
      }

      select.appendChild(opt);
    });

    if (currentValue && !found) {
      var cur = document.createElement("option");
      cur.value = currentValue;
      cur.textContent = currentText;
      cur.selected = true;
      select.insertBefore(cur, select.firstChild);
    }

    select.value = currentValue;
    select.setAttribute("data-client-full-loaded", "1");
  }

  function bind() {
    var selects = qsa(document, 'select[name="trmm_client_id"]').filter(isClientMappingSelect);

    harvestOptions();

    selects.forEach(function (select) {
      collapseToCurrent(select);

      if (select.getAttribute("data-client-lazy-bound") === "1") return;
      select.setAttribute("data-client-lazy-bound", "1");

      ["pointerdown", "mousedown", "focus", "click"].forEach(function (eventName) {
        select.addEventListener(eventName, function () {
          loadFull(select);
        });
      });
    });

    document.documentElement.setAttribute("data-rmm-client-lazy-select-count", String(selects.length));
    document.documentElement.setAttribute(
      "data-rmm-client-lazy-option-count",
      String((window.rmmClientLazyOptionTemplate || []).length)
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }

  setTimeout(bind, 250);
  setTimeout(bind, 1000);

  window.rmmClientCurrentOnlyLazySelects = {
    bind: bind,
    loadFull: loadFull,
    harvestOptions: harvestOptions
  };
})();
</script>

<style id="rmm-client-current-only-lazy-selects-style">
  select[name="trmm_client_id"][data-client-current-only-ready="1"] {
    min-width: 320px;
    max-width: 520px;
  }
</style>


<style id="rmm-asset-mapping-polish-style">
  #rmm-asset-split-wrap .rmm-asset-mapping-status-badge {
    white-space: nowrap;
  }

  #rmm-asset-split-wrap .rmm-top-asset-linebased-save {
    margin-right: .25rem;
  }
</style>


<style id="rmm-asset-unified-conflicts-style">
  #rmm-asset-split-wrap .rmm-unified-conflict-left-row td,
  #rmm-asset-split-wrap .rmm-unified-conflict-right-row td {
    background-color: rgba(255, 193, 7, .08);
  }

  #rmm-asset-split-wrap .rmm-unified-conflict-right-row .rmm-split-actions-cell .form-inline {
    display: block;
  }

  #rmm-asset-split-wrap .rmm-unified-conflict-right-row .rmm-split-actions-cell select {
    min-width: 320px;
    max-width: 520px;
  }
</style>


<style id="rmm-site-location-mapping-style">
  #rmm-site-location-table td {
    vertical-align: middle;
  }

  #rmm-site-location-table .form-inline {
    align-items: flex-start;
  }

  #rmm-site-location-table select {
    min-width: 260px;
    max-width: 360px;
  }

  #rmm-site-location-table td:nth-child(8) form {
    display: block;
  }

  #rmm-site-location-table td:nth-child(8) .btn {
    min-width: 148px;
    text-align: left;
  }
</style>


<style id="rmm-site-header-badges-style">
  .card.card-dark .card-tools .badge {
    font-size: 0.75rem;
    vertical-align: middle;
  }

  #rmm-site-location-table td {
    vertical-align: middle;
  }
</style>


<style id="rmm-mapping-tab-badges-style">
  .card.card-dark .card-tools .badge {
    font-size: 0.75rem;
    vertical-align: middle;
  }
</style>


<style id="rmm-asset-top-client-style">
  #rmm-asset-row-limit {
    min-width: 84px;
  }

  .rmm-asset-card .card-body > .rmm-table-filter {
    max-width: 640px;
  }
</style>


<style id="rmm-final-mapping-search-style">
  tr.rmm-final-search-hidden,
  tr.rmm-filter-hidden {
    display: none !important;
  }
</style>


<script id="rmm-final-mapping-search">
(function () {
  "use strict";

  function norm(value) {
    return String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
  }

  function showRow(row, visible) {
    if (!row) return;
    row.classList.remove("rmm-filter-hidden");
    row.classList.toggle("rmm-final-search-hidden", !visible);
    row.style.display = visible ? "" : "none";
  }

  function filterNormalTable(target, query) {
    var q = norm(query);
    var rows = Array.prototype.slice.call(target.querySelectorAll("tbody tr"));

    rows.forEach(function (row) {
      var haystack = norm(row.textContent || "");
      showRow(row, !q || haystack.indexOf(q) !== -1);
    });
  }

  function rowKey(row) {
    if (!row) return "";
    return row.getAttribute("data-row-key") ||
           row.getAttribute("data-asset-row-key") ||
           row.dataset.rowKey ||
           "";
  }

  function filterAssetSplitTable(target, query) {
    var q = norm(query);
    var leftRows = Array.prototype.slice.call(target.querySelectorAll("#rmm-asset-left-table tbody tr"));
    var rightRows = Array.prototype.slice.call(target.querySelectorAll("#rmm-asset-right-table tbody tr"));

    var rightByKey = {};
    rightRows.forEach(function (row, idx) {
      var key = rowKey(row) || ("idx-" + idx);
      rightByKey[key] = row;
    });

    leftRows.forEach(function (left, idx) {
      var key = rowKey(left) || ("idx-" + idx);
      var right = rightByKey[key] || rightRows[idx] || null;
      var haystack = norm((left ? left.textContent : "") + " " + (right ? right.textContent : ""));
      var visible = !q || haystack.indexOf(q) !== -1;
      showRow(left, visible);
      showRow(right, visible);
    });

    // Hide any right rows that did not have a matching left row.
    rightRows.forEach(function (right, idx) {
      var key = rowKey(right) || ("idx-" + idx);
      var hasLeft = leftRows.some(function (left, leftIdx) {
        return (rowKey(left) || ("idx-" + leftIdx)) === key;
      });
      if (!hasLeft) {
        var haystack = norm(right.textContent || "");
        showRow(right, !q || haystack.indexOf(q) !== -1);
      }
    });

    if (typeof window.rmmAssetSplitSyncHeights === "function") {
      window.rmmAssetSplitSyncHeights();
    }
  }

  function applyFilter(input) {
    if (!input) return;
    var selector = input.getAttribute("data-target");
    if (!selector) return;

    var target = document.querySelector(selector);
    if (!target) return;

    if (target.id === "rmm-asset-split-wrap") {
      filterAssetSplitTable(target, input.value);
    } else {
      filterNormalTable(target, input.value);
    }
  }

  function bindFinalMappingSearch() {
    var inputs = Array.prototype.slice.call(document.querySelectorAll(
      'input.rmm-table-filter[data-target="#rmm-site-location-table"],' +
      'input.rmm-table-filter[data-target="#rmm-asset-split-wrap"],' +
      'input.rmm-asset-split-filter[data-target="#rmm-asset-split-wrap"]'
    ));

    inputs.forEach(function (input) {
      if (input.dataset.rmmFinalSearchBound === "1") {
        applyFilter(input);
        return;
      }

      input.dataset.rmmFinalSearchBound = "1";

      input.addEventListener("input", function () {
        applyFilter(input);
      });

      input.addEventListener("search", function () {
        applyFilter(input);
      });

      input.addEventListener("keyup", function () {
        applyFilter(input);
      });

      applyFilter(input);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindFinalMappingSearch);
  } else {
    bindFinalMappingSearch();
  }

  window.rmmFinalMappingSearch = bindFinalMappingSearch;
})();
</script>



<style id="rmm-final-client-search-style">
  #rmm-client-table tbody tr.rmm-client-final-search-hidden {
    display: none !important;
    visibility: collapse !important;
  }
</style>


<script id="rmm-final-client-search">
(function () {
  "use strict";

  function norm(value) {
    return String(value || "").toLowerCase().replace(/\s+/g, " ").trim();
  }

  function getClientSearchInput() {
    return document.querySelector('input.rmm-client-final-filter[data-target="#rmm-client-table"]') || document.querySelector('input[data-target="#rmm-client-table"]');
  }

  function getRowText(row) {
    if (!row) return "";

    /*
     * Do NOT use row.textContent here.
     * The Client Mapping row contains a TacticalRMM dropdown with every
     * possible TacticalRMM client as <option> text. row.textContent therefore
     * makes every valid TacticalRMM/client search match every row.
     *
     * The PHP-rendered data-client-final-search attribute is the authoritative
     * per-row search index.
     */
    var parts = [
      row.getAttribute("data-client-final-search") || ""
    ];

    Array.prototype.slice.call(row.querySelectorAll("input[type='hidden']")).forEach(function (el) {
      parts.push(el.value || "");
    });

    Array.prototype.slice.call(row.querySelectorAll("select")).forEach(function (el) {
      parts.push(el.getAttribute("data-current-label") || "");
      if (el.selectedOptions && el.selectedOptions.length) {
        Array.prototype.slice.call(el.selectedOptions).forEach(function (opt) {
          if (opt.selected) {
            parts.push(opt.textContent || "");
            parts.push(opt.value || "");
          }
        });
      }
    });

    return norm(parts.join(" "));
  }

  function setVisible(row, visible) {
    if (!row) return;

    row.classList.remove("rmm-filter-hidden");
    row.classList.toggle("rmm-client-final-search-hidden", !visible);

    if (visible) {
      row.style.removeProperty("display");
      row.style.removeProperty("visibility");
    } else {
      row.style.setProperty("display", "none", "important");
      row.style.setProperty("visibility", "collapse", "important");
    }
  }

  function applyClientSearch() {
    var input = getClientSearchInput();
    var table = document.getElementById("rmm-client-table");

    if (!input || !table) return false;

    var q = norm(input.value);
    var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr"));

    rows.forEach(function (row) {
      var haystack = getRowText(row);
      var visible = !q || haystack.indexOf(q) !== -1;
      setVisible(row, visible);
    });

    return true;
  }

  function bindClientSearch() {
    var input = getClientSearchInput();
    if (!input) return;

    input.classList.add("rmm-client-final-filter");

    if (input.dataset.rmmClientFinalSearchBound !== "1") {
      input.dataset.rmmClientFinalSearchBound = "1";

      ["input", "keyup", "change", "search", "paste", "cut"].forEach(function (eventName) {
        input.addEventListener(eventName, function () {
          applyClientSearch();
          window.setTimeout(applyClientSearch, 0);
          window.setTimeout(applyClientSearch, 25);
          window.setTimeout(applyClientSearch, 100);
        }, true);
      });
    }

    applyClientSearch();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindClientSearch);
  } else {
    bindClientSearch();
  }

  // Keep this available from console and from inline input attributes.
  window.rmmFinalClientSearch = applyClientSearch;

  // Last-word reapply: if old Client sort/search JS touches rows after us,
  // this will put the filter state back.
  window.setTimeout(applyClientSearch, 250);
  window.setTimeout(applyClientSearch, 750);

  var table = document.getElementById("rmm-client-table");
  if (table && window.MutationObserver) {
    var busy = false;
    var observer = new MutationObserver(function () {
      if (busy) return;
      busy = true;
      window.setTimeout(function () {
        applyClientSearch();
        busy = false;
      }, 0);
    });
    observer.observe(table, { childList: true, subtree: true, attributes: true, attributeFilter: ["style", "class"] });
  }
})();
</script>

<?php require_once "includes/footer.php"; ?>
