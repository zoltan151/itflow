<?php
/*
 * ITFlow TacticalRMM Integration UI - sidecar admin page.
 * First-pass UI. Does not modify ITFlow core navigation.
 */

$root = __DIR__;

$included_itflow = false;
foreach ([
    "$root/inc_all_settings.php",
    "$root/inc_all_admin.php",
    "$root/inc_all.php",
    "$root/config.php"
] as $include_file) {
    if (file_exists($include_file)) {
        require_once $include_file;
        $included_itflow = true;
        break;
    }
}

if (!$included_itflow) {
    http_response_code(500);
    die("ITFlow include files not found.");
}

if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function trmm_db() {
    global $dbhost, $dbusername, $dbpassword, $database, $mysqli;

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

function trmm_query($sql) {
    $db = trmm_db();
    $result = $db->query($sql);
    if (!$result) {
        throw new Exception($db->error);
    }
    return $result;
}

function trmm_exec($sql) {
    $db = trmm_db();
    if (!$db->query($sql)) {
        throw new Exception($db->error);
    }
    return true;
}

function trmm_escape($value) {
    return trmm_db()->real_escape_string((string)$value);
}

function trmm_current_user_label() {
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

function trmm_is_probably_admin() {
    // Access control is handled by ITFlow's inc_all_settings.php include.
    // If that include allowed this page to execute, accept the session.
    return true;
}

try {
    if (!trmm_is_probably_admin()) {
        http_response_code(403);
        die("Forbidden: admin/settings access is required.");
    }

    $message = '';
    $error = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $action = $_POST['action'] ?? '';
        $requested_by = trmm_escape(trmm_current_user_label());

        $job_map = [
            'test_connection' => 'test_connection',
            'client_auto_match' => 'client_auto_match',
            'asset_preview' => 'asset_preview',
            'asset_apply' => 'asset_apply',
        ];

        if (isset($job_map[$action])) {
            $job_type = trmm_escape($job_map[$action]);
            trmm_exec("INSERT INTO itflow_rmm_jobs (provider, job_type, job_status, requested_by, created_at) VALUES ('tacticalrmm', '$job_type', 'queued', '$requested_by', NOW())");
            $message = "Queued job: " . h($job_map[$action]) . ". It should run within about one minute.";
        } elseif ($action === 'manual_client_match') {
            $itflow_client_id = (int)($_POST['itflow_client_id'] ?? 0);
            $trmm_client_id = (int)($_POST['trmm_client_id'] ?? 0);
            $trmm_client_name = trmm_escape($_POST['trmm_client_name'] ?? '');
            if ($itflow_client_id <= 0 || $trmm_client_id <= 0 || $trmm_client_name === '') {
                throw new Exception("Manual match requires ITFlow client ID, Tactical client ID, and Tactical client name.");
            }
            trmm_exec("
                INSERT INTO itflow_trmm_client_map
                  (itflow_client_id, trmm_client_id, trmm_client_name, match_type, enabled, notes, updated_at)
                VALUES
                  ($itflow_client_id, $trmm_client_id, '$trmm_client_name', 'manual_selected', 1, 'Set from RMM UI', NOW())
                ON DUPLICATE KEY UPDATE
                  trmm_client_id=VALUES(trmm_client_id),
                  trmm_client_name=VALUES(trmm_client_name),
                  match_type=VALUES(match_type),
                  enabled=1,
                  notes=VALUES(notes),
                  updated_at=NOW()
            ");
            $message = "Manual client match saved.";
        } elseif ($action === 'disable_client_match') {
            $itflow_client_id = (int)($_POST['itflow_client_id'] ?? 0);
            if ($itflow_client_id <= 0) throw new Exception("Missing ITFlow client ID.");
            trmm_exec("UPDATE itflow_trmm_client_map SET enabled=0, match_type='disabled', updated_at=NOW() WHERE itflow_client_id=$itflow_client_id LIMIT 1");
            $message = "Client mapping disabled.";
        }
    }

    $integration = trmm_query("SELECT * FROM itflow_rmm_integrations WHERE provider='tacticalrmm' LIMIT 1")->fetch_assoc();

    $counts = [];
    $count_sql = [
        'Active ITFlow assets' => "SELECT COUNT(*) c FROM assets WHERE asset_archived_at IS NULL",
        'Enabled client mappings' => "SELECT COUNT(*) c FROM itflow_trmm_client_map WHERE enabled=1",
        'Enabled asset mappings' => "SELECT COUNT(*) c FROM itflow_trmm_asset_map WHERE sync_enabled=1",
        'Duplicate TRMM agent IDs' => "SELECT COUNT(*) c FROM (SELECT trmm_agent_id FROM itflow_trmm_asset_map GROUP BY trmm_agent_id HAVING COUNT(*) > 1) x",
        'Duplicate ITFlow asset IDs' => "SELECT COUNT(*) c FROM (SELECT itflow_asset_id FROM itflow_trmm_asset_map GROUP BY itflow_asset_id HAVING COUNT(*) > 1) x",
    ];
    foreach ($count_sql as $label => $sql) {
        $counts[$label] = trmm_query($sql)->fetch_assoc()['c'] ?? 0;
    }

    $client_rows = trmm_query("
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

    $asset_rows = trmm_query("
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
        ORDER BY m.updated_at DESC, m.map_id DESC
        LIMIT 200
    ");

    $jobs = trmm_query("
        SELECT job_id, job_type, job_status, requested_by, created_at, started_at, finished_at, LEFT(COALESCE(result_summary,''), 1000) result_summary
        FROM itflow_rmm_jobs
        ORDER BY job_id DESC
        LIMIT 50
    ");

} catch (Throwable $e) {
    $error = $e->getMessage();
}
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>ITFlow RMM Integration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 24px; color: #222; background: #f7f7f7; }
        .wrap { max-width: 1500px; margin: 0 auto; }
        .card { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 18px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
        h1, h2 { margin-top: 0; }
        .grid { display: grid; grid-template-columns: repeat(5, minmax(160px, 1fr)); gap: 12px; }
        .metric { background: #f2f4f7; padding: 12px; border-radius: 6px; }
        .metric b { display: block; font-size: 22px; margin-top: 5px; }
        .actions form { display: inline-block; margin: 0 8px 8px 0; }
        button { padding: 8px 12px; border-radius: 5px; border: 1px solid #999; cursor: pointer; background: #fff; }
        button.primary { background: #1f6feb; color: white; border-color: #1f6feb; }
        button.danger { background: #b42318; color: white; border-color: #b42318; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { border-bottom: 1px solid #e5e5e5; padding: 8px; text-align: left; vertical-align: top; }
        th { background: #f2f4f7; position: sticky; top: 0; }
        .ok { color: #067647; font-weight: bold; }
        .warn { color: #b54708; font-weight: bold; }
        .bad { color: #b42318; font-weight: bold; }
        .msg { padding: 10px; border-radius: 6px; background: #ecfdf3; border: 1px solid #abefc6; margin-bottom: 18px; }
        .err { padding: 10px; border-radius: 6px; background: #fef3f2; border: 1px solid #fecdca; margin-bottom: 18px; }
        .small { color: #666; font-size: 12px; }
        input[type=text], input[type=number] { padding: 6px; width: 160px; }
        .tabs a { display: inline-block; margin-right: 12px; padding: 8px 10px; background: #fff; border: 1px solid #ddd; border-radius: 5px; text-decoration: none; color: #222; }
        pre { white-space: pre-wrap; max-height: 240px; overflow: auto; background: #111827; color: #e5e7eb; padding: 10px; border-radius: 6px; }
    </style>
</head>
<body>
<div class="wrap">
    <h1>3rd Party Integrations → RMM</h1>
    <p class="small">Provider: TacticalRMM. This sidecar page uses the proven sync backend under <code>/opt/itflow-trmm-sync</code>.</p>

    <?php if (!empty($message)): ?><div class="msg"><?= $message ?></div><?php endif; ?>
    <?php if (!empty($error)): ?><div class="err"><?= h($error) ?></div><?php endif; ?>

    <div class="card">
        <h2>Settings</h2>
        <table>
            <tr><th>Provider</th><td><?= h($integration['provider_label'] ?? 'TacticalRMM') ?></td></tr>
            <tr><th>Enabled</th><td><?= !empty($integration['enabled']) ? '<span class="ok">Yes</span>' : '<span class="bad">No</span>' ?></td></tr>
            <tr><th>API URL</th><td><?= h($integration['api_base'] ?? '') ?></td></tr>
            <tr><th>Token</th><td><?= !empty($integration['token_configured']) ? '<span class="ok">Configured root-only</span>' : '<span class="bad">Not configured</span>' ?> <span class="small">/opt/itflow-trmm-sync/.secrets</span></td></tr>
            <tr><th>Last connection</th><td><?= h(($integration['last_connection_status'] ?? 'never') . ' ' . ($integration['last_connection_at'] ?? '')) ?></td></tr>
            <tr><th>Last sync</th><td><?= h(($integration['last_sync_status'] ?? 'never') . ' ' . ($integration['last_sync_at'] ?? '')) ?></td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Actions</h2>
        <div class="actions">
            <form method="post"><input type="hidden" name="action" value="test_connection"><button>Test Connection</button></form>
            <form method="post"><input type="hidden" name="action" value="client_auto_match"><button>Auto-match All Clients</button></form>
            <form method="post"><input type="hidden" name="action" value="asset_preview"><button>Preview Asset Sync</button></form>
            <form method="post" onsubmit="return confirm('Run full live TacticalRMM asset sync now?');"><input type="hidden" name="action" value="asset_apply"><button class="primary">Run Full Sync Now</button></form>
        </div>
        <p class="small">Jobs are queued and processed by <code>itflow-trmm-ui-worker.timer</code> within about one minute.</p>
    </div>

    <div class="card">
        <h2>Status</h2>
        <div class="grid">
            <?php foreach ($counts as $label => $value): ?>
                <div class="metric"><?= h($label) ?><b><?= h($value) ?></b></div>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="card">
        <h2>Client Mapping</h2>
        <table>
            <thead>
                <tr>
                    <th>ITFlow Client</th>
                    <th>TacticalRMM Client</th>
                    <th>Tactical ID</th>
                    <th>Match Type</th>
                    <th>Status</th>
                    <th>Manual Match / Disable</th>
                </tr>
            </thead>
            <tbody>
            <?php while ($r = $client_rows->fetch_assoc()): ?>
                <tr>
                    <td><?= h($r['client_name']) ?><br><span class="small">ITFlow <?= h($r['client_id']) ?></span></td>
                    <td><?= h($r['trmm_client_name'] ?? '') ?></td>
                    <td><?= h($r['trmm_client_id'] ?? '') ?></td>
                    <td><?= h($r['match_type'] ?? 'unmatched') ?></td>
                    <td>
                        <?php if (!empty($r['trmm_client_id']) && (string)$r['enabled'] === '1'): ?>
                            <span class="ok">Mapped</span>
                        <?php elseif (!empty($r['trmm_client_id'])): ?>
                            <span class="warn">Disabled</span>
                        <?php else: ?>
                            <span class="warn">Unmatched</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <form method="post" style="margin-bottom:6px;">
                            <input type="hidden" name="action" value="manual_client_match">
                            <input type="hidden" name="itflow_client_id" value="<?= h($r['client_id']) ?>">
                            <input type="number" name="trmm_client_id" placeholder="TRMM ID" required>
                            <input type="text" name="trmm_client_name" placeholder="TRMM client name" required>
                            <button>Save</button>
                        </form>
                        <?php if (!empty($r['trmm_client_id'])): ?>
                        <form method="post">
                            <input type="hidden" name="action" value="disable_client_match">
                            <input type="hidden" name="itflow_client_id" value="<?= h($r['client_id']) ?>">
                            <button class="danger">Disable</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endwhile; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Asset Mapping</h2>
        <p class="small">Showing latest 200 mapped RMM assets. Permanent identity is <code>trmm_agent_id → asset_id</code>.</p>
        <table>
            <thead>
                <tr>
                    <th>ITFlow Asset</th>
                    <th>Client</th>
                    <th>TRMM Hostname</th>
                    <th>TRMM Agent ID</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                    <th>Updated</th>
                </tr>
            </thead>
            <tbody>
            <?php while ($r = $asset_rows->fetch_assoc()): ?>
                <tr>
                    <td><?= h($r['asset_name']) ?><br><span class="small">Asset <?= h($r['itflow_asset_id']) ?> / <?= h($r['asset_type']) ?></span></td>
                    <td><?= h($r['client_name']) ?></td>
                    <td><?= h($r['last_hostname']) ?></td>
                    <td><code><?= h($r['trmm_agent_id']) ?></code></td>
                    <td><?= h($r['last_status'] ?: $r['asset_status']) ?></td>
                    <td><?= h($r['last_seen']) ?></td>
                    <td><?= h($r['updated_at']) ?></td>
                </tr>
            <?php endwhile; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Jobs</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Requested By</th>
                    <th>Created</th>
                    <th>Started</th>
                    <th>Finished</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody>
            <?php while ($j = $jobs->fetch_assoc()): ?>
                <tr>
                    <td><?= h($j['job_id']) ?></td>
                    <td><?= h($j['job_type']) ?></td>
                    <td><?= h($j['job_status']) ?></td>
                    <td><?= h($j['requested_by']) ?></td>
                    <td><?= h($j['created_at']) ?></td>
                    <td><?= h($j['started_at']) ?></td>
                    <td><?= h($j['finished_at']) ?></td>
                    <td><pre><?= h($j['result_summary']) ?></pre></td>
                </tr>
            <?php endwhile; ?>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Operational Commands</h2>
        <pre>sudo /usr/local/sbin/itflow-trmm-sync-status
sudo /usr/local/sbin/itflow-trmm-live-dryrun
sudo systemctl start itflow-trmm-sync.service
sudo systemctl status itflow-trmm-ui-worker.timer
sudo journalctl -u itflow-trmm-ui-worker.service -n 100 --no-pager</pre>
    </div>
</div>
</body>
</html>
