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

try {
    $integration = rmm_query("SELECT * FROM itflow_rmm_integrations WHERE provider='tacticalrmm' LIMIT 1")->fetch_assoc();

    $client_maps = rmm_query("SELECT COUNT(*) c FROM itflow_trmm_client_map WHERE enabled=1")->fetch_assoc()['c'] ?? 0;
    $asset_maps = rmm_query("SELECT COUNT(*) c FROM itflow_trmm_asset_map WHERE sync_enabled=1")->fetch_assoc()['c'] ?? 0;
    $active_assets = rmm_query("SELECT COUNT(*) c FROM assets WHERE asset_archived_at IS NULL")->fetch_assoc()['c'] ?? 0;

    $duplicate_agents = rmm_query("
        SELECT COUNT(*) c
        FROM (
            SELECT trmm_agent_id
            FROM itflow_trmm_asset_map
            GROUP BY trmm_agent_id
            HAVING COUNT(*) > 1
        ) x
    ")->fetch_assoc()['c'] ?? 0;

    $integration_error = '';
} catch (Throwable $e) {
    $integration_error = $e->getMessage();
    $integration = null;
    $client_maps = 0;
    $asset_maps = 0;
    $active_assets = 0;
    $duplicate_agents = 0;
}
?>

<div class="content-header">
  <div class="container-fluid">
    <div class="row mb-2">
      <div class="col-sm-6">
        <h1 class="m-0">3rd Party Integrations</h1>
      </div>
      <div class="col-sm-6">
        <ol class="breadcrumb float-sm-right">
          <li class="breadcrumb-item"><a href="settings_module.php">Settings</a></li>
          <li class="breadcrumb-item active">3rd Party Integrations</li>
        </ol>
      </div>
    </div>
  </div>
</div>

<section class="content">
  <div class="container-fluid">

    <?php if (!empty($integration_error)): ?>
      <div class="alert alert-danger"><?= rmm_h($integration_error) ?></div>
    <?php endif; ?>

    <div class="card card-dark">
      <div class="card-header">
        <h3 class="card-title"><i class="fas fa-plug mr-2"></i>Configured Integrations</h3>
      </div>

      <div class="card-body p-0">
        <table class="table table-striped mb-0">
          <thead>
            <tr>
              <th style="width: 120px;">Category</th>
              <th style="width: 180px;">Provider</th>
              <th style="width: 130px;">Status</th>
              <th>Summary</th>
              <th style="width: 140px;" class="text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>RMM</strong></td>
              <td>TacticalRMM</td>
              <td>
                <?php if (!empty($integration['enabled'])): ?>
                  <span class="badge badge-success">Configured</span>
                <?php else: ?>
                  <span class="badge badge-secondary">Disabled</span>
                <?php endif; ?>
              </td>
              <td>
                <div>Syncs TacticalRMM clients and agents/devices into ITFlow organizations and assets.</div>
                <small class="text-muted">
                  Client mappings: <?= rmm_h($client_maps) ?> |
                  Asset mappings: <?= rmm_h($asset_maps) ?> |
                  Active assets: <?= rmm_h($active_assets) ?> |
                  Duplicate RMM agent IDs: <?= rmm_h($duplicate_agents) ?>
                  <br>
                  Last connection:
                  <?= rmm_h(($integration['last_connection_status'] ?? 'never') . ' ' . ($integration['last_connection_at'] ?? '')) ?>
                  |
                  Last sync:
                  <?= rmm_h(($integration['last_sync_status'] ?? 'never') . ' ' . ($integration['last_sync_at'] ?? '')) ?>
                </small>
              </td>
              <td class="text-right">
                <a class="btn btn-primary btn-sm" href="settings_rmm.php">
                  <i class="fas fa-cog mr-1"></i>Configure
                </a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card-footer text-muted">
        Future integration categories/providers can be added here later.
      </div>
    </div>

  </div>
</section>

<?php require_once "includes/footer.php"; ?>
