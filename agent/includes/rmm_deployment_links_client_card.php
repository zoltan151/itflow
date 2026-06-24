<?php
/*
 * TacticalRMM deployment links card for client pages.
 * Expects the normal ITFlow client context, especially $client_id and $mysqli.
 */

if (!isset($client_id)) {
    $client_id = (int)($_GET['client_id'] ?? 0);
}

if (!function_exists('rmm_deploy_h')) {
    function rmm_deploy_h($value): string {
        return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

$rmm_deployment_table_exists = false;
$rmm_deployment_table_sql = mysqli_query($mysqli, "SHOW TABLES LIKE 'itflow_trmm_deployment_links'");
if ($rmm_deployment_table_sql && mysqli_num_rows($rmm_deployment_table_sql) > 0) {
    $rmm_deployment_table_exists = true;
}

$rmm_deploy_total = 0;
$rmm_deploy_expired = 0;
$rmm_deploy_missing_location = 0;
$rmm_deploy_rows = [];

if ($rmm_deployment_table_exists && $client_id > 0) {
    $count_sql = mysqli_query(
        $mysqli,
        "SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN expired = 1 THEN 1 ELSE 0 END) AS expired_count,
            SUM(CASE WHEN itflow_location_id = 0 THEN 1 ELSE 0 END) AS missing_location_count
         FROM itflow_trmm_deployment_links
         WHERE active = 1 AND itflow_client_id = $client_id"
    );
    if ($count_sql) {
        $count_row = mysqli_fetch_assoc($count_sql);
        $rmm_deploy_total = (int)($count_row['total'] ?? 0);
        $rmm_deploy_expired = (int)($count_row['expired_count'] ?? 0);
        $rmm_deploy_missing_location = (int)($count_row['missing_location_count'] ?? 0);
    }

    $links_sql = mysqli_query(
        $mysqli,
        "SELECT d.*,
                l.location_name
         FROM itflow_trmm_deployment_links d
         LEFT JOIN locations l ON l.location_id = d.itflow_location_id
         WHERE d.active = 1 AND d.itflow_client_id = $client_id
         ORDER BY d.expired ASC,
                  d.expires_at IS NULL ASC,
                  d.expires_at ASC,
                  l.location_name ASC,
                  d.trmm_site_name ASC
         LIMIT 12"
    );
    if ($links_sql) {
        while ($row = mysqli_fetch_assoc($links_sql)) {
            $rmm_deploy_rows[] = $row;
        }
    }
}
?>

<div class="card mb-3" id="rmm-client-deployment-links-card">
  <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
    <h5 class="mb-0"><i class="fas fa-rocket mr-2"></i>TacticalRMM Deployment Links</h5>
    <div>
      <span class="badge badge-light"><?= (int)$rmm_deploy_total ?> active</span>
      <?php if ($rmm_deploy_expired > 0): ?>
        <span class="badge badge-danger"><?= (int)$rmm_deploy_expired ?> expired</span>
      <?php endif; ?>
      <?php if ($rmm_deploy_missing_location > 0): ?>
        <span class="badge badge-warning"><?= (int)$rmm_deploy_missing_location ?> unmapped</span>
      <?php endif; ?>
    </div>
  </div>

  <div class="card-body p-0">
    <?php if (!$rmm_deployment_table_exists): ?>
      <div class="p-3 text-muted">
        TacticalRMM deployment-link sync has not created its table yet.
      </div>
    <?php elseif ($rmm_deploy_total === 0): ?>
      <div class="p-3 text-muted">
        No active TacticalRMM deployment links are synced for this client.
      </div>
    <?php else: ?>
      <div class="table-responsive">
        <table class="table table-sm table-striped mb-0">
          <thead>
            <tr>
              <th>Status</th>
              <th>Location</th>
              <th>TRMM Site</th>
              <th>Type / Arch</th>
              <th>Expires</th>
              <th>Deployment</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($rmm_deploy_rows as $dl): ?>
              <?php
              $expired = (int)($dl['expired'] ?? 0) === 1;
              $missing_location = (int)($dl['itflow_location_id'] ?? 0) <= 0;
              ?>
              <tr>
                <td>
                  <?php if ($expired): ?>
                    <span class="badge badge-danger">Expired</span>
                  <?php else: ?>
                    <span class="badge badge-success">Active</span>
                  <?php endif; ?>
                  <?php if ($missing_location): ?>
                    <span class="badge badge-warning">Location Unmapped</span>
                  <?php endif; ?>
                </td>
                <td><?= rmm_deploy_h($dl['location_name'] ?: ('ITFlow Location #' . (int)$dl['itflow_location_id'])) ?></td>
                <td><?= rmm_deploy_h(($dl['trmm_site_name'] ?? '') . ' #' . (int)$dl['trmm_site_id']) ?></td>
                <td><?= rmm_deploy_h(trim(($dl['mon_type'] ?? '') . ' / ' . ($dl['goarch'] ?? ''), ' /')) ?></td>
                <td><?= rmm_deploy_h($dl['expires_at'] ?: 'No expiry') ?></td>
                <td>
                  <?php if (!empty($dl['deployment_url'])): ?>
                    <a href="<?= rmm_deploy_h($dl['deployment_url']) ?>" target="_blank" rel="noopener">Open Link</a>
                  <?php else: ?>
                    <code><?= rmm_deploy_h($dl['deployment_uid'] ?? '') ?></code>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <?php if ($rmm_deploy_total > count($rmm_deploy_rows)): ?>
        <div class="p-2 border-top">
          <a href="rmm_deployments.php?client_id=<?= (int)$client_id ?>">View all <?= (int)$rmm_deploy_total ?> deployment links</a>
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>
</div>
