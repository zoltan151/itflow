<?php

require_once "includes/inc_all_client.php";

if (!isset($client_id)) {
    $client_id = (int)($_GET['client_id'] ?? 0);
}

if (!function_exists('rmm_deploy_page_h')) {
    function rmm_deploy_page_h($value): string {
        return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

if (!function_exists('rmm_deploy_format_date')) {
    function rmm_deploy_format_date($value, bool $include_time = false): string {
        $value = trim((string)$value);
        if ($value === '' || $value === '0000-00-00 00:00:00' || $value === '0000-00-00') {
            return 'No expiry';
        }

        try {
            $dt = new DateTime($value);
            return $dt->format($include_time ? 'F d, Y h:i A' : 'F d, Y');
        } catch (Throwable $e) {
            return $value;
        }
    }
}

$table_exists = false;
$table_sql = mysqli_query($mysqli, "SHOW TABLES LIKE 'itflow_trmm_deployment_links'");
if ($table_sql && mysqli_num_rows($table_sql) > 0) {
    $table_exists = true;
}

$status = $_GET['status'] ?? 'active';
$search = trim((string)($_GET['q'] ?? ''));

$where = "d.itflow_client_id = $client_id";
if ($status === 'expired') {
    $where .= " AND d.active = 1 AND d.expired = 1";
} elseif ($status === 'inactive') {
    $where .= " AND d.active = 0";
} elseif ($status === 'all') {
    $where .= "";
} else {
    $status = 'active';
    $where .= " AND d.active = 1";
}

if ($search !== '') {
    $search_sql = mysqli_real_escape_string($mysqli, $search);
    $where .= " AND (
        d.trmm_client_name LIKE '%$search_sql%' OR
        d.trmm_site_name LIKE '%$search_sql%' OR
        d.deployment_uid LIKE '%$search_sql%' OR
        d.deployment_url LIKE '%$search_sql%' OR
        d.mon_type LIKE '%$search_sql%' OR
        d.goarch LIKE '%$search_sql%' OR
        l.location_name LIKE '%$search_sql%'
    )";
}

$counts = [
    'active' => 0,
    'expired' => 0,
    'inactive' => 0,
    'all' => 0,
    'missing_location' => 0,
];

$rows = [];

if ($table_exists) {
    $count_sql = mysqli_query(
        $mysqli,
        "SELECT
            SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) AS active_count,
            SUM(CASE WHEN active = 1 AND expired = 1 THEN 1 ELSE 0 END) AS expired_count,
            SUM(CASE WHEN active = 0 THEN 1 ELSE 0 END) AS inactive_count,
            COUNT(*) AS all_count,
            SUM(CASE WHEN active = 1 AND itflow_location_id = 0 THEN 1 ELSE 0 END) AS missing_location_count
         FROM itflow_trmm_deployment_links
         WHERE itflow_client_id = $client_id"
    );
    if ($count_sql) {
        $cr = mysqli_fetch_assoc($count_sql);
        $counts['active'] = (int)($cr['active_count'] ?? 0);
        $counts['expired'] = (int)($cr['expired_count'] ?? 0);
        $counts['inactive'] = (int)($cr['inactive_count'] ?? 0);
        $counts['all'] = (int)($cr['all_count'] ?? 0);
        $counts['missing_location'] = (int)($cr['missing_location_count'] ?? 0);
    }

    $sql = mysqli_query(
        $mysqli,
        "SELECT d.*,
                c.client_name,
                l.location_name
         FROM itflow_trmm_deployment_links d
         LEFT JOIN clients c ON c.client_id = d.itflow_client_id
         LEFT JOIN locations l ON l.location_id = d.itflow_location_id
         WHERE $where
         ORDER BY d.active DESC,
                  d.expired ASC,
                  l.location_name ASC,
                  d.trmm_site_name ASC,
                  d.expires_at IS NULL ASC,
                  d.expires_at ASC
         LIMIT 500"
    );

    if ($sql) {
        while ($row = mysqli_fetch_assoc($sql)) {
            $rows[] = $row;
        }
    }
}

?>

<style>
.rmm-deploy-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(430px, 1fr));
  gap: 1rem;
}
.rmm-deploy-card {
  border: 1px solid #dee2e6;
  border-radius: .35rem;
  background: #fff;
  box-shadow: 0 1px 2px rgba(0,0,0,.04);
}
.rmm-deploy-card-header {
  padding: .75rem .85rem;
  border-bottom: 1px solid #e9ecef;
  background: #f8f9fa;
}
.rmm-deploy-card-body {
  padding: .85rem;
}
.rmm-deploy-title {
  font-weight: 700;
  font-size: 1rem;
  margin-bottom: .15rem;
}
.rmm-deploy-subtitle {
  color: #6c757d;
  font-size: .85rem;
}
.rmm-deploy-meta {
  display: flex;
  flex-wrap: wrap;
  gap: .35rem;
  margin-top: .5rem;
}
.rmm-deploy-link-row {
  display: flex;
  gap: .4rem;
}
.rmm-deploy-copy-input {
  font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  font-size: .82rem;
  cursor: pointer;
}
.rmm-copy-toast {
  display: none;
  position: fixed;
  right: 1rem;
  bottom: 1rem;
  z-index: 99999;
  background: #212529;
  color: #fff;
  padding: .65rem .9rem;
  border-radius: .35rem;
  box-shadow: 0 4px 14px rgba(0,0,0,.25);
}
@media (max-width: 650px) {
  .rmm-deploy-grid {
    grid-template-columns: 1fr;
  }
  .rmm-deploy-link-row {
    flex-direction: column;
  }
}
</style>

<div class="card mb-3">
  <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
    <h3 class="card-title mb-0"><i class="fas fa-rocket mr-2"></i>TacticalRMM Deployment Links</h3>
    <div>
      <span class="badge badge-light">Active <?= (int)$counts['active'] ?></span>
      <span class="badge badge-danger">Expired <?= (int)$counts['expired'] ?></span>
      <span class="badge badge-secondary">Inactive <?= (int)$counts['inactive'] ?></span>
      <?php if ($counts['missing_location'] > 0): ?>
        <span class="badge badge-warning">Location Unmapped <?= (int)$counts['missing_location'] ?></span>
      <?php endif; ?>
    </div>
  </div>

  <div class="card-body">
    <p class="text-muted mb-3">
      Deployment links are synced from TacticalRMM and mapped through ITFlow Client/Site mappings. Click a link field or Copy to place the deployment URL on your clipboard.
    </p>

    <form class="form-inline mb-0" method="get">
      <input type="hidden" name="client_id" value="<?= (int)$client_id ?>">
      <input class="form-control form-control-sm mr-2 mb-2" style="min-width: 280px;" type="text" name="q" value="<?= rmm_deploy_page_h($search) ?>" placeholder="Search site, location, UID, link, type...">

      <select class="form-control form-control-sm mr-2 mb-2" name="status">
        <option value="active" <?= $status === 'active' ? 'selected' : '' ?>>Active</option>
        <option value="expired" <?= $status === 'expired' ? 'selected' : '' ?>>Expired</option>
        <option value="inactive" <?= $status === 'inactive' ? 'selected' : '' ?>>Inactive</option>
        <option value="all" <?= $status === 'all' ? 'selected' : '' ?>>All</option>
      </select>

      <button class="btn btn-sm btn-primary mb-2">Filter</button>
      <a class="btn btn-sm btn-secondary ml-2 mb-2" href="rmm_deployments.php?client_id=<?= (int)$client_id ?>">Reset</a>
    </form>
  </div>
</div>

<?php if (!$table_exists): ?>
  <div class="alert alert-warning">Deployment-link table has not been created yet. Run the TacticalRMM sync once.</div>
<?php elseif (empty($rows)): ?>
  <div class="alert alert-info">No deployment links matched this view.</div>
<?php else: ?>
  <div class="rmm-deploy-grid">
    <?php foreach ($rows as $dl): ?>
      <?php
      $is_expired = (int)($dl['expired'] ?? 0) === 1;
      $is_active = (int)($dl['active'] ?? 0) === 1;
      $missing_location = (int)($dl['itflow_location_id'] ?? 0) <= 0;
      $location_label = $dl['location_name'] ?: ('ITFlow Location #' . (int)$dl['itflow_location_id']);
      $trmm_site_label = trim(($dl['trmm_site_name'] ?? '') . ' #' . (int)$dl['trmm_site_id']);
      $deployment_link = trim((string)($dl['deployment_url'] ?? ''));
      if ($deployment_link === '') {
          $deployment_link = trim((string)($dl['deployment_uid'] ?? ''));
      }
      ?>
      <div class="rmm-deploy-card">
        <div class="rmm-deploy-card-header">
          <div class="d-flex justify-content-between align-items-start">
            <div>
              <div class="rmm-deploy-title"><?= rmm_deploy_page_h($location_label) ?></div>
              <div class="rmm-deploy-subtitle"><?= rmm_deploy_page_h($trmm_site_label) ?></div>
            </div>
            <div class="text-right">
              <?php if (!$is_active): ?>
                <span class="badge badge-secondary">Inactive</span>
              <?php elseif ($is_expired): ?>
                <span class="badge badge-danger">Expired</span>
              <?php else: ?>
                <span class="badge badge-success">Active</span>
              <?php endif; ?>
              <?php if ($missing_location): ?>
                <span class="badge badge-warning">Unmapped</span>
              <?php endif; ?>
            </div>
          </div>
        </div>

        <div class="rmm-deploy-card-body">
          <div class="rmm-deploy-meta">
            <span class="badge badge-light border">Type: <?= rmm_deploy_page_h($dl['mon_type'] ?? '') ?></span>
            <span class="badge badge-light border">Arch: <?= rmm_deploy_page_h($dl['goarch'] ?? '') ?></span>
            <span class="badge badge-light border">Created: <?= rmm_deploy_page_h(!empty($dl['created_at_trmm']) ? rmm_deploy_format_date($dl['created_at_trmm'], true) : 'Unknown') ?></span>
            <span class="badge badge-light border">Expires: <?= rmm_deploy_page_h(!empty($dl['expires_at']) ? rmm_deploy_format_date($dl['expires_at']) : 'No expiry') ?></span>
          </div>

          <label class="small text-muted mt-3 mb-1">Deployment link</label>
          <div class="rmm-deploy-link-row">
            <input
              class="form-control form-control-sm rmm-deploy-copy-input"
              type="text"
              readonly
              value="<?= rmm_deploy_page_h($deployment_link) ?>"
              title="Click to copy"
              onclick="rmmCopyDeploymentLink(this.value)"
            >
            <button
              class="btn btn-sm btn-outline-primary"
              type="button"
              onclick="rmmCopyDeploymentLink(this.previousElementSibling.value)"
            >Copy</button>
          </div>

          <div class="small text-muted mt-2">
            UID: <code><?= rmm_deploy_page_h($dl['deployment_uid'] ?? '') ?></code>
            <br>
            Last synced: <?= rmm_deploy_page_h(!empty($dl['last_synced_at']) ? rmm_deploy_format_date($dl['last_synced_at'], true) : '') ?>
          </div>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
<?php endif; ?>

<div id="rmm-copy-toast" class="rmm-copy-toast">Copied deployment link</div>

<script>
function rmmShowCopyToast(message) {
  var toast = document.getElementById('rmm-copy-toast');
  if (!toast) return;
  toast.textContent = message || 'Copied deployment link';
  toast.style.display = 'block';
  clearTimeout(window.rmmCopyToastTimer);
  window.rmmCopyToastTimer = setTimeout(function () {
    toast.style.display = 'none';
  }, 1600);
}

function rmmCopyDeploymentLink(text) {
  text = String(text || '').trim();
  if (!text) {
    rmmShowCopyToast('Nothing to copy');
    return;
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(function () {
      rmmShowCopyToast('Copied deployment link');
    }).catch(function () {
      rmmFallbackCopyDeploymentLink(text);
    });
  } else {
    rmmFallbackCopyDeploymentLink(text);
  }
}

function rmmFallbackCopyDeploymentLink(text) {
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();

  try {
    document.execCommand('copy');
    rmmShowCopyToast('Copied deployment link');
  } catch (e) {
    rmmShowCopyToast('Copy failed; select the field manually');
  }

  document.body.removeChild(ta);
}
</script>

<?php require_once "includes/footer.php"; ?>
