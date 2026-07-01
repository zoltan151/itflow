
<?php
require_once "includes/inc_all.php";

function itflow_vops_e($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function itflow_vops_table_exists($table)
{
    global $mysqli;
    $table = mysqli_real_escape_string($mysqli, $table);
    $sql = mysqli_query($mysqli, "SHOW TABLES LIKE '$table'");
    return $sql && mysqli_num_rows($sql) > 0;
}

function itflow_vops_column_exists($table, $column)
{
    global $mysqli;
    $table = mysqli_real_escape_string($mysqli, $table);
    $column = mysqli_real_escape_string($mysqli, $column);
    $sql = mysqli_query($mysqli, "SHOW COLUMNS FROM `$table` LIKE '$column'");
    return $sql && mysqli_num_rows($sql) > 0;
}

function itflow_vops_contains($haystack, $needle)
{
    return strpos(strtolower((string)$haystack), strtolower((string)$needle)) !== false;
}

function itflow_vops_status_class($status)
{
    if (itflow_vops_contains($status, 'development')) return 'warning';
    if (itflow_vops_contains($status, 'coming')) return 'success';
    if (itflow_vops_contains($status, 'ship') || itflow_vops_contains($status, 'complete')) return 'success';
    if (itflow_vops_contains($status, 'planned')) return 'primary';
    if (itflow_vops_contains($status, 'critical')) return 'danger';
    return 'secondary';
}

$has_roadmap = itflow_vops_table_exists('roadmap_items');
$has_visual = $has_roadmap && itflow_vops_column_exists('roadmap_items', 'roadmap_item_lane');

$lanes = ['Documentation', 'Onboarding', 'Integrations', 'Automation', 'AI / Tray Agent', 'Other'];
$items_by_lane = array_fill_keys($lanes, []);
$summary = ['active' => 0, 'dev' => 0, 'high' => 0, 'shipped' => 0];

if ($has_roadmap) {
    $visual_select = $has_visual ? "roadmap_item_lane, roadmap_item_progress, roadmap_item_start_date, roadmap_item_target_date" : "roadmap_item_category AS roadmap_item_lane, 0 AS roadmap_item_progress, NULL AS roadmap_item_start_date, NULL AS roadmap_item_target_date";
    $archived = itflow_vops_column_exists('roadmap_items', 'roadmap_item_archived_at') ? "WHERE roadmap_item_archived_at IS NULL" : "";
    $sql = mysqli_query($mysqli, "SELECT roadmap_item_title, roadmap_item_description, roadmap_item_category, roadmap_item_status, roadmap_item_priority, roadmap_item_pinned, roadmap_item_sort_order, $visual_select FROM roadmap_items $archived ORDER BY roadmap_item_pinned DESC, roadmap_item_sort_order ASC, roadmap_item_title ASC LIMIT 200");
    if ($sql) {
        while ($row = mysqli_fetch_assoc($sql)) {
            $lane = $row['roadmap_item_lane'] ?: $row['roadmap_item_category'] ?: 'Other';
            if (!isset($items_by_lane[$lane])) $lane = isset($items_by_lane[$row['roadmap_item_category'] ?? '']) ? $row['roadmap_item_category'] : 'Other';
            $items_by_lane[$lane][] = $row;

            $status = strtolower((string)$row['roadmap_item_status']);
            $priority = strtolower((string)$row['roadmap_item_priority']);
            if (!itflow_vops_contains($status, 'ship') && !itflow_vops_contains($status, 'complete')) $summary['active']++;
            if (itflow_vops_contains($status, 'development')) $summary['dev']++;
            if ($priority === 'critical' || $priority === 'high') $summary['high']++;
            if (itflow_vops_contains($status, 'ship') || itflow_vops_contains($status, 'complete')) $summary['shipped']++;
        }
    }
}
?>

<style>
.itflow-vops-card{background:#fff;border:1px solid #dee2e6;border-radius:.35rem;padding:1rem;margin-bottom:1rem}
.itflow-vops-lane{background:#f8f9fa;border:1px solid #dee2e6;border-radius:.35rem;padding:1rem;margin-bottom:1rem}
.itflow-vops-item{background:#fff;border:1px solid #dee2e6;border-left:4px solid #007bff;border-radius:.25rem;padding:.75rem;margin-bottom:.75rem}
.itflow-vops-board{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}
</style>

<div class="d-flex justify-content-between align-items-center mb-3">
    <div>
        <h3 class="mb-0">InfoTech Infrastructure Roadmap</h3>
        <div class="text-muted">Visual roadmap for ITFlow, RMM, backups, integrations, automation, and infrastructure improvements</div>
    </div>

<!-- ITFLOW_ROADMAP_ACTION_ROW -->
<div class="d-flex justify-content-between align-items-center mb-3">
    <div>
        <!-- ITFLOW_ROADMAP_VIEW_TOGGLE -->
        <div class="btn-group" role="group" aria-label="Roadmap view toggle">
            <a href="roadmap.php" class="btn btn-outline-primary">
                <i class="fas fa-th-large mr-1"></i> Card View
            </a>
            <a href="roadmap_visual.php" class="btn btn-primary active">
                <i class="fas fa-stream mr-1"></i> Timeline View
            </a>
        </div>
        <!-- /ITFLOW_ROADMAP_VIEW_TOGGLE -->
    </div>
    <div>
        <!-- ITFLOW_ROADMAP_ADD_ACTION -->
        <?php if (lookupUserPermission("module_config") >= 2) { ?>
            <button type="button" class="btn btn-primary ajax-modal" data-modal-url="modals/roadmap/roadmap_add.php" data-modal-size="lg">
                <i class="fas fa-fw fa-plus mr-1"></i> Add Roadmap Item
            </button>
        <?php } ?>
        <!-- /ITFLOW_ROADMAP_ADD_ACTION -->
    </div>
</div>
<!-- /ITFLOW_ROADMAP_ACTION_ROW -->
</div>

<?php if (!$has_roadmap) { ?>
    <div class="alert alert-warning">Roadmap table is not available yet.</div>
<?php } ?>

<div class="row">
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">Active Initiatives</div><h2><?= intval($summary['active']) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">In Development</div><h2><?= intval($summary['dev']) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">High Priority</div><h2><?= intval($summary['high']) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">Shipped / Complete</div><h2><?= intval($summary['shipped']) ?></h2></div></div>
</div>

<div class="itflow-vops-board">
    <?php foreach ($items_by_lane as $lane => $items) { ?>
        <div class="itflow-vops-lane">
            <h5><?= itflow_vops_e($lane) ?> <span class="badge badge-light"><?= count($items) ?></span></h5>
            <?php if (!$items) { ?><div class="text-muted small">No items in this lane.</div><?php } ?>
            <?php foreach ($items as $item) { ?>
                <div class="itflow-vops-item">
                    <strong><?= itflow_vops_e($item['roadmap_item_title'] ?? '') ?></strong><br>
                    <span class="badge badge-<?= itflow_vops_e(itflow_vops_status_class($item['roadmap_item_status'] ?? '')) ?>"><?= itflow_vops_e($item['roadmap_item_status'] ?? '') ?></span>
                    <span class="badge badge-light"><?= itflow_vops_e($item['roadmap_item_priority'] ?? '') ?></span>
                    <?php if (intval($item['roadmap_item_progress'] ?? 0) > 0) { ?>
                        <div class="progress mt-2" style="height:6px"><div class="progress-bar" style="width:<?= intval($item['roadmap_item_progress']) ?>%"></div></div>
                    <?php } ?>
                    <div class="small text-muted mt-2"><?= itflow_vops_e($item['roadmap_item_description'] ?? '') ?></div>
                </div>
            <?php } ?>
        </div>
    <?php } ?>
</div>

<?php require_once "includes/footer.php"; ?>
