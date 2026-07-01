
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

$has_table = itflow_vops_table_exists('employee_lifecycle_items');
$stages = ['Request Received','Access & Licensing','Hardware Prep','Security Setup','Training / SOP Assignment','First Day','30-Day Follow-up','Complete'];
$stage_counts = array_fill_keys($stages, 0);
$items = [];

if ($has_table) {
    $sql = mysqli_query($mysqli, "SELECT eli.*, c.client_name, u.user_name FROM employee_lifecycle_items eli LEFT JOIN clients c ON c.client_id = eli.employee_lifecycle_client_id LEFT JOIN users u ON u.user_id = eli.employee_assigned_user_id ORDER BY eli.employee_created_at DESC LIMIT 100");
    if ($sql) {
        while ($row = mysqli_fetch_assoc($sql)) {
            $items[] = $row;
            if (isset($stage_counts[$row['employee_stage']])) $stage_counts[$row['employee_stage']]++;
        }
    }
}

$new = 0; $off = 0; $waiting = 0; $sum = 0;
foreach ($items as $item) {
    if (strtolower((string)$item['employee_lifecycle_type']) === 'offboarding') $off++; else $new++;
    if (itflow_vops_contains($item['employee_status'] ?? '', 'waiting')) $waiting++;
    $sum += intval($item['employee_completion'] ?? 0);
}
$avg = count($items) ? round($sum / count($items)) : 0;
?>

<style>
.itflow-people-card{background:#fff;border:1px solid #dee2e6;border-radius:.35rem;padding:1rem;margin-bottom:1rem}
.itflow-people-stage{display:flex;gap:.5rem;overflow-x:auto;background:#fff;border:1px solid #dee2e6;border-radius:.35rem;padding:1rem;margin-bottom:1rem}
.itflow-people-step{min-width:140px;text-align:center}
</style>

<div class="d-flex justify-content-between align-items-center mb-3">
    <div>
        <h3 class="mb-0">Employee Onboarding & Offboarding</h3>
        <div class="text-muted">Manage new hire onboarding and employee offboarding across all clients</div>
    </div>
    <button class="btn btn-primary" disabled>Add Employee</button>
</div>

<?php if (!$has_table) { ?><div class="alert alert-warning">Employee lifecycle table is not available yet.</div><?php } ?>

<div class="row">
    <div class="col-md-3"><div class="itflow-people-card"><div class="text-muted">New Hires</div><h2><?= intval($new) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-people-card"><div class="text-muted">Offboardings</div><h2><?= intval($off) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-people-card"><div class="text-muted">Waiting on Client</div><h2><?= intval($waiting) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-people-card"><div class="text-muted">Completion Rate</div><h2><?= intval($avg) ?>%</h2></div></div>
</div>

<div class="itflow-people-stage">
    <?php $i=1; foreach ($stages as $stage) { ?>
        <div class="itflow-people-step"><span class="badge badge-primary"><?= $i++ ?></span><br><strong><?= itflow_vops_e($stage) ?></strong><br><span class="text-muted"><?= intval($stage_counts[$stage]) ?></span></div>
    <?php } ?>
</div>

<?php if (!$items) { ?>
    <div class="itflow-people-card text-center p-5">
        <h4>No employee lifecycle records yet</h4>
        <p class="text-muted">This module is ready for employee onboarding/offboarding records and task templates.</p>
    </div>
<?php } ?>

<?php foreach ($items as $item) { ?>
    <div class="itflow-people-card">
        <div class="row align-items-center">
            <div class="col-md-3"><strong><?= itflow_vops_e($item['employee_name'] ?? '') ?></strong><br><span class="text-muted"><?= itflow_vops_e($item['client_name'] ?? '') ?></span></div>
            <div class="col-md-3"><?= itflow_vops_e($item['employee_title'] ?? '') ?><br><small class="text-muted"><?= itflow_vops_e($item['employee_start_date'] ?: 'No start date') ?></small></div>
            <div class="col-md-3"><div class="progress" style="height:6px"><div class="progress-bar" style="width:<?= intval($item['employee_completion'] ?? 0) ?>%"></div></div><small><?= intval($item['employee_completion'] ?? 0) ?>%</small></div>
            <div class="col-md-3"><span class="badge badge-info"><?= itflow_vops_e($item['employee_stage'] ?? '') ?></span> <span class="badge badge-warning"><?= itflow_vops_e($item['employee_risk'] ?? '') ?></span></div>
        </div>
    </div>
<?php } ?>

<?php require_once "includes/footer.php"; ?>
