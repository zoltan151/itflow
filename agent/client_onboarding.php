
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

$phases = ['Backfill Needed','Signed','Discovery','Access Collection','Planning','Deployment','Documentation','Training','Go-Live','Stabilization','Complete'];
$has_table = itflow_vops_table_exists('client_onboardings');
$phase_counts = array_fill_keys($phases, 0);
$cards = array_fill_keys($phases, []);

if ($has_table) {
    $sql = mysqli_query($mysqli, "SELECT co.*, c.client_name, u.user_name FROM client_onboardings co LEFT JOIN clients c ON c.client_id = co.onboarding_client_id LEFT JOIN users u ON u.user_id = co.onboarding_owner_id ORDER BY c.client_name ASC");
    if ($sql) {
        while ($row = mysqli_fetch_assoc($sql)) {
            $phase = $row['onboarding_phase'] ?: 'Backfill Needed';
            if (!isset($cards[$phase])) $phase = 'Backfill Needed';
            $cards[$phase][] = $row;
            $phase_counts[$phase]++;
        }
    }
}

$total = array_sum($phase_counts);
$blocked = 0;
$sum = 0;
foreach ($cards as $rows) {
    foreach ($rows as $row) {
        if (intval($row['onboarding_blocked'] ?? 0)) $blocked++;
        $sum += intval($row['onboarding_completion'] ?? 0);
    }
}
$avg = $total ? round($sum / $total) : 0;
?>

<style>
.itflow-on-card{background:#fff;border:1px solid #dee2e6;border-radius:.35rem;padding:1rem;margin-bottom:1rem}
.itflow-on-board{display:flex;gap:1rem;overflow-x:auto;padding-bottom:1rem}
.itflow-on-col{min-width:260px;background:#f8f9fa;border:1px solid #dee2e6;border-radius:.35rem;padding:1rem}
.itflow-on-client{background:#fff;border:1px solid #dee2e6;border-radius:.25rem;padding:.75rem;margin-bottom:.75rem}
.itflow-on-rail{display:flex;gap:.35rem;overflow-x:auto;margin-bottom:1rem}
.itflow-on-step{min-width:130px;background:#e9f2ff;border:1px solid #b6d4fe;border-radius:.35rem;padding:.5rem;text-align:center;font-weight:600}
</style>

<div class="d-flex justify-content-between align-items-center mb-3">
    <div>
        <h3 class="mb-0">Client Onboarding</h3>
        <div class="text-muted">Visual onboarding tracker and progress board</div>
    </div>
    <button class="btn btn-primary" disabled>Start Onboarding</button>
</div>

<?php if (!$has_table) { ?><div class="alert alert-warning">Client onboarding table is not available yet.</div><?php } ?>

<div class="row">
    <div class="col-md-3"><div class="itflow-on-card"><div class="text-muted">Active Onboardings</div><h2><?= intval($total - intval($phase_counts['Complete'])) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-on-card"><div class="text-muted">Blocked</div><h2><?= intval($blocked) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-on-card"><div class="text-muted">Backfill Needed</div><h2><?= intval($phase_counts['Backfill Needed']) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-on-card"><div class="text-muted">Avg Completion</div><h2><?= intval($avg) ?>%</h2></div></div>
</div>

<div class="itflow-on-rail">
    <?php foreach ($phases as $phase) { ?>
        <div class="itflow-on-step"><?= itflow_vops_e($phase) ?><br><span class="text-muted"><?= intval($phase_counts[$phase]) ?></span></div>
    <?php } ?>
</div>

<div class="itflow-on-board">
    <?php foreach ($phases as $phase) { ?>
        <div class="itflow-on-col">
            <h5><?= itflow_vops_e($phase) ?> <span class="badge badge-light"><?= intval($phase_counts[$phase]) ?></span></h5>
            <?php foreach ($cards[$phase] as $card) { ?>
                <div class="itflow-on-client">
                    <strong><?= itflow_vops_e($card['client_name'] ?: 'Unknown Client') ?></strong><br>
                    <span class="text-muted"><?= itflow_vops_e($card['onboarding_status'] ?? '') ?></span>
                    <div class="progress mt-2" style="height:6px"><div class="progress-bar" style="width:<?= intval($card['onboarding_completion'] ?? 0) ?>%"></div></div>
                    <div class="small mt-2">Owner: <?= itflow_vops_e($card['user_name'] ?: 'Unassigned') ?></div>
                    <?php if ($phase === 'Backfill Needed') { ?><span class="badge badge-warning mt-2">Needs Backfill</span><?php } ?>
                    <?php if (intval($card['onboarding_blocked'] ?? 0)) { ?><span class="badge badge-danger mt-2">Blocked</span><?php } ?>
                </div>
            <?php } ?>
        </div>
    <?php } ?>
</div>

<?php require_once "includes/footer.php"; ?>
