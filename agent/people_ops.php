<?php
require_once "includes/inc_all_agent.php";

function itflow_vops_e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

$stages = ['Request Received', 'Access & Licensing', 'Hardware Prep', 'Security Setup', 'Training / SOP Assignment', 'First Day', '30-Day Follow-up', 'Complete'];
$stage_counts = array_fill_keys($stages, 0);

$items = [];
$sql = mysqli_query($mysqli, "
    SELECT eli.*, c.client_name, u.user_name
    FROM employee_lifecycle_items eli
    LEFT JOIN clients c ON c.client_id = eli.employee_lifecycle_client_id
    LEFT JOIN users u ON u.user_id = eli.employee_assigned_user_id
    ORDER BY eli.employee_start_date ASC, eli.employee_created_at DESC LIMIT 100
");
if ($sql) {
    while ($row = mysqli_fetch_assoc($sql)) {
        $items[] = $row;
        if (isset($stage_counts[$row['employee_stage']])) {
            $stage_counts[$row['employee_stage']]++;
        }
    }
}

$new_hires = 0;
$offboards = 0;
$waiting = 0;
$completion_sum = 0;
foreach ($items as $item) {
    if (strtolower($item['employee_lifecycle_type']) === 'offboarding') $offboards++; else $new_hires++;
    if (str_contains(strtolower($item['employee_status']), 'waiting')) $waiting++;
    $completion_sum += intval($item['employee_completion']);
}
$avg_completion = count($items) ? round($completion_sum / count($items)) : 0;
?>

<style>
.itflow-people-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:14px}
.itflow-people-metric{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px}
.itflow-people-stage{display:flex;justify-content:space-around;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:16px;overflow-x:auto}
.itflow-people-stage .step{min-width:120px;text-align:center}
.itflow-people-stage .circle{width:34px;height:34px;border-radius:50%;border:1px solid #cbd5e1;margin:0 auto 8px auto;display:flex;align-items:center;justify-content:center;background:#fff;font-weight:bold}
.itflow-people-stage .step:first-child .circle{background:#0d6efd;color:#fff}
.itflow-right-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:16px}
.itflow-progress{height:6px;border-radius:99px;background:#e5e7eb;overflow:hidden}.itflow-progress div{height:6px;background:#0d6efd}
</style>

<div class="itflow-people-page">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h3 class="mb-0">Employee Onboarding & Offboarding <small class="text-muted"><i class="far fa-question-circle"></i></small></h3>
            <div class="text-muted">Manage new hire onboarding and employee offboarding across all clients</div>
        </div>
        <button class="btn btn-primary" disabled><i class="fas fa-plus mr-1"></i> Add Employee</button>
    </div>

    <div class="row mb-4">
        <div class="col-md-3"><div class="itflow-people-metric"><small class="text-muted">New Hires</small><h2><?= intval($new_hires) ?></h2></div></div>
        <div class="col-md-3"><div class="itflow-people-metric"><small class="text-muted">Offboardings</small><h2><?= intval($offboards) ?></h2></div></div>
        <div class="col-md-3"><div class="itflow-people-metric"><small class="text-muted">Waiting on Client</small><h2><?= intval($waiting) ?></h2></div></div>
        <div class="col-md-3"><div class="itflow-people-metric"><small class="text-muted">Completion Rate</small><h2><?= intval($avg_completion) ?>%</h2></div></div>
    </div>

    <div class="mb-3">
        <button class="btn btn-sm btn-primary">Onboarding</button>
        <button class="btn btn-sm btn-outline-secondary">Offboarding</button>
        <button class="btn btn-sm btn-outline-secondary">Templates</button>
    </div>

    <div class="itflow-people-stage">
        <?php $i = 1; foreach ($stages as $stage) { ?>
            <div class="step">
                <div class="circle"><?= $i++ ?></div>
                <strong><?= itflow_vops_e($stage) ?></strong><br>
                <small class="text-muted"><?= intval($stage_counts[$stage]) ?></small>
            </div>
        <?php } ?>
    </div>

    <div class="row">
        <div class="col-xl-9">
            <?php if (empty($items)) { ?>
                <div class="itflow-people-card text-center p-5">
                    <h4>No employee lifecycle records yet</h4>
                    <p class="text-muted">This module is ready for new hire onboarding, offboarding, task templates, and client input tracking.</p>
                </div>
            <?php } ?>

            <?php foreach ($items as $item) { ?>
                <div class="itflow-people-card">
                    <div class="row align-items-center">
                        <div class="col-md-3">
                            <h5 class="mb-1"><?= itflow_vops_e($item['employee_name']) ?></h5>
                            <div class="text-muted"><?= itflow_vops_e($item['client_name']) ?></div>
                            <div class="small"><?= itflow_vops_e($item['employee_title']) ?></div>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Start Date</small><br>
                            <?= itflow_vops_e($item['employee_start_date'] ?: 'Not Set') ?><br>
                            <small class="text-muted">Assigned Tech: <?= itflow_vops_e($item['user_name'] ?: 'Unassigned') ?></small>
                        </div>
                        <div class="col-md-3">
                            <small class="text-muted">Overall Progress</small>
                            <div class="itflow-progress"><div style="width:<?= intval($item['employee_completion']) ?>%"></div></div>
                            <small><?= intval($item['employee_completion']) ?>%</small>
                        </div>
                        <div class="col-md-3">
                            <span class="badge badge-info"><?= itflow_vops_e($item['employee_stage']) ?></span>
                            <span class="badge badge-warning"><?= itflow_vops_e($item['employee_risk']) ?></span>
                        </div>
                    </div>
                </div>
            <?php } ?>
        </div>

        <div class="col-xl-3">
            <div class="itflow-right-card">
                <h5>Templates</h5>
                <div class="border-bottom py-2">Standard Employee Onboarding <span class="badge badge-light">Default</span></div>
                <div class="border-bottom py-2">Executive Onboarding <span class="badge badge-light">Executive</span></div>
                <div class="border-bottom py-2">Remote Employee Onboarding <span class="badge badge-light">Remote</span></div>
            </div>

            <div class="itflow-right-card">
                <h5>Automations</h5>
                <div class="custom-control custom-switch"><input type="checkbox" class="custom-control-input" id="auto1" checked disabled><label class="custom-control-label" for="auto1">Welcome email on start date</label></div>
                <div class="custom-control custom-switch"><input type="checkbox" class="custom-control-input" id="auto2" checked disabled><label class="custom-control-label" for="auto2">Start date reminder</label></div>
                <div class="custom-control custom-switch"><input type="checkbox" class="custom-control-input" id="auto3" checked disabled><label class="custom-control-label" for="auto3">Generate checklist</label></div>
            </div>
        </div>
    </div>
</div>

<?php require_once "includes/footer.php"; ?>
