<?php
require_once "includes/inc_all_agent.php";

function itflow_vops_e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

$phases = [
    'Backfill Needed',
    'Signed',
    'Discovery',
    'Access Collection',
    'Planning',
    'Deployment',
    'Documentation',
    'Training',
    'Go-Live',
    'Stabilization',
    'Complete'
];

$phase_counts = array_fill_keys($phases, 0);
$cards_by_phase = array_fill_keys($phases, []);

$sql = mysqli_query($mysqli, "
    SELECT co.*, c.client_name, u.user_name
    FROM client_onboardings co
    LEFT JOIN clients c ON c.client_id = co.onboarding_client_id
    LEFT JOIN users u ON u.user_id = co.onboarding_owner_id
    ORDER BY FIELD(co.onboarding_phase, 'Backfill Needed','Signed','Discovery','Access Collection','Planning','Deployment','Documentation','Training','Go-Live','Stabilization','Complete'), c.client_name ASC
");

if ($sql) {
    while ($row = mysqli_fetch_assoc($sql)) {
        $phase = $row['onboarding_phase'] ?: 'Backfill Needed';
        if (!isset($cards_by_phase[$phase])) {
            $phase = 'Backfill Needed';
        }
        $cards_by_phase[$phase][] = $row;
        $phase_counts[$phase]++;
    }
}

$total_onboardings = array_sum($phase_counts);
$blocked_count = 0;
$completion_sum = 0;
foreach ($cards_by_phase as $rows) {
    foreach ($rows as $row) {
        if (intval($row['onboarding_blocked'])) $blocked_count++;
        $completion_sum += intval($row['onboarding_completion']);
    }
}
$avg_completion = $total_onboardings ? round($completion_sum / $total_onboardings) : 0;
?>

<style>
.itflow-onboarding-page .metric-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px}
.itflow-onboarding-page .phase-rail{display:flex;gap:4px;overflow-x:auto;margin-bottom:20px}
.itflow-onboarding-page .phase-step{background:#eef5ff;border:1px solid #cfe2ff;border-radius:8px;padding:10px 18px;min-width:135px;text-align:center;font-weight:600;clip-path:polygon(0 0,92% 0,100% 50%,92% 100%,0 100%,8% 50%)}
.itflow-onboarding-page .phase-step-complete{background:#e7f7ed;border-color:#9ad7ad}
.itflow-onboarding-board{display:flex;gap:12px;overflow-x:auto;padding-bottom:16px}
.itflow-onboarding-column{background:#f8fafc;border:1px solid #e5e7eb;border-radius:10px;min-width:260px;max-width:280px;padding:12px}
.itflow-onboarding-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px;margin-bottom:12px;box-shadow:0 1px 2px rgba(15,23,42,.05)}
.itflow-onboarding-progress{height:6px;border-radius:99px;background:#e5e7eb;overflow:hidden}
.itflow-onboarding-progress > div{height:6px;background:#0d6efd}
.itflow-onboarding-detail{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px}
.itflow-right-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:16px}
</style>

<div class="itflow-onboarding-page">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h3 class="mb-0">Client Onboarding <small class="text-muted"><i class="far fa-question-circle"></i></small></h3>
            <div class="text-muted">Visual onboarding tracker, progress board, and communication funnel</div>
        </div>
        <button class="btn btn-primary" disabled><i class="fas fa-plus mr-1"></i> Start Onboarding</button>
    </div>

    <div class="row mb-4">
        <div class="col-md-3"><div class="metric-card"><small class="text-muted">Active Onboardings</small><h2><?= intval($total_onboardings - ($phase_counts['Complete'] ?? 0)) ?></h2></div></div>
        <div class="col-md-3"><div class="metric-card"><small class="text-muted">Blocked</small><h2><?= intval($blocked_count) ?></h2></div></div>
        <div class="col-md-3"><div class="metric-card"><small class="text-muted">Backfill Needed</small><h2><?= intval($phase_counts['Backfill Needed'] ?? 0) ?></h2></div></div>
        <div class="col-md-3"><div class="metric-card"><small class="text-muted">Avg Completion</small><h2><?= intval($avg_completion) ?>%</h2></div></div>
    </div>

    <div class="phase-rail">
        <?php foreach ($phases as $phase) { ?>
            <div class="phase-step <?= $phase === 'Complete' ? 'phase-step-complete' : '' ?>">
                <?= itflow_vops_e($phase) ?><br><span class="text-muted"><?= intval($phase_counts[$phase]) ?></span>
            </div>
        <?php } ?>
    </div>

    <div class="row">
        <div class="col-xl-9">
            <div class="itflow-onboarding-board">
                <?php foreach ($phases as $phase) { ?>
                    <div class="itflow-onboarding-column">
                        <div class="d-flex justify-content-between mb-2">
                            <strong><?= itflow_vops_e($phase) ?></strong>
                            <span class="badge badge-light"><?= intval($phase_counts[$phase]) ?></span>
                        </div>

                        <?php foreach ($cards_by_phase[$phase] as $card) { ?>
                            <div class="itflow-onboarding-card">
                                <div class="font-weight-bold"><?= itflow_vops_e($card['client_name'] ?: 'Unknown Client') ?></div>
                                <div class="text-muted mb-2"><?= itflow_vops_e($card['onboarding_status']) ?></div>
                                <div class="itflow-onboarding-progress mb-2">
                                    <div style="width:<?= intval($card['onboarding_completion']) ?>%"></div>
                                </div>
                                <div class="small mb-2"><?= intval($card['onboarding_completion']) ?>% complete</div>
                                <div class="small text-muted">Owner: <?= itflow_vops_e($card['user_name'] ?: 'Unassigned') ?></div>
                                <?php if ($card['onboarding_target_go_live']) { ?>
                                    <div class="small text-muted">Target Go-Live: <?= itflow_vops_e($card['onboarding_target_go_live']) ?></div>
                                <?php } ?>
                                <?php if (intval($card['onboarding_blocked'])) { ?>
                                    <span class="badge badge-danger mt-2">Blocked</span>
                                <?php } elseif ($phase === 'Backfill Needed') { ?>
                                    <span class="badge badge-warning mt-2">Needs Backfill</span>
                                <?php } ?>
                            </div>
                        <?php } ?>

                        <?php if (empty($cards_by_phase[$phase])) { ?>
                            <div class="text-muted small p-3 text-center">No clients in this phase</div>
                        <?php } ?>
                    </div>
                <?php } ?>
            </div>
        </div>

        <div class="col-xl-3">
            <div class="itflow-right-card">
                <h5><i class="fas fa-bolt mr-2"></i>Automation & Client Communication</h5>
                <div class="border-bottom py-2"><strong>Event-triggered</strong><br><small class="text-muted">Access approved, agreement signed, blocker created</small></div>
                <div class="border-bottom py-2"><strong>Scheduled communications</strong><br><small class="text-muted">Welcome emails, progress updates, reminders</small></div>
                <button class="btn btn-primary btn-block mt-3" disabled>Manage Automations</button>
            </div>

            <div class="itflow-right-card">
                <h5><i class="fas fa-exclamation-triangle mr-2"></i>Blocked / Missing Data</h5>
                <?php
                $blocked_sql = mysqli_query($mysqli, "
                    SELECT c.client_name, co.onboarding_blocker_note
                    FROM client_onboardings co
                    LEFT JOIN clients c ON c.client_id = co.onboarding_client_id
                    WHERE co.onboarding_blocked = 1 OR co.onboarding_phase = 'Backfill Needed'
                    ORDER BY c.client_name ASC LIMIT 8
                ");
                if ($blocked_sql && mysqli_num_rows($blocked_sql)) {
                    while ($blocked = mysqli_fetch_assoc($blocked_sql)) {
                        echo "<div class='border-bottom py-2'><strong>" . itflow_vops_e($blocked['client_name']) . "</strong><br><small class='text-muted'>" . itflow_vops_e($blocked['onboarding_blocker_note'] ?: 'Needs onboarding backfill') . "</small></div>";
                    }
                } else {
                    echo "<div class='text-muted'>No blocked onboarding items.</div>";
                }
                ?>
            </div>
        </div>
    </div>
</div>

<?php require_once "includes/footer.php"; ?>
