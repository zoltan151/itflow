<?php
require_once "includes/inc_all_agent.php";

function itflow_vops_e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function itflow_vops_status_class($status) {
    $status = strtolower((string)$status);
    if (str_contains($status, 'development')) return 'itflow-vops-status-dev';
    if (str_contains($status, 'coming')) return 'itflow-vops-status-soon';
    if (str_contains($status, 'ship') || str_contains($status, 'complete')) return 'itflow-vops-status-done';
    if (str_contains($status, 'planned')) return 'itflow-vops-status-planned';
    return 'itflow-vops-status-backlog';
}

$today = new DateTimeImmutable('first day of this month');
$month = intval($today->format('n'));
$quarter_start_month = 1 + (intdiv($month - 1, 3) * 3);
$quarter_start = $today->setDate(intval($today->format('Y')), $quarter_start_month, 1);

$quarters = [];
for ($i = 0; $i < 4; $i++) {
    $start = $quarter_start->modify('+' . ($i * 3) . ' months');
    $end = $start->modify('+2 months')->modify('last day of this month');
    $quarters[] = [
        'label' => 'Q' . ceil(intval($start->format('n')) / 3) . ' ' . $start->format('Y'),
        'sub' => $start->format('M') . ' - ' . $end->format('M Y'),
        'start' => $start,
        'end' => $end
    ];
}

$lanes = [
    'Documentation' => ['icon' => 'fa-file-alt', 'desc' => 'Improve documentation and access'],
    'Onboarding' => ['icon' => 'fa-users', 'desc' => 'Streamline client and employee onboarding'],
    'Integrations' => ['icon' => 'fa-plug', 'desc' => 'Expand platform integrations'],
    'Automation' => ['icon' => 'fa-cogs', 'desc' => 'Automate communication and operations'],
    'AI / Tray Agent' => ['icon' => 'fa-robot', 'desc' => 'Self-help and AI-assisted support'],
    'Other' => ['icon' => 'fa-map-signs', 'desc' => 'Other initiatives']
];

$items_by_lane = [];
foreach (array_keys($lanes) as $lane) {
    $items_by_lane[$lane] = [];
}

$sql = mysqli_query($mysqli, "SELECT * FROM roadmap_items WHERE roadmap_item_archived_at IS NULL ORDER BY roadmap_item_pinned DESC, roadmap_item_sort_order ASC, roadmap_item_priority ASC, roadmap_item_title ASC LIMIT 200");
if ($sql) {
    while ($row = mysqli_fetch_assoc($sql)) {
        $lane = $row['roadmap_item_lane'] ?: $row['roadmap_item_category'] ?: 'Other';
        if (!isset($items_by_lane[$lane])) {
            $lane = isset($lanes[$row['roadmap_item_category'] ?? '']) ? $row['roadmap_item_category'] : 'Other';
        }
        $items_by_lane[$lane][] = $row;
    }
}

$summary = [
    'active' => 0,
    'dev' => 0,
    'high' => 0,
    'shipped' => 0
];

foreach ($items_by_lane as $lane_items) {
    foreach ($lane_items as $item) {
        $status = strtolower($item['roadmap_item_status'] ?? '');
        $priority = strtolower($item['roadmap_item_priority'] ?? '');
        if (!str_contains($status, 'ship') && !str_contains($status, 'complete')) $summary['active']++;
        if (str_contains($status, 'development')) $summary['dev']++;
        if ($priority === 'critical' || $priority === 'high') $summary['high']++;
        if (str_contains($status, 'ship') || str_contains($status, 'complete')) $summary['shipped']++;
    }
}

function itflow_vops_timeline_style($item, $quarters) {
    $start_raw = $item['roadmap_item_start_date'] ?? '';
    $target_raw = $item['roadmap_item_target_date'] ?? '';

    if (!$start_raw || !$target_raw) {
        return 'grid-column: 1 / span 1;';
    }

    try {
        $start = new DateTimeImmutable($start_raw);
        $target = new DateTimeImmutable($target_raw);
    } catch (Exception $e) {
        return 'grid-column: 1 / span 1;';
    }

    $start_col = 1;
    $end_col = 1;

    foreach ($quarters as $i => $quarter) {
        if ($start <= $quarter['end']) {
            $start_col = $i + 1;
            break;
        }
    }

    foreach ($quarters as $i => $quarter) {
        if ($target <= $quarter['end']) {
            $end_col = $i + 1;
            break;
        }
        $end_col = $i + 1;
    }

    if ($end_col < $start_col) {
        $end_col = $start_col;
    }

    $span = max(1, $end_col - $start_col + 1);
    return 'grid-column: ' . $start_col . ' / span ' . $span . ';';
}
?>

<style>
.itflow-vops-page .small-box-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px;min-height:112px}
.itflow-vops-page .metric-icon{width:54px;height:54px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px}
.itflow-vops-page .metric-blue{background:#e8f2ff;color:#0d6efd}.itflow-vops-page .metric-orange{background:#fff4dd;color:#f59f00}.itflow-vops-page .metric-red{background:#ffe8e8;color:#dc3545}.itflow-vops-page .metric-green{background:#e7f7ed;color:#198754}
.itflow-vops-roadmap-grid{display:grid;grid-template-columns:190px repeat(4,1fr);border:1px solid #e5e7eb;border-radius:10px;overflow:hidden;background:#fff}
.itflow-vops-roadmap-header,.itflow-vops-roadmap-lane,.itflow-vops-roadmap-cell{border-bottom:1px solid #edf0f3}
.itflow-vops-roadmap-header{padding:14px;background:#fbfcfe;font-weight:600;text-align:center}
.itflow-vops-roadmap-lane{padding:22px 18px;background:#fff;border-right:1px solid #edf0f3;min-height:116px}
.itflow-vops-roadmap-track{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;grid-column:2 / span 4;padding:18px;min-height:116px;border-bottom:1px solid #edf0f3;background:linear-gradient(to right,transparent 24.8%,#edf0f3 25%,transparent 25.2%,transparent 49.8%,#edf0f3 50%,transparent 50.2%,transparent 74.8%,#edf0f3 75%,transparent 75.2%)}
.itflow-vops-bar{border-radius:8px;padding:10px 12px;border:1px solid #cfd8e3;background:#f8fafc;font-weight:600;min-height:58px;box-shadow:0 1px 2px rgba(15,23,42,.06)}
.itflow-vops-status-backlog{background:#f8fafc;border-color:#cbd5e1}.itflow-vops-status-planned{background:#e8f2ff;border-color:#94c6ff}.itflow-vops-status-dev{background:#fff3cd;border-color:#ffd166}.itflow-vops-status-soon{background:#e7f7ed;border-color:#8ad7a7}.itflow-vops-status-done{background:#dcfce7;border-color:#22c55e}
.itflow-vops-badge{display:inline-block;font-size:11px;border-radius:4px;padding:2px 6px;margin-top:6px;background:#0d6efd;color:white}
.itflow-vops-sidebar-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin-bottom:16px}
.itflow-vops-priority-list{padding-left:20px;margin-bottom:0}.itflow-vops-priority-list li{margin-bottom:14px}
</style>

<div class="itflow-vops-page">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h3 class="mb-0">Platform Roadmap <small class="text-muted"><i class="far fa-question-circle"></i></small></h3>
            <div class="text-muted">Visual roadmap timeline, priority planning, and dependency view</div>
        </div>
        <div>
            <a href="roadmap.php" class="btn btn-outline-secondary"><i class="fas fa-th-large mr-1"></i> Board</a>
            <a href="roadmap_visual.php" class="btn btn-primary"><i class="fas fa-stream mr-1"></i> Timeline</a>
        </div>
    </div>

    <div class="mb-3">
        <a class="btn btn-sm btn-outline-secondary" href="roadmap.php">Board</a>
        <a class="btn btn-sm btn-primary" href="roadmap_visual.php">Timeline</a>
        <button class="btn btn-sm btn-outline-secondary" disabled>Dependencies</button>
    </div>

    <div class="row mb-4">
        <div class="col-md-3"><div class="small-box-card d-flex align-items-center"><div class="metric-icon metric-blue mr-3"><i class="fas fa-rocket"></i></div><div><div class="text-muted">Active Initiatives</div><h2 class="mb-0"><?= intval($summary['active']) ?></h2></div></div></div>
        <div class="col-md-3"><div class="small-box-card d-flex align-items-center"><div class="metric-icon metric-orange mr-3"><i class="fas fa-code"></i></div><div><div class="text-muted">In Development</div><h2 class="mb-0"><?= intval($summary['dev']) ?></h2></div></div></div>
        <div class="col-md-3"><div class="small-box-card d-flex align-items-center"><div class="metric-icon metric-red mr-3"><i class="fas fa-flag"></i></div><div><div class="text-muted">High Priority</div><h2 class="mb-0"><?= intval($summary['high']) ?></h2></div></div></div>
        <div class="col-md-3"><div class="small-box-card d-flex align-items-center"><div class="metric-icon metric-green mr-3"><i class="fas fa-check-circle"></i></div><div><div class="text-muted">Shipped</div><h2 class="mb-0"><?= intval($summary['shipped']) ?></h2></div></div></div>
    </div>

    <div class="row">
        <div class="col-xl-9">
            <div class="itflow-vops-roadmap-grid">
                <div class="itflow-vops-roadmap-header text-left">Category</div>
                <?php foreach ($quarters as $quarter) { ?>
                    <div class="itflow-vops-roadmap-header"><?= itflow_vops_e($quarter['label']) ?><br><small class="text-muted"><?= itflow_vops_e($quarter['sub']) ?></small></div>
                <?php } ?>

                <?php foreach ($lanes as $lane => $meta) { ?>
                    <div class="itflow-vops-roadmap-lane">
                        <div class="font-weight-bold"><i class="fas <?= itflow_vops_e($meta['icon']) ?> text-primary mr-2"></i><?= itflow_vops_e($lane) ?></div>
                        <small class="text-muted"><?= itflow_vops_e($meta['desc']) ?></small>
                    </div>
                    <div class="itflow-vops-roadmap-track">
                        <?php foreach ($items_by_lane[$lane] ?? [] as $item) { ?>
                            <?php $style = itflow_vops_timeline_style($item, $quarters); ?>
                            <div class="itflow-vops-bar <?= itflow_vops_e(itflow_vops_status_class($item['roadmap_item_status'] ?? '')) ?>" style="<?= itflow_vops_e($style) ?>">
                                <div><?= itflow_vops_e($item['roadmap_item_title']) ?></div>
                                <span class="itflow-vops-badge"><?= itflow_vops_e($item['roadmap_item_status']) ?></span>
                                <?php if (intval($item['roadmap_item_progress'] ?? 0) > 0) { ?>
                                    <div class="progress mt-2" style="height:5px">
                                        <div class="progress-bar" style="width:<?= intval($item['roadmap_item_progress']) ?>%"></div>
                                    </div>
                                <?php } ?>
                            </div>
                        <?php } ?>
                    </div>
                <?php } ?>
            </div>

            <div class="mt-3 text-muted">
                <span class="mr-3"><i class="fas fa-circle text-secondary"></i> Backlog</span>
                <span class="mr-3"><i class="fas fa-circle text-primary"></i> Planned</span>
                <span class="mr-3"><i class="fas fa-circle text-warning"></i> In Development</span>
                <span class="mr-3"><i class="fas fa-circle text-success"></i> Coming Soon / Shipped</span>
            </div>
        </div>

        <div class="col-xl-3">
            <div class="itflow-vops-sidebar-card">
                <h5><i class="fas fa-thumbtack mr-2"></i>Pinned Priorities</h5>
                <ol class="itflow-vops-priority-list">
                    <?php
                    $pinned_sql = mysqli_query($mysqli, "SELECT roadmap_item_title, roadmap_item_priority FROM roadmap_items WHERE roadmap_item_archived_at IS NULL AND roadmap_item_pinned = 1 ORDER BY roadmap_item_sort_order ASC LIMIT 10");
                    if ($pinned_sql) {
                        while ($pinned = mysqli_fetch_assoc($pinned_sql)) {
                            echo "<li><strong>" . itflow_vops_e($pinned['roadmap_item_title']) . "</strong><br><small class='badge badge-danger'>" . itflow_vops_e($pinned['roadmap_item_priority']) . "</small></li>";
                        }
                    }
                    ?>
                </ol>
            </div>

            <div class="itflow-vops-sidebar-card">
                <h5><i class="far fa-clock mr-2"></i>Recently Updated</h5>
                <?php
                $recent_sql = mysqli_query($mysqli, "SELECT roadmap_item_title, roadmap_item_status, roadmap_item_updated_at FROM roadmap_items WHERE roadmap_item_archived_at IS NULL ORDER BY COALESCE(roadmap_item_updated_at, roadmap_item_created_at) DESC LIMIT 8");
                if ($recent_sql) {
                    while ($recent = mysqli_fetch_assoc($recent_sql)) {
                        echo "<div class='border-bottom py-2'><strong>" . itflow_vops_e($recent['roadmap_item_title']) . "</strong><br><small class='text-muted'>" . itflow_vops_e($recent['roadmap_item_status']) . "</small></div>";
                    }
                }
                ?>
            </div>
        </div>
    </div>
</div>

<?php require_once "includes/footer.php"; ?>
