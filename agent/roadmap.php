<?php
// ITFLOW_PLATFORM_ROADMAP_PHASE3B
// ITFLOW_ROADMAP_PHASE3E_PLANNING_FIELDS
// ITFLOW_ROADMAP_DROPDOWN_FIX
// ITFLOW_ROADMAP_QUICK_PIN_EDIT_FIX
// ITFLOW_ROADMAP_EDIT_MODAL_500_FIX
// ITFLOW_ROADMAP_MODAL_BOOTSTRAP_HARDENING

require_once "includes/inc_all.php";

enforceUserPermission('module_config');

$page_title = "InfoTech Infrastructure Roadmap";

$roadmap_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
$roadmap_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
$roadmap_priorities = ['Low', 'Medium', 'High', 'Critical'];
$roadmap_efforts = ['Tiny', 'Small', 'Medium', 'Large', 'XL'];
$roadmap_impacts = ['Low', 'Medium', 'High', 'Critical'];
$roadmap_complexities = ['Low', 'Medium', 'High', 'Very High'];

$status_badges = [
    'Backlog' => 'secondary',
    'Planned' => 'primary',
    'In Development' => 'warning',
    'Coming Soon' => 'info',
    'Shipped' => 'success',
];

$priority_badges = [
    'Low' => 'secondary',
    'Medium' => 'info',
    'High' => 'warning',
    'Critical' => 'danger',
];

$effort_badges = [
    'Tiny' => 'success',
    'Small' => 'success',
    'Medium' => 'info',
    'Large' => 'warning',
    'XL' => 'danger',
];

$impact_badges = [
    'Low' => 'secondary',
    'Medium' => 'info',
    'High' => 'warning',
    'Critical' => 'danger',
];

$complexity_badges = [
    'Low' => 'success',
    'Medium' => 'info',
    'High' => 'warning',
    'Very High' => 'danger',
];

$filter_status = sanitizeInput($_GET['status'] ?? '');
$filter_category = sanitizeInput($_GET['category'] ?? '');
$filter_priority = sanitizeInput($_GET['priority'] ?? '');
$filter_effort = sanitizeInput($_GET['effort'] ?? '');
$filter_impact = sanitizeInput($_GET['impact'] ?? '');
$filter_complexity = sanitizeInput($_GET['complexity'] ?? '');
$filter_owner_id = intval($_GET['owner_id'] ?? 0);
$filter_pinned = intval($_GET['pinned'] ?? 0);
$q = sanitizeInput($_GET['q'] ?? '');
$archived = intval($_GET['archived'] ?? 0);

if (!in_array($filter_status, $roadmap_statuses, true)) {
    $filter_status = '';
}

if (!in_array($filter_category, $roadmap_categories, true)) {
    $filter_category = '';
}

if (!in_array($filter_priority, $roadmap_priorities, true)) {
    $filter_priority = '';
}

if (!in_array($filter_effort, $roadmap_efforts, true)) {
    $filter_effort = '';
}

if (!in_array($filter_impact, $roadmap_impacts, true)) {
    $filter_impact = '';
}

if (!in_array($filter_complexity, $roadmap_complexities, true)) {
    $filter_complexity = '';
}

$where = "WHERE roadmap_item_archived_at " . ($archived ? "IS NOT NULL" : "IS NULL");

if ($filter_status) {
    $filter_status_sql = mysqli_real_escape_string($mysqli, $filter_status);
    $where .= " AND roadmap_item_status = '$filter_status_sql'";
}

if ($filter_category) {
    $filter_category_sql = mysqli_real_escape_string($mysqli, $filter_category);
    $where .= " AND roadmap_item_category = '$filter_category_sql'";
}

if ($filter_priority) {
    $filter_priority_sql = mysqli_real_escape_string($mysqli, $filter_priority);
    $where .= " AND roadmap_item_priority = '$filter_priority_sql'";
}

if ($filter_effort) {
    $filter_effort_sql = mysqli_real_escape_string($mysqli, $filter_effort);
    $where .= " AND roadmap_item_effort = '$filter_effort_sql'";
}

if ($filter_impact) {
    $filter_impact_sql = mysqli_real_escape_string($mysqli, $filter_impact);
    $where .= " AND roadmap_item_impact = '$filter_impact_sql'";
}

if ($filter_complexity) {
    $filter_complexity_sql = mysqli_real_escape_string($mysqli, $filter_complexity);
    $where .= " AND roadmap_item_complexity = '$filter_complexity_sql'";
}

if ($filter_owner_id > 0) {
    $where .= " AND roadmap_item_owner_id = $filter_owner_id";
}

if ($filter_pinned) {
    $where .= " AND roadmap_item_pinned = 1";
}

if ($q) {
    $safe_q = mysqli_real_escape_string($mysqli, $q);
    $where .= " AND (
        roadmap_item_title LIKE '%$safe_q%'
        OR roadmap_item_description LIKE '%$safe_q%'
        OR roadmap_item_notes LIKE '%$safe_q%'
        OR roadmap_item_dependencies LIKE '%$safe_q%'
        OR roadmap_item_target_version LIKE '%$safe_q%'
    )";
}

function roadmapUrl(array $overrides = []) {
    $params = $_GET;

    foreach ($overrides as $key => $value) {
        if ($value === '' || $value === null) {
            unset($params[$key]);
        } else {
            $params[$key] = $value;
        }
    }

    return 'roadmap.php?' . http_build_query($params);
}

function roadmapActiveClass($current, $expected) {
    return (string)$current === (string)$expected ? 'active' : '';
}

$sql_counts = mysqli_query(
    $mysqli,
    "SELECT roadmap_item_status, COUNT(*) AS count
     FROM roadmap_items
     WHERE roadmap_item_archived_at IS NULL
     GROUP BY roadmap_item_status"
);

$status_counts = array_fill_keys($roadmap_statuses, 0);

while ($row = mysqli_fetch_assoc($sql_counts)) {
    $status_counts[$row['roadmap_item_status']] = intval($row['count']);
}

$sql_total = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM roadmap_items WHERE roadmap_item_archived_at IS NULL");
$total_active = intval(mysqli_fetch_assoc($sql_total)['count'] ?? 0);

$sql_pinned = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM roadmap_items WHERE roadmap_item_archived_at IS NULL AND roadmap_item_pinned = 1");
$total_pinned = intval(mysqli_fetch_assoc($sql_pinned)['count'] ?? 0);

$sql_high_impact = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM roadmap_items WHERE roadmap_item_archived_at IS NULL AND roadmap_item_impact IN ('High', 'Critical')");
$total_high_impact = intval(mysqli_fetch_assoc($sql_high_impact)['count'] ?? 0);

$sql_unassigned = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM roadmap_items WHERE roadmap_item_archived_at IS NULL AND roadmap_item_owner_id = 0");
$total_unassigned = intval(mysqli_fetch_assoc($sql_unassigned)['count'] ?? 0);

$sql_owner_filter_users = mysqli_query(
    $mysqli,
    "SELECT DISTINCT users.user_id, users.user_name
     FROM roadmap_items
     INNER JOIN users ON roadmap_item_owner_id = user_id
     WHERE roadmap_item_archived_at IS NULL
     ORDER BY users.user_name ASC"
);

$sql_roadmap_items = mysqli_query(
    $mysqli,
    "SELECT roadmap_items.*, users.user_name AS owner_name, creator.user_name AS creator_name
     FROM roadmap_items
     LEFT JOIN users ON roadmap_item_owner_id = users.user_id
     LEFT JOIN users AS creator ON roadmap_item_created_by = creator.user_id
     $where
     ORDER BY
        roadmap_item_pinned DESC,
        roadmap_item_sort_order ASC,
        CASE roadmap_item_status
            WHEN 'In Development' THEN 1
            WHEN 'Coming Soon' THEN 2
            WHEN 'Planned' THEN 3
            WHEN 'Backlog' THEN 4
            WHEN 'Shipped' THEN 5
            ELSE 6
        END,
        CASE roadmap_item_priority
            WHEN 'Critical' THEN 1
            WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3
            WHEN 'Low' THEN 4
            ELSE 5
        END,
        CASE roadmap_item_impact
            WHEN 'Critical' THEN 1
            WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3
            WHEN 'Low' THEN 4
            ELSE 5
        END,
        roadmap_item_updated_at DESC,
        roadmap_item_created_at DESC"
);

?>

<div class="card card-dark">
    <div class="card-header py-2">
        <h3 class="card-title mt-2">
            <i class="fas fa-fw fa-map-signs mr-2"></i>InfoTech Infrastructure Roadmap
        </h3>
</div>

    
<!-- ITFLOW_ROADMAP_ACTION_ROW -->
<div class="card-body border-bottom bg-light py-3">
    <div class="d-flex justify-content-between align-items-center flex-wrap">
        <div class="mb-2 mb-md-0">
            <!-- ITFLOW_ROADMAP_VIEW_TOGGLE -->
            <div class="btn-group" role="group" aria-label="Roadmap view toggle">
                <a href="roadmap.php" class="btn btn-primary active">
                    <i class="fas fa-th-large mr-1"></i> Card View
                </a>
                <a href="roadmap_visual.php" class="btn btn-outline-primary">
                    <i class="fas fa-stream mr-1"></i> Timeline View
                </a>
            </div>
            <!-- /ITFLOW_ROADMAP_VIEW_TOGGLE -->
        </div>
        <div>
            <!-- ITFLOW_ROADMAP_ADD_ACTION -->
            <?php if (lookupUserPermission("module_config") >= 2) { ?>
                <button type="button" class="btn btn-primary ajax-modal itflow-roadmap-add-action" data-modal-url="modals/roadmap_add.php" data-modal-size="lg">
                    <i class="fas fa-fw fa-plus mr-1"></i> Add Roadmap Item
                </button>
            <?php } ?>
            <!-- /ITFLOW_ROADMAP_ADD_ACTION -->
        </div>
    </div>
</div>
<!-- /ITFLOW_ROADMAP_ACTION_ROW -->
<div class="card-body border-bottom">
        <div class="row text-center">
            <div class="col-md-3 col-6 mb-2">
                <div class="border rounded p-2 bg-light">
                    <div class="h4 mb-0"><?= $total_active ?></div>
                    <div class="text-muted small">Active Items</div>
                </div>
            </div>
            <div class="col-md-3 col-6 mb-2">
                <div class="border rounded p-2 bg-light">
                    <div class="h4 mb-0"><?= $total_pinned ?></div>
                    <div class="text-muted small">Pinned</div>
                </div>
            </div>
            <div class="col-md-3 col-6 mb-2">
                <div class="border rounded p-2 bg-light">
                    <div class="h4 mb-0"><?= $total_high_impact ?></div>
                    <div class="text-muted small">High / Critical Impact</div>
                </div>
            </div>
            <div class="col-md-3 col-6 mb-2">
                <div class="border rounded p-2 bg-light">
                    <div class="h4 mb-0"><?= $total_unassigned ?></div>
                    <div class="text-muted small">Unassigned</div>
                </div>
            </div>
        </div>
    </div>

    <div class="card-body border-bottom d-print-none">
        <div class="row">
            <div class="col-md-8">
                <div class="btn-group flex-wrap mb-2" role="group" aria-label="Roadmap status filters">
                    <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_status, '') ?>" href="<?= roadmapUrl(['status' => '']) ?>">
                        All
                    </a>
                    <?php foreach ($roadmap_statuses as $status) { ?>
                        <a class="btn btn-sm btn-outline-<?= $status_badges[$status] ?> <?= roadmapActiveClass($filter_status, $status) ?>" href="<?= roadmapUrl(['status' => $status]) ?>">
                            <?= $status ?> <span class="badge badge-light ml-1"><?= intval($status_counts[$status]) ?></span>
                        </a>
                    <?php } ?>
                </div>

                <div class="mt-2">
                    <span class="text-muted mr-2">Category:</span>
                    <div class="btn-group flex-wrap" role="group" aria-label="Roadmap category filters">
                        <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_category, '') ?>" href="<?= roadmapUrl(['category' => '']) ?>">All</a>
                        <?php foreach ($roadmap_categories as $category) { ?>
                            <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_category, $category) ?>" href="<?= roadmapUrl(['category' => $category]) ?>"><?= $category ?></a>
                        <?php } ?>
                    </div>
                </div>

                <div class="mt-2">
                    <span class="text-muted mr-2">Priority:</span>
                    <div class="btn-group flex-wrap" role="group" aria-label="Roadmap priority filters">
                        <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_priority, '') ?>" href="<?= roadmapUrl(['priority' => '']) ?>">Any</a>
                        <?php foreach ($roadmap_priorities as $priority) { ?>
                            <a class="btn btn-sm btn-outline-<?= $priority_badges[$priority] ?> <?= roadmapActiveClass($filter_priority, $priority) ?>" href="<?= roadmapUrl(['priority' => $priority]) ?>"><?= $priority ?></a>
                        <?php } ?>
                    </div>
                </div>

                <div class="mt-2">
                    <span class="text-muted mr-2">Impact:</span>
                    <div class="btn-group flex-wrap" role="group" aria-label="Roadmap impact filters">
                        <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_impact, '') ?>" href="<?= roadmapUrl(['impact' => '']) ?>">Any</a>
                        <?php foreach ($roadmap_impacts as $impact) { ?>
                            <a class="btn btn-sm btn-outline-<?= $impact_badges[$impact] ?> <?= roadmapActiveClass($filter_impact, $impact) ?>" href="<?= roadmapUrl(['impact' => $impact]) ?>"><?= $impact ?></a>
                        <?php } ?>
                    </div>
                </div>

                <div class="mt-2">
                    <span class="text-muted mr-2">Effort:</span>
                    <div class="btn-group flex-wrap" role="group" aria-label="Roadmap effort filters">
                        <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_effort, '') ?>" href="<?= roadmapUrl(['effort' => '']) ?>">Any</a>
                        <?php foreach ($roadmap_efforts as $effort) { ?>
                            <a class="btn btn-sm btn-outline-<?= $effort_badges[$effort] ?> <?= roadmapActiveClass($filter_effort, $effort) ?>" href="<?= roadmapUrl(['effort' => $effort]) ?>"><?= $effort ?></a>
                        <?php } ?>
                    </div>
                </div>

                <div class="mt-2">
                    <span class="text-muted mr-2">Complexity:</span>
                    <div class="btn-group flex-wrap" role="group" aria-label="Roadmap complexity filters">
                        <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_complexity, '') ?>" href="<?= roadmapUrl(['complexity' => '']) ?>">Any</a>
                        <?php foreach ($roadmap_complexities as $complexity) { ?>
                            <a class="btn btn-sm btn-outline-<?= $complexity_badges[$complexity] ?> <?= roadmapActiveClass($filter_complexity, $complexity) ?>" href="<?= roadmapUrl(['complexity' => $complexity]) ?>"><?= $complexity ?></a>
                        <?php } ?>
                    </div>
                </div>

                <div class="mt-2">
                    <a class="btn btn-sm btn-outline-warning <?= $filter_pinned ? 'active' : '' ?>" href="<?= roadmapUrl(['pinned' => $filter_pinned ? '' : 1]) ?>">
                        <i class="fas fa-thumbtack mr-1"></i>Pinned
                    </a>

                    <a class="btn btn-sm btn-outline-secondary ml-1 <?= $archived ? 'active' : '' ?>" href="<?= roadmapUrl(['archived' => $archived ? '' : 1]) ?>">
                        <i class="fas fa-archive mr-1"></i>Archived
                    </a>
                </div>
            </div>

            <div class="col-md-4">
                <form method="get">
                    <?php foreach ($_GET as $key => $value) {
                        if ($key === 'q' || $key === 'owner_id') {
                            continue;
                        }
                        ?>
                        <input type="hidden" name="<?= nullable_htmlentities($key) ?>" value="<?= nullable_htmlentities($value) ?>">
                    <?php } ?>

                    <div class="form-group mb-2">
                        <label class="small text-muted mb-1">Owner</label>
                        <select class="form-control form-control-sm select2" name="owner_id" onchange="this.form.submit()">
                            <option value="0">Any Owner</option>
                            <?php while ($owner = mysqli_fetch_assoc($sql_owner_filter_users)) { ?>
                                <option value="<?= intval($owner['user_id']) ?>" <?php if ($filter_owner_id == intval($owner['user_id'])) { echo 'selected'; } ?>>
                                    <?= nullable_htmlentities($owner['user_name']) ?>
                                </option>
                            <?php } ?>
                        </select>
                    </div>

                    <label class="small text-muted mb-1">Search</label>
                    <div class="input-group">
                        <input type="search" name="q" class="form-control" value="<?= nullable_htmlentities($q) ?>" placeholder="Search roadmap">
                        <div class="input-group-append">
                            <button class="btn btn-dark"><i class="fas fa-search"></i></button>
                            <?php if ($q || $filter_status || $filter_category || $filter_priority || $filter_effort || $filter_impact || $filter_complexity || $filter_owner_id || $filter_pinned || $archived) { ?>
                                <a class="btn btn-outline-secondary" href="roadmap.php">Clear</a>
                            <?php } ?>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <div class="card-body">
        <div class="row">
            <?php while ($row = mysqli_fetch_assoc($sql_roadmap_items)) {
                $roadmap_item_id = intval($row['roadmap_item_id']);
                $title = nullable_htmlentities($row['roadmap_item_title']);
                $description = nullable_htmlentities($row['roadmap_item_description']);
                $category = nullable_htmlentities($row['roadmap_item_category']);
                $status = nullable_htmlentities($row['roadmap_item_status']);
                $priority = nullable_htmlentities($row['roadmap_item_priority']);
                $target_version = nullable_htmlentities($row['roadmap_item_target_version']);
                $notes = nullable_htmlentities($row['roadmap_item_notes']);
                $created_at = nullable_htmlentities($row['roadmap_item_created_at']);
                $updated_at = nullable_htmlentities($row['roadmap_item_updated_at']);
                $owner_name = nullable_htmlentities($row['owner_name'] ?: 'Unassigned');
                $creator_name = nullable_htmlentities($row['creator_name']);
                $archived_at = nullable_htmlentities($row['roadmap_item_archived_at']);

                $effort = nullable_htmlentities($row['roadmap_item_effort'] ?? 'Medium');
                $impact = nullable_htmlentities($row['roadmap_item_impact'] ?? 'Medium');
                $complexity = nullable_htmlentities($row['roadmap_item_complexity'] ?? 'Medium');
                $sort_order = intval($row['roadmap_item_sort_order'] ?? 0);
                $pinned = intval($row['roadmap_item_pinned'] ?? 0);
                $dependencies = nullable_htmlentities($row['roadmap_item_dependencies'] ?? '');

                $status_badge = $status_badges[$row['roadmap_item_status']] ?? 'secondary';
                $priority_badge = $priority_badges[$row['roadmap_item_priority']] ?? 'secondary';
                $effort_badge = $effort_badges[$row['roadmap_item_effort'] ?? 'Medium'] ?? 'secondary';
                $impact_badge = $impact_badges[$row['roadmap_item_impact'] ?? 'Medium'] ?? 'secondary';
                $complexity_badge = $complexity_badges[$row['roadmap_item_complexity'] ?? 'Medium'] ?? 'secondary';
                ?>
                <div class="col-xl-4 col-lg-6 col-md-12 d-flex align-items-stretch">
                    <div class="card w-100 <?= $pinned ? 'border-warning' : '' ?>">
                        <div class="card-header py-2">
                            <div class="d-flex justify-content-between align-items-start">
                                <h5 class="card-title mb-0">
                                    <?php if ($pinned) { ?>
                                        <i class="fas fa-thumbtack text-warning mr-1" title="Pinned"></i>
                                    <?php } ?>
                                    <?= $title ?>
                                </h5>

                                <?php if (lookupUserPermission("module_config") >= 2) { ?>
                                    <div class="btn-group mr-1 itflow-roadmap-quick-pin">
                                        <?php if ($pinned) { ?>
                                            <a class="btn btn-sm btn-warning confirm-link" href="post.php?unpin_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>" title="Unpin roadmap item">
                                                <i class="fas fa-thumbtack"></i>
                                                <span class="sr-only">Unpin roadmap item</span>
                                            </a>
                                        <?php } else { ?>
                                            <a class="btn btn-sm btn-light confirm-link" href="post.php?pin_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>" title="Pin roadmap item">
                                                <i class="fas fa-thumbtack"></i>
                                                <span class="sr-only">Pin roadmap item</span>
                                            </a>
                                        <?php } ?>
                                    </div>

                                    <div class="btn-group itflow-roadmap-card-actions">
                                        <button type="button"
                                            class="btn btn-sm btn-light dropdown-toggle itflow-roadmap-action-toggle"
                                            data-toggle="dropdown"
                                            data-boundary="viewport"
                                            aria-haspopup="true"
                                            aria-expanded="false"
                                            title="Roadmap item actions">
                                            <i class="fas fa-ellipsis-v"></i>
                                            <span class="sr-only">Roadmap item actions</span>
                                        </button>
                                        <div class="dropdown-menu dropdown-menu-right">
                                            <a class="dropdown-item ajax-modal itflow-roadmap-edit-action" href="#" data-modal-url="modals/roadmap_edit.php?id=<?= $roadmap_item_id ?>" data-modal-size="lg">
                                                <i class="fas fa-edit fa-fw mr-2"></i>Edit
                                            </a>
                                            <?php if (!$archived_at) { ?>
                                                <a class="dropdown-item text-danger confirm-link" href="post.php?archive_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                    <i class="fas fa-archive fa-fw mr-2"></i>Archive
                                                </a>
                                            <?php } else { ?>
                                                <a class="dropdown-item confirm-link" href="post.php?restore_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                    <i class="fas fa-undo fa-fw mr-2"></i>Restore
                                                </a>
                                                <?php if (lookupUserPermission("module_config") >= 3) { ?>
                                                    <div class="dropdown-divider"></div>
                                                    <a class="dropdown-item text-danger text-bold confirm-link" href="post.php?delete_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                        <i class="fas fa-trash fa-fw mr-2"></i>Delete Permanently
                                                    </a>
                                                <?php } ?>
                                            <?php } ?>
                                        </div>
                                    </div>
                                <?php } ?>
                            </div>
                        </div>

                        <div class="card-body">
                            <div class="mb-3">
                                <span class="badge badge-<?= $status_badge ?> mr-1"><?= $status ?></span>
                                <span class="badge badge-<?= $priority_badge ?> mr-1">Priority: <?= $priority ?></span>
                                <span class="badge badge-secondary"><?= $category ?></span>
                            </div>

                            <div class="mb-3">
                                <span class="badge badge-<?= $impact_badge ?> mr-1">Impact: <?= $impact ?></span>
                                <span class="badge badge-<?= $effort_badge ?> mr-1">Effort: <?= $effort ?></span>
                                <span class="badge badge-<?= $complexity_badge ?>">Complexity: <?= $complexity ?></span>
                            </div>

                            <?php if ($description) { ?>
                                <p><?= nl2br($description) ?></p>
                            <?php } else { ?>
                                <p class="text-muted">No description yet.</p>
                            <?php } ?>

                            <?php if ($dependencies) { ?>
                                <div class="alert alert-light border py-2">
                                    <div class="text-muted text-uppercase small mb-1">
                                        <i class="fas fa-project-diagram mr-1"></i>Dependencies / Blockers
                                    </div>
                                    <?= nl2br($dependencies) ?>
                                </div>
                            <?php } ?>

                            <?php if ($notes) { ?>
                                <div class="alert alert-light border py-2">
                                    <div class="text-muted text-uppercase small mb-1">
                                        <i class="fas fa-sticky-note mr-1"></i>Internal Notes
                                    </div>
                                    <?= nl2br($notes) ?>
                                </div>
                            <?php } ?>

                            <dl class="row small text-muted mb-0">
                                <dt class="col-5">Owner</dt>
                                <dd class="col-7"><?= $owner_name ?></dd>

                                <?php if ($target_version) { ?>
                                    <dt class="col-5">Target</dt>
                                    <dd class="col-7"><?= $target_version ?></dd>
                                <?php } ?>

                                <?php if ($sort_order) { ?>
                                    <dt class="col-5">Sort Order</dt>
                                    <dd class="col-7"><?= $sort_order ?></dd>
                                <?php } ?>

                                <dt class="col-5">Created</dt>
                                <dd class="col-7"><?= $created_at ?><?= $creator_name ? " by $creator_name" : "" ?></dd>

                                <?php if ($updated_at) { ?>
                                    <dt class="col-5">Updated</dt>
                                    <dd class="col-7"><?= $updated_at ?></dd>
                                <?php } ?>

                                <?php if ($archived_at) { ?>
                                    <dt class="col-5">Archived</dt>
                                    <dd class="col-7"><?= $archived_at ?></dd>
                                <?php } ?>
                            </dl>
                        </div>
                    </div>
                </div>
            <?php } ?>

            <?php if (mysqli_num_rows($sql_roadmap_items) == 0) { ?>
                <div class="col-12">
                    <div class="alert alert-info mb-0">
                        <i class="fas fa-info-circle mr-2"></i>No roadmap items match the current filters.
                    </div>
                </div>
            <?php } ?>
        </div>
    </div>
</div>

<!-- ITFLOW_ROADMAP_DROPDOWN_FIX_FALLBACK -->

<style>
    .itflow-roadmap-quick-pin .btn,
    .itflow-roadmap-card-actions .btn {
        min-width: 32px;
    }

    .itflow-roadmap-card-actions .dropdown-menu {
        z-index: 2050;
    }

    .itflow-roadmap-action-toggle::after {
        display: none;
    }
</style>

<script>
document.addEventListener('DOMContentLoaded', function () {
    document.addEventListener('click', function (event) {
        var toggle = event.target.closest('.itflow-roadmap-action-toggle');

        if (!toggle) {
            document.querySelectorAll('.itflow-roadmap-card-actions .dropdown-menu.show').forEach(function (menu) {
                menu.classList.remove('show');
            });

            document.querySelectorAll('.itflow-roadmap-action-toggle[aria-expanded="true"]').forEach(function (button) {
                button.setAttribute('aria-expanded', 'false');
            });

            return;
        }

        var actions = toggle.closest('.itflow-roadmap-card-actions');
        var menu = actions ? actions.querySelector('.dropdown-menu') : null;

        if (!menu || (window.jQuery && typeof window.jQuery.fn.dropdown === 'function')) {
            return;
        }

        event.preventDefault();
        event.stopPropagation();

        document.querySelectorAll('.itflow-roadmap-card-actions .dropdown-menu.show').forEach(function (openMenu) {
            if (openMenu !== menu) {
                openMenu.classList.remove('show');
            }
        });

        var shouldOpen = !menu.classList.contains('show');
        menu.classList.toggle('show', shouldOpen);
        toggle.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
    }, true);
});
</script>



<!-- ITFLOW_ROADMAP_EDIT_MODAL_FALLBACK -->
<script>
document.addEventListener('DOMContentLoaded', function () {
    document.addEventListener('click', function (event) {
        var editLink = event.target.closest('.itflow-roadmap-edit-action');

        if (!editLink) {
            return;
        }

        var modalUrl = editLink.getAttribute('data-modal-url');

        if (!modalUrl) {
            return;
        }

        event.preventDefault();
        event.stopPropagation();

        if (!window.jQuery) {
            return;
        }

        window.jQuery.get(modalUrl, function (html) {
            var container = window.jQuery('#itflowRoadmapModalFallbackContainer');

            if (!container.length) {
                container = window.jQuery('<div id="itflowRoadmapModalFallbackContainer"></div>').appendTo('body');
            }

            container.html(html);

            var modal = container.find('.modal').first();

            if (modal.length) {
                modal.modal('show');
            }
        }).fail(function (xhr) {
            alert('Unable to load roadmap edit modal. HTTP ' + xhr.status);
        });
    }, true);
});
</script>

<!-- ITFLOW_ROADMAP_ADD_MODAL_FALLBACK -->
<div id="itflowRoadmapAddModalFallbackContainer"></div>
<script>
(function() {
    function closeRoadmapFallbackModal(modalEl) {
        if (!modalEl) {
            return;
        }

        modalEl.classList.remove('show');
        modalEl.style.display = 'none';
        modalEl.setAttribute('aria-hidden', 'true');
        modalEl.removeAttribute('aria-modal');

        document.body.classList.remove('modal-open');
        document.body.style.removeProperty('padding-right');

        var backdrops = document.querySelectorAll('.itflow-roadmap-manual-backdrop');
        for (var i = 0; i < backdrops.length; i++) {
            backdrops[i].parentNode.removeChild(backdrops[i]);
        }
    }

    function showRoadmapFallbackModal(container) {
        var modalEl = container.querySelector('.modal');

        if (!modalEl) {
            alert('Roadmap add modal loaded, but no modal markup was found.');
            return;
        }

        if (window.jQuery && typeof window.jQuery.fn.modal === 'function') {
            window.jQuery(modalEl).modal('show');
            return;
        }

        if (window.bootstrap && typeof window.bootstrap.Modal === 'function') {
            var nativeModal = new window.bootstrap.Modal(modalEl);
            nativeModal.show();
            return;
        }

        modalEl.style.display = 'block';
        modalEl.classList.add('show');
        modalEl.removeAttribute('aria-hidden');
        modalEl.setAttribute('aria-modal', 'true');

        document.body.classList.add('modal-open');

        var backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop fade show itflow-roadmap-manual-backdrop';
        document.body.appendChild(backdrop);

        var closeButtons = modalEl.querySelectorAll('[data-dismiss="modal"], [data-bs-dismiss="modal"], .close');
        for (var i = 0; i < closeButtons.length; i++) {
            closeButtons[i].addEventListener('click', function(event) {
                event.preventDefault();
                closeRoadmapFallbackModal(modalEl);
            });
        }

        backdrop.addEventListener('click', function() {
            closeRoadmapFallbackModal(modalEl);
        });

        document.addEventListener('keydown', function escHandler(event) {
            if (event.key === 'Escape') {
                closeRoadmapFallbackModal(modalEl);
                document.removeEventListener('keydown', escHandler);
            }
        });
    }

    document.addEventListener('click', function(event) {
        var trigger = event.target.closest('.itflow-roadmap-add-action');

        if (!trigger) {
            return;
        }

        var modalUrl = trigger.getAttribute('data-modal-url');

        if (!modalUrl || typeof jQuery === 'undefined') {
            return;
        }

        event.preventDefault();
        event.stopPropagation();

        jQuery.get(modalUrl)
            .done(function(html) {
                var container = document.getElementById('itflowRoadmapAddModalFallbackContainer');

                if (!container) {
                    container = document.createElement('div');
                    container.id = 'itflowRoadmapAddModalFallbackContainer';
                    document.body.appendChild(container);
                }

                container.innerHTML = html;
                showRoadmapFallbackModal(container);
            })
            .fail(function(xhr) {
                alert('Unable to load roadmap add modal. HTTP ' + xhr.status);
            });
    }, true);
})();
</script>
<!-- /ITFLOW_ROADMAP_ADD_MODAL_FALLBACK -->


<?php require_once "includes/footer.php"; ?>
