<?php
// ITFLOW_PLATFORM_ROADMAP_PHASE3B

require_once "includes/inc_all.php";

enforceUserPermission('module_config');

$page_title = "Platform Roadmap";

$roadmap_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
$roadmap_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
$roadmap_priorities = ['Low', 'Medium', 'High', 'Critical'];

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

$filter_status = sanitizeInput($_GET['status'] ?? '');
$filter_category = sanitizeInput($_GET['category'] ?? '');
$filter_priority = sanitizeInput($_GET['priority'] ?? '');
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

if ($q) {
    $safe_q = mysqli_real_escape_string($mysqli, $q);
    $where .= " AND (roadmap_item_title LIKE '%$safe_q%' OR roadmap_item_description LIKE '%$safe_q%' OR roadmap_item_notes LIKE '%$safe_q%')";
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

$sql_roadmap_items = mysqli_query(
    $mysqli,
    "SELECT roadmap_items.*, users.user_name
     FROM roadmap_items
     LEFT JOIN users ON roadmap_item_created_by = user_id
     $where
     ORDER BY
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
        roadmap_item_updated_at DESC,
        roadmap_item_created_at DESC"
);

?>

<div class="card card-dark">
    <div class="card-header py-2">
        <h3 class="card-title mt-2">
            <i class="fas fa-fw fa-map-signs mr-2"></i>Platform Roadmap
        </h3>

        <div class="card-tools">
            <?php if (lookupUserPermission("module_config") >= 2) { ?>
                <button type="button" class="btn btn-primary ajax-modal" data-modal-url="modals/roadmap/roadmap_add.php" data-modal-size="lg">
                    <i class="fas fa-fw fa-plus mr-2"></i>Add Roadmap Item
                </button>
            <?php } ?>
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
                    <div class="btn-group" role="group" aria-label="Roadmap priority filters">
                        <a class="btn btn-sm btn-outline-secondary <?= roadmapActiveClass($filter_priority, '') ?>" href="<?= roadmapUrl(['priority' => '']) ?>">Any</a>
                        <?php foreach ($roadmap_priorities as $priority) { ?>
                            <a class="btn btn-sm btn-outline-<?= $priority_badges[$priority] ?> <?= roadmapActiveClass($filter_priority, $priority) ?>" href="<?= roadmapUrl(['priority' => $priority]) ?>"><?= $priority ?></a>
                        <?php } ?>
                    </div>

                    <a class="btn btn-sm btn-outline-secondary ml-2 <?= $archived ? 'active' : '' ?>" href="<?= roadmapUrl(['archived' => $archived ? '' : 1]) ?>">
                        <i class="fas fa-archive mr-1"></i>Archived
                    </a>
                </div>
            </div>

            <div class="col-md-4">
                <form method="get">
                    <?php foreach ($_GET as $key => $value) {
                        if ($key === 'q') {
                            continue;
                        }
                        ?>
                        <input type="hidden" name="<?= nullable_htmlentities($key) ?>" value="<?= nullable_htmlentities($value) ?>">
                    <?php } ?>
                    <div class="input-group">
                        <input type="search" name="q" class="form-control" value="<?= nullable_htmlentities($q) ?>" placeholder="Search roadmap">
                        <div class="input-group-append">
                            <button class="btn btn-dark"><i class="fas fa-search"></i></button>
                            <?php if ($q || $filter_status || $filter_category || $filter_priority || $archived) { ?>
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
                $created_by = nullable_htmlentities($row['user_name']);
                $archived_at = nullable_htmlentities($row['roadmap_item_archived_at']);
                ?>
                <div class="col-lg-6 col-xl-4">
                    <div class="card h-100 <?= $archived_at ? 'border-secondary' : '' ?>">
                        <div class="card-header">
                            <div class="d-flex justify-content-between">
                                <div>
                                    <h5 class="mb-1"><?= $title ?></h5>
                                    <div>
                                        <span class="badge badge-<?= $status_badges[$status] ?? 'secondary' ?> mr-1"><?= $status ?></span>
                                        <span class="badge badge-<?= $priority_badges[$priority] ?? 'secondary' ?> mr-1"><?= $priority ?></span>
                                        <span class="badge badge-light"><?= $category ?></span>
                                    </div>
                                </div>
                                <?php if (lookupUserPermission("module_config") >= 2) { ?>
                                    <div class="dropdown dropleft">
                                        <button class="btn btn-sm btn-outline-secondary" type="button" data-toggle="dropdown">
                                            <i class="fas fa-ellipsis-h"></i>
                                        </button>
                                        <div class="dropdown-menu">
                                            <?php if (!$archived_at) { ?>
                                                <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/roadmap/roadmap_edit.php?id=<?= $roadmap_item_id ?>" data-modal-size="lg">
                                                    <i class="fas fa-fw fa-pencil-alt mr-2"></i>Edit
                                                </a>
                                                <div class="dropdown-divider"></div>
                                                <a class="dropdown-item text-danger confirm-link" href="post.php?archive_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                    <i class="fas fa-fw fa-archive mr-2"></i>Archive
                                                </a>
                                            <?php } else { ?>
                                                <a class="dropdown-item confirm-link" href="post.php?restore_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                    <i class="fas fa-fw fa-trash-restore mr-2"></i>Restore
                                                </a>
                                                <?php if (lookupUserPermission("module_config") >= 3) { ?>
                                                    <div class="dropdown-divider"></div>
                                                    <a class="dropdown-item text-danger text-bold confirm-link" href="post.php?delete_roadmap_item=<?= $roadmap_item_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                                                        <i class="fas fa-fw fa-trash mr-2"></i>Delete
                                                    </a>
                                                <?php } ?>
                                            <?php } ?>
                                        </div>
                                    </div>
                                <?php } ?>
                            </div>
                        </div>
                        <div class="card-body">
                            <?php if ($description) { ?>
                                <p><?= nl2br($description) ?></p>
                            <?php } else { ?>
                                <p class="text-muted">No description yet.</p>
                            <?php } ?>

                            <?php if ($target_version) { ?>
                                <div class="small mb-2">
                                    <strong>Target:</strong> <?= $target_version ?>
                                </div>
                            <?php } ?>

                            <?php if ($notes) { ?>
                                <div class="small text-muted">
                                    <strong>Notes:</strong><br>
                                    <?= nl2br($notes) ?>
                                </div>
                            <?php } ?>
                        </div>
                        <div class="card-footer small text-muted">
                            Created <?= $created_at ?>
                            <?php if ($created_by) { ?>
                                by <?= $created_by ?>
                            <?php } ?>
                            <?php if ($updated_at) { ?>
                                <br>Updated <?= $updated_at ?>
                            <?php } ?>
                            <?php if ($archived_at) { ?>
                                <br><span class="text-danger">Archived <?= $archived_at ?></span>
                            <?php } ?>
                        </div>
                    </div>
                </div>
            <?php } ?>

            <?php if (mysqli_num_rows($sql_roadmap_items) == 0) { ?>
                <div class="col-12">
                    <div class="text-center text-muted p-5">
                        <i class="fas fa-map-signs fa-3x mb-3"></i>
                        <h4>No roadmap items found</h4>
                        <p>Try clearing filters or add a new roadmap item.</p>
                    </div>
                </div>
            <?php } ?>
        </div>
    </div>
</div>

<?php

require_once "includes/footer.php";
