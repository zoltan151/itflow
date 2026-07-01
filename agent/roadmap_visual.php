
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
                    <button type="button" class="btn btn-primary itflow-roadmap-add-action" data-toggle="modal" data-target="#addRoadmapItemModal" data-bs-toggle="modal" data-bs-target="#addRoadmapItemModal">
                        <i class="fas fa-fw fa-plus mr-1"></i> Add Roadmap Item
                    </button>
                <?php } ?>
                <!-- /ITFLOW_ROADMAP_ADD_ACTION -->
            </div>
        </div>
    </div>
    <!-- /ITFLOW_ROADMAP_ACTION_ROW -->

<?php if (!$has_roadmap) { ?>
    <div class="alert alert-warning">Roadmap table is not available yet.</div>
<?php } ?>

<div class="card-body border-bottom">
<div class="row">
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">Active Initiatives</div><h2><?= intval($summary['active']) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">In Development</div><h2><?= intval($summary['dev']) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">High Priority</div><h2><?= intval($summary['high']) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-vops-card"><div class="text-muted">Shipped / Complete</div><h2><?= intval($summary['shipped']) ?></h2></div></div>
</div>

</div>
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

<!-- ITFLOW_ROADMAP_ADD_INLINE_MODAL -->
<?php if (lookupUserPermission("module_config") >= 2) { ?>
    <?php
    $roadmap_add_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
    $roadmap_add_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
    $roadmap_add_priorities = ['Low', 'Medium', 'High', 'Critical'];
    $roadmap_add_efforts = ['Tiny', 'Small', 'Medium', 'Large', 'XL'];
    $roadmap_add_impacts = ['Low', 'Medium', 'High', 'Critical'];
    $roadmap_add_complexities = ['Low', 'Medium', 'High', 'Very High'];
    $sql_roadmap_add_users = mysqli_query($mysqli, "SELECT user_id, user_name FROM users ORDER BY user_name ASC");
    ?>

    <div class="modal fade" id="addRoadmapItemModal" tabindex="-1" role="dialog" aria-labelledby="addRoadmapItemModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg" role="document">
            <div class="modal-content bg-light">
                <form action="post.php" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

                    <div class="modal-header bg-dark">
                        <h5 class="modal-title text-white" id="addRoadmapItemModalLabel">
                            <i class="fas fa-map-signs mr-2"></i>Add Roadmap Item
                        </h5>
                        <button type="button" class="close text-white itflow-roadmap-add-modal-close" data-dismiss="modal" data-bs-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                    </div>

                    <div class="modal-body">

                        <div class="form-group">
                            <label>Title <strong class="text-danger">*</strong></label>
                            <input type="text" class="form-control" name="roadmap_item_title" maxlength="255" required>
                        </div>

                        <div class="form-group">
                            <label>Description</label>
                            <textarea class="form-control" name="roadmap_item_description" rows="4"></textarea>
                        </div>

                        <div class="form-row">
                            <div class="form-group col-md-4">
                                <label>Category</label>
                                <select class="form-control select2" name="roadmap_item_category">
                                    <?php foreach ($roadmap_add_categories as $category) { ?>
                                        <option value="<?= nullable_htmlentities($category) ?>"><?= nullable_htmlentities($category) ?></option>
                                    <?php } ?>
                                </select>
                            </div>

                            <div class="form-group col-md-4">
                                <label>Status</label>
                                <select class="form-control select2" name="roadmap_item_status">
                                    <?php foreach ($roadmap_add_statuses as $status) { ?>
                                        <option value="<?= nullable_htmlentities($status) ?>"><?= nullable_htmlentities($status) ?></option>
                                    <?php } ?>
                                </select>
                            </div>

                            <div class="form-group col-md-4">
                                <label>Priority</label>
                                <select class="form-control select2" name="roadmap_item_priority">
                                    <?php foreach ($roadmap_add_priorities as $priority) { ?>
                                        <option value="<?= nullable_htmlentities($priority) ?>" <?php if ($priority == 'Medium') { echo 'selected'; } ?>><?= nullable_htmlentities($priority) ?></option>
                                    <?php } ?>
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group col-md-4">
                                <label>Owner</label>
                                <select class="form-control select2" name="roadmap_item_owner_id">
                                    <option value="0">Unassigned</option>
                                    <?php if ($sql_roadmap_add_users) { ?>
                                        <?php while ($user = mysqli_fetch_assoc($sql_roadmap_add_users)) { ?>
                                            <option value="<?= intval($user['user_id']) ?>"><?= nullable_htmlentities($user['user_name']) ?></option>
                                        <?php } ?>
                                    <?php } ?>
                                </select>
                            </div>

                            <div class="form-group col-md-4">
                                <label>Target Phase / Release</label>
                                <input type="text" class="form-control" name="roadmap_item_target_version" maxlength="64" placeholder="Optional, e.g. Phase 4, v2.5, Q3">
                            </div>

                            <div class="form-group col-md-4">
                                <label>Sort Order</label>
                                <input type="number" class="form-control" name="roadmap_item_sort_order" value="0">
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="form-group col-md-4">
                                <label>Effort</label>
                                <select class="form-control select2" name="roadmap_item_effort">
                                    <?php foreach ($roadmap_add_efforts as $effort) { ?>
                                        <option value="<?= nullable_htmlentities($effort) ?>" <?php if ($effort == 'Medium') { echo 'selected'; } ?>><?= nullable_htmlentities($effort) ?></option>
                                    <?php } ?>
                                </select>
                            </div>

                            <div class="form-group col-md-4">
                                <label>Impact</label>
                                <select class="form-control select2" name="roadmap_item_impact">
                                    <?php foreach ($roadmap_add_impacts as $impact) { ?>
                                        <option value="<?= nullable_htmlentities($impact) ?>" <?php if ($impact == 'Medium') { echo 'selected'; } ?>><?= nullable_htmlentities($impact) ?></option>
                                    <?php } ?>
                                </select>
                            </div>

                            <div class="form-group col-md-4">
                                <label>Complexity</label>
                                <select class="form-control select2" name="roadmap_item_complexity">
                                    <?php foreach ($roadmap_add_complexities as $complexity) { ?>
                                        <option value="<?= nullable_htmlentities($complexity) ?>" <?php if ($complexity == 'Medium') { echo 'selected'; } ?>><?= nullable_htmlentities($complexity) ?></option>
                                    <?php } ?>
                                </select>
                            </div>
                        </div>

                        <div class="custom-control custom-switch mb-3">
                            <input type="checkbox" class="custom-control-input" id="roadmapItemPinnedAdd" name="roadmap_item_pinned" value="1">
                            <label class="custom-control-label" for="roadmapItemPinnedAdd">Pin / feature this roadmap item</label>
                        </div>

                        <div class="form-group">
                            <label>Dependencies / Blockers</label>
                            <textarea class="form-control" name="roadmap_item_dependencies" rows="3" placeholder="Optional dependencies, blockers, related phases, or required prerequisites"></textarea>
                        </div>

                        <div class="form-group">
                            <label>Internal Notes</label>
                            <textarea class="form-control" name="roadmap_item_notes" rows="3"></textarea>
                        </div>

                    </div>

                    <div class="modal-footer">
                        <button type="submit" name="add_roadmap_item" class="btn btn-primary">
                            <i class="fas fa-check mr-2"></i>Create
                        </button>
                        <button type="button" class="btn btn-secondary itflow-roadmap-add-modal-close" data-dismiss="modal" data-bs-dismiss="modal">
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
<?php } ?>
<!-- /ITFLOW_ROADMAP_ADD_INLINE_MODAL -->

<!-- ITFLOW_ROADMAP_ADD_INLINE_MODAL_SCRIPT -->
<script>
(function() {
    function closeInlineRoadmapAddModal(modalEl) {
        if (!modalEl) {
            return;
        }

        modalEl.classList.remove('show');
        modalEl.style.display = 'none';
        modalEl.setAttribute('aria-hidden', 'true');
        modalEl.removeAttribute('aria-modal');

        document.body.classList.remove('modal-open');
        document.body.style.removeProperty('padding-right');

        var backdrops = document.querySelectorAll('.itflow-roadmap-add-inline-backdrop');
        for (var i = 0; i < backdrops.length; i++) {
            backdrops[i].parentNode.removeChild(backdrops[i]);
        }
    }

    function showInlineRoadmapAddModal() {
        var modalEl = document.getElementById('addRoadmapItemModal');

        if (!modalEl) {
            alert('Add Roadmap Item modal is missing from this page.');
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
        backdrop.className = 'modal-backdrop fade show itflow-roadmap-add-inline-backdrop';
        document.body.appendChild(backdrop);

        var firstInput = modalEl.querySelector('input[name="roadmap_item_title"]');
        if (firstInput) {
            setTimeout(function() {
                firstInput.focus();
            }, 50);
        }

        var closeButtons = modalEl.querySelectorAll('.itflow-roadmap-add-modal-close, [data-dismiss="modal"], [data-bs-dismiss="modal"], .close');
        for (var i = 0; i < closeButtons.length; i++) {
            closeButtons[i].addEventListener('click', function(event) {
                event.preventDefault();
                closeInlineRoadmapAddModal(modalEl);
            });
        }

        backdrop.addEventListener('click', function() {
            closeInlineRoadmapAddModal(modalEl);
        });

        document.addEventListener('keydown', function escHandler(event) {
            if (event.key === 'Escape') {
                closeInlineRoadmapAddModal(modalEl);
                document.removeEventListener('keydown', escHandler);
            }
        });
    }

    document.addEventListener('click', function(event) {
        var trigger = event.target.closest('.itflow-roadmap-add-action');

        if (!trigger) {
            return;
        }

        event.preventDefault();
        event.stopPropagation();

        showInlineRoadmapAddModal();
    }, true);
})();
</script>
<!-- /ITFLOW_ROADMAP_ADD_INLINE_MODAL_SCRIPT -->


<?php require_once "includes/footer.php"; ?>
