<?php
// ITFLOW_PLATFORM_ROADMAP_PHASE3B
// ITFLOW_ROADMAP_PHASE3E_PLANNING_FIELDS

$itflow_agent_root = dirname(__DIR__, 2);
$itflow_modal_bootstrap = $itflow_agent_root . "/includes/inc_all_modal.php";

if (!is_dir($itflow_agent_root) || !is_file($itflow_modal_bootstrap)) {
    http_response_code(500);
    exit("Unable to load ITFlow modal bootstrap");
}

chdir($itflow_agent_root);

require_once $itflow_modal_bootstrap;

enforceUserPermission('module_config', 2);

$roadmap_item_id = intval($_GET['id']);

$sql = mysqli_query($mysqli, "SELECT * FROM roadmap_items WHERE roadmap_item_id = $roadmap_item_id LIMIT 1");

if (!$sql || mysqli_num_rows($sql) == 0) {
    exit("Roadmap item not found");
}

$row = mysqli_fetch_assoc($sql);

$title = nullable_htmlentities($row['roadmap_item_title']);
$description = nullable_htmlentities($row['roadmap_item_description']);
$category_current = nullable_htmlentities($row['roadmap_item_category']);
$status_current = nullable_htmlentities($row['roadmap_item_status']);
$priority_current = nullable_htmlentities($row['roadmap_item_priority']);
$target_version = nullable_htmlentities($row['roadmap_item_target_version']);
$notes = nullable_htmlentities($row['roadmap_item_notes']);

$owner_id_current = intval($row['roadmap_item_owner_id'] ?? 0);
$effort_current = nullable_htmlentities($row['roadmap_item_effort'] ?? 'Medium');
$impact_current = nullable_htmlentities($row['roadmap_item_impact'] ?? 'Medium');
$complexity_current = nullable_htmlentities($row['roadmap_item_complexity'] ?? 'Medium');
$sort_order_current = intval($row['roadmap_item_sort_order'] ?? 0);
$pinned_current = intval($row['roadmap_item_pinned'] ?? 0);
$dependencies = nullable_htmlentities($row['roadmap_item_dependencies'] ?? '');

$roadmap_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
$roadmap_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
$roadmap_priorities = ['Low', 'Medium', 'High', 'Critical'];
$roadmap_efforts = ['Tiny', 'Small', 'Medium', 'Large', 'XL'];
$roadmap_impacts = ['Low', 'Medium', 'High', 'Critical'];
$roadmap_complexities = ['Low', 'Medium', 'High', 'Very High'];

$sql_users = mysqli_query($mysqli, "SELECT user_id, user_name FROM users ORDER BY user_name ASC");
?>

<div class="modal" id="editRoadmapItemModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-light">
            <form action="post.php" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                <input type="hidden" name="roadmap_item_id" value="<?= $roadmap_item_id ?>">

                <div class="modal-header bg-dark">
                    <h5 class="modal-title"><i class="fas fa-map-signs mr-2"></i>Edit Roadmap Item</h5>
                    <button type="button" class="close text-white" data-dismiss="modal">
                        <span>&times;</span>
                    </button>
                </div>

                <div class="modal-body">

                    <div class="form-group">
                        <label>Title <strong class="text-danger">*</strong></label>
                        <input type="text" class="form-control" name="roadmap_item_title" maxlength="255" value="<?= $title ?>" required autofocus>
                    </div>

                    <div class="form-group">
                        <label>Description</label>
                        <textarea class="form-control" name="roadmap_item_description" rows="4"><?= $description ?></textarea>
                    </div>

                    <div class="form-row">
                        <div class="form-group col-md-4">
                            <label>Category</label>
                            <select class="form-control select2" name="roadmap_item_category">
                                <?php foreach ($roadmap_categories as $category) { ?>
                                    <option value="<?= nullable_htmlentities($category) ?>" <?php if ($category_current == $category) { echo 'selected'; } ?>><?= nullable_htmlentities($category) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Status</label>
                            <select class="form-control select2" name="roadmap_item_status">
                                <?php foreach ($roadmap_statuses as $status) { ?>
                                    <option value="<?= nullable_htmlentities($status) ?>" <?php if ($status_current == $status) { echo 'selected'; } ?>><?= nullable_htmlentities($status) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Priority</label>
                            <select class="form-control select2" name="roadmap_item_priority">
                                <?php foreach ($roadmap_priorities as $priority) { ?>
                                    <option value="<?= nullable_htmlentities($priority) ?>" <?php if ($priority_current == $priority) { echo 'selected'; } ?>><?= nullable_htmlentities($priority) ?></option>
                                <?php } ?>
                            </select>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group col-md-4">
                            <label>Owner</label>
                            <select class="form-control select2" name="roadmap_item_owner_id">
                                <option value="0">Unassigned</option>
                                <?php while ($user = mysqli_fetch_assoc($sql_users)) { ?>
                                    <option value="<?= intval($user['user_id']) ?>" <?php if ($owner_id_current == intval($user['user_id'])) { echo 'selected'; } ?>><?= nullable_htmlentities($user['user_name']) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Target Phase / Release</label>
                            <input type="text" class="form-control" name="roadmap_item_target_version" maxlength="64" value="<?= $target_version ?>">
                        </div>

                        <div class="form-group col-md-4">
                            <label>Sort Order</label>
                            <input type="number" class="form-control" name="roadmap_item_sort_order" value="<?= $sort_order_current ?>">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group col-md-4">
                            <label>Effort</label>
                            <select class="form-control select2" name="roadmap_item_effort">
                                <?php foreach ($roadmap_efforts as $effort) { ?>
                                    <option value="<?= nullable_htmlentities($effort) ?>" <?php if ($effort_current == $effort) { echo 'selected'; } ?>><?= nullable_htmlentities($effort) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Impact</label>
                            <select class="form-control select2" name="roadmap_item_impact">
                                <?php foreach ($roadmap_impacts as $impact) { ?>
                                    <option value="<?= nullable_htmlentities($impact) ?>" <?php if ($impact_current == $impact) { echo 'selected'; } ?>><?= nullable_htmlentities($impact) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Complexity</label>
                            <select class="form-control select2" name="roadmap_item_complexity">
                                <?php foreach ($roadmap_complexities as $complexity) { ?>
                                    <option value="<?= nullable_htmlentities($complexity) ?>" <?php if ($complexity_current == $complexity) { echo 'selected'; } ?>><?= nullable_htmlentities($complexity) ?></option>
                                <?php } ?>
                            </select>
                        </div>
                    </div>

                    <div class="custom-control custom-switch mb-3">
                        <input type="checkbox" class="custom-control-input" id="roadmapItemPinnedEdit" name="roadmap_item_pinned" value="1" <?php if ($pinned_current) { echo 'checked'; } ?>>
                        <label class="custom-control-label" for="roadmapItemPinnedEdit">Pin / feature this roadmap item</label>
                    </div>

                    <div class="form-group">
                        <label>Dependencies / Blockers</label>
                        <textarea class="form-control" name="roadmap_item_dependencies" rows="3"><?= $dependencies ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Internal Notes</label>
                        <textarea class="form-control" name="roadmap_item_notes" rows="3"><?= $notes ?></textarea>
                    </div>

                </div>

                <div class="modal-footer">
                    <button type="submit" name="edit_roadmap_item" class="btn btn-primary">
                        <i class="fas fa-save mr-2"></i>Save
                    </button>
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>
