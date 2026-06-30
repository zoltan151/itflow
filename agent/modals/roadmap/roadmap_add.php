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

$roadmap_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
$roadmap_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
$roadmap_priorities = ['Low', 'Medium', 'High', 'Critical'];
$roadmap_efforts = ['Tiny', 'Small', 'Medium', 'Large', 'XL'];
$roadmap_impacts = ['Low', 'Medium', 'High', 'Critical'];
$roadmap_complexities = ['Low', 'Medium', 'High', 'Very High'];

$sql_users = mysqli_query($mysqli, "SELECT user_id, user_name FROM users ORDER BY user_name ASC");
?>

<div class="modal" id="addRoadmapItemModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content bg-light">
            <form action="post.php" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

                <div class="modal-header bg-dark">
                    <h5 class="modal-title"><i class="fas fa-map-signs mr-2"></i>Add Roadmap Item</h5>
                    <button type="button" class="close text-white" data-dismiss="modal">
                        <span>&times;</span>
                    </button>
                </div>

                <div class="modal-body">

                    <div class="form-group">
                        <label>Title <strong class="text-danger">*</strong></label>
                        <input type="text" class="form-control" name="roadmap_item_title" maxlength="255" required autofocus>
                    </div>

                    <div class="form-group">
                        <label>Description</label>
                        <textarea class="form-control" name="roadmap_item_description" rows="4"></textarea>
                    </div>

                    <div class="form-row">
                        <div class="form-group col-md-4">
                            <label>Category</label>
                            <select class="form-control select2" name="roadmap_item_category">
                                <?php foreach ($roadmap_categories as $category) { ?>
                                    <option value="<?= nullable_htmlentities($category) ?>"><?= nullable_htmlentities($category) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Status</label>
                            <select class="form-control select2" name="roadmap_item_status">
                                <?php foreach ($roadmap_statuses as $status) { ?>
                                    <option value="<?= nullable_htmlentities($status) ?>"><?= nullable_htmlentities($status) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Priority</label>
                            <select class="form-control select2" name="roadmap_item_priority">
                                <?php foreach ($roadmap_priorities as $priority) { ?>
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
                                <?php while ($user = mysqli_fetch_assoc($sql_users)) { ?>
                                    <option value="<?= intval($user['user_id']) ?>"><?= nullable_htmlentities($user['user_name']) ?></option>
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
                                <?php foreach ($roadmap_efforts as $effort) { ?>
                                    <option value="<?= nullable_htmlentities($effort) ?>" <?php if ($effort == 'Medium') { echo 'selected'; } ?>><?= nullable_htmlentities($effort) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Impact</label>
                            <select class="form-control select2" name="roadmap_item_impact">
                                <?php foreach ($roadmap_impacts as $impact) { ?>
                                    <option value="<?= nullable_htmlentities($impact) ?>" <?php if ($impact == 'Medium') { echo 'selected'; } ?>><?= nullable_htmlentities($impact) ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Complexity</label>
                            <select class="form-control select2" name="roadmap_item_complexity">
                                <?php foreach ($roadmap_complexities as $complexity) { ?>
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
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>
