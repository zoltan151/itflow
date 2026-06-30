<?php
// ITFLOW_PLATFORM_ROADMAP_PHASE3B

require_once "../includes/inc_all_modal.php";

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

$roadmap_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
$roadmap_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
$roadmap_priorities = ['Low', 'Medium', 'High', 'Critical'];

?>

<div class="modal" id="editRoadmapItemModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
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
                                    <option value="<?= $category ?>" <?= $category === $category_current ? 'selected' : '' ?>><?= $category ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Status</label>
                            <select class="form-control select2" name="roadmap_item_status">
                                <?php foreach ($roadmap_statuses as $status) { ?>
                                    <option value="<?= $status ?>" <?= $status === $status_current ? 'selected' : '' ?>><?= $status ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Priority</label>
                            <select class="form-control select2" name="roadmap_item_priority">
                                <?php foreach ($roadmap_priorities as $priority) { ?>
                                    <option value="<?= $priority ?>" <?= $priority === $priority_current ? 'selected' : '' ?>><?= $priority ?></option>
                                <?php } ?>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Target Version / Milestone</label>
                        <input type="text" class="form-control" name="roadmap_item_target_version" maxlength="64" value="<?= $target_version ?>">
                    </div>

                    <div class="form-group">
                        <label>Internal Notes</label>
                        <textarea class="form-control" name="roadmap_item_notes" rows="3"><?= $notes ?></textarea>
                    </div>
                </div>

                <div class="modal-footer">
                    <button type="submit" name="edit_roadmap_item" class="btn btn-primary">
                        <i class="fas fa-check mr-2"></i>Save
                    </button>
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                </div>
            </form>
        </div>
    </div>
</div>
