<?php
// ITFLOW_PLATFORM_ROADMAP_PHASE3B

require_once "../includes/inc_all_modal.php";

enforceUserPermission('module_config', 2);

$roadmap_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
$roadmap_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
$roadmap_priorities = ['Low', 'Medium', 'High', 'Critical'];

?>

<div class="modal" id="addRoadmapItemModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
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
                                    <option value="<?= $category ?>"><?= $category ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Status</label>
                            <select class="form-control select2" name="roadmap_item_status">
                                <?php foreach ($roadmap_statuses as $status) { ?>
                                    <option value="<?= $status ?>" <?= $status === 'Backlog' ? 'selected' : '' ?>><?= $status ?></option>
                                <?php } ?>
                            </select>
                        </div>

                        <div class="form-group col-md-4">
                            <label>Priority</label>
                            <select class="form-control select2" name="roadmap_item_priority">
                                <?php foreach ($roadmap_priorities as $priority) { ?>
                                    <option value="<?= $priority ?>" <?= $priority === 'Medium' ? 'selected' : '' ?>><?= $priority ?></option>
                                <?php } ?>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Target Version / Milestone</label>
                        <input type="text" class="form-control" name="roadmap_item_target_version" maxlength="64" placeholder="Optional, e.g. Phase 4, v2.5, Q3">
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
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>
                </div>
            </form>
        </div>
    </div>
</div>
