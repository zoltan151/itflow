<?php
// ITFLOW_DOCUMENT_TYPES_PHASE2A

require_once '../../../includes/modal_header.php';

$client_id = intval($_GET['client_id'] ?? 0);
$contact_id = intval($_GET['contact_id'] ?? 0);
$asset_id = intval($_GET['asset_id'] ?? 0);
intval($_GET['folder_id'] ?? 0);

// ITFLOW_CLIENT_DOCUMENT_ADD_LOCKED_CLIENT_CONTEXT
$client_name_display = '';

if ($client_id > 0) {
    $sql_client_context = mysqli_query(
        $mysqli,
        "SELECT client_name FROM clients WHERE client_id = $client_id LIMIT 1"
    );

    if ($row_client_context = mysqli_fetch_assoc($sql_client_context)) {
        $client_name_display = nullable_htmlentities($row_client_context['client_name']);
    }
}

if (!$client_name_display) {
    $client_name_display = 'Unknown Client';
}

$document_type = 'General';

ob_start();

?>
<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fa fa-fw fa-file-alt mr-2"></i>New Document</h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>
<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="client_id" value="<?= $client_id ?>">
    <input type="hidden" name="contact" value="<?= $contact_id ?>">
    <input type="hidden" name="asset" value="<?= $asset_id ?>">
    <div class="modal-body">

        <div class="form-group">
            <label>Client</label>
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-building"></i></span>
                </div>
                <input type="text" class="form-control bg-light text-muted" value="<?= $client_name_display ?>" readonly disabled>
            </div>
            <small class="form-text text-muted">This document will be created under this client.</small>
        </div>

        <div class="form-group">
            <input type="text" class="form-control" name="name" placeholder="Name" maxlength="200" required autofocus>
        </div>

        <?php
        $document_type_options = [
            'General' => ['label' => 'General', 'icon' => 'fa-file-alt', 'class' => 'secondary'],
            'SOP' => ['label' => 'SOP', 'icon' => 'fa-clipboard-list', 'class' => 'primary'],
            'Client SOP' => ['label' => 'Client SOP', 'icon' => 'fa-clipboard-check', 'class' => 'primary'],
            'Runbook' => ['label' => 'Runbook', 'icon' => 'fa-list-ol', 'class' => 'info'],
            'Onboarding' => ['label' => 'Onboarding', 'icon' => 'fa-user-plus', 'class' => 'success'],
            'Offboarding' => ['label' => 'Offboarding', 'icon' => 'fa-user-minus', 'class' => 'warning'],
            'Network Diagram' => ['label' => 'Network Diagram', 'icon' => 'fa-network-wired', 'class' => 'dark'],
            'Diagram / Whiteboard' => ['label' => 'Diagram / Whiteboard', 'icon' => 'fa-project-diagram', 'class' => 'dark'],
            'Process Map' => ['label' => 'Process Map', 'icon' => 'fa-sitemap', 'class' => 'info'],
            'Mind Map' => ['label' => 'Mind Map', 'icon' => 'fa-brain', 'class' => 'info'],
            'Planner' => ['label' => 'Planner', 'icon' => 'fa-tasks', 'class' => 'success'],
            'Timeline' => ['label' => 'Timeline', 'icon' => 'fa-stream', 'class' => 'purple'],
            'Internal KB' => ['label' => 'Internal KB', 'icon' => 'fa-book', 'class' => 'secondary'],
            'Other' => ['label' => 'Other', 'icon' => 'fa-file', 'class' => 'secondary'],
        ];
        
        if (!isset($document_type) || !isset($document_type_options[$document_type])) {
            $document_type = 'General';
        }
        ?>
        <div class="form-group">
            <label>Document Type</label>
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-tags"></i></span>
                </div>
                <select class="form-control select2" name="document_type">
                    <?php foreach ($document_type_options as $document_type_key => $document_type_meta) { ?>
                        <option value="<?= nullable_htmlentities($document_type_key) ?>" <?php if ($document_type === $document_type_key) { echo 'selected'; } ?>>
                            <?= nullable_htmlentities($document_type_meta['label']) ?>
                        </option>
                    <?php } ?>
                </select>
            </div>
        </div>
        <?php
        ?>

        <div class="form-group">
            <textarea class="form-control tinymce" name="content"></textarea>
        </div>

        <div class="form-group">
            <label>Select Folder</label>
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-folder"></i></span>
                </div>
                <select class="form-control select2" name="folder">
                    <option value="0">/</option>
                    <?php
                    // Start displaying folder options from the root (parent_folder = 0)
                    display_folder_options(0, $client_id);
                    ?>
                </select>
            </div>
        </div>

        <div class="form-group">
            <label>Description</label>
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-align-left"></i></span>
                </div>
                <input type="text" class="form-control" name="description" placeholder="Short summary of the document">
            </div>
        </div>
    </div>
    <div class="modal-footer">
        <button type="submit" name="add_document" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Create</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>

<?php
require_once '../../../includes/modal_footer.php';
