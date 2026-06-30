<?php
// ITFLOW_DOCUMENT_TYPES_PHASE2A

require_once '../../../includes/modal_header.php';

// ITFLOW_GLOBAL_NEW_DOCUMENT_OB_START_FIX
// modal_footer.php expects modal body output to be buffered, matching the standard modal pattern.
ob_start();

$document_type = 'General';

?>

<div class="modal-header bg-dark">
    <h5 class="modal-title">
        <i class="fa fa-fw fa-file-alt mr-2"></i>New Document
        <small class="text-muted ml-2">Quick Add</small>
    </h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>

<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="folder" value="0">
    <input type="hidden" name="contact" value="0">
    <input type="hidden" name="asset" value="0">

    <div class="modal-body">

        <div class="alert alert-info">
            <i class="fas fa-info-circle mr-2"></i>
            Choose the client this document belongs to. Global Quick Add documents are created in that client's root documentation folder.
        </div>

        <div class="form-group">
            <label>Client <strong class="text-danger">*</strong></label>
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-building"></i></span>
                </div>
                <select class="form-control select2" name="client_id" required autofocus>
                    <option value="">- Select Client -</option>
                    <?php
                    $sql_clients = mysqli_query(
                        $mysqli,
                        "SELECT client_id, client_name
                         FROM clients
                         WHERE client_archived_at IS NULL
                         ORDER BY client_name ASC"
                    );

                    while ($row = mysqli_fetch_assoc($sql_clients)) {
                        $client_id = intval($row['client_id']);
                        $client_name = nullable_htmlentities($row['client_name']);
                        ?>
                        <option value="<?= $client_id ?>"><?= $client_name ?></option>
                    <?php } ?>
                </select>
            </div>
        </div>

        <div class="form-group">
            <label>Name <strong class="text-danger">*</strong></label>
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-file"></i></span>
                </div>
                <input type="text" class="form-control" name="name" placeholder="Document name" maxlength="200" required>
            </div>
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
            <label>Content</label>
            <textarea class="form-control tinymce" name="content"></textarea>
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
        <button type="submit" name="add_document" class="btn btn-primary text-bold">
            <i class="fa fa-check mr-2"></i>Create
        </button>
        <button type="button" class="btn btn-light" data-dismiss="modal">
            <i class="fa fa-times mr-2"></i>Cancel
        </button>
    </div>
</form>

<?php

require_once '../../../includes/modal_footer.php';
