<?php
// ITFLOW_DOCUMENT_TYPES_PHASE2A

require_once '../../../includes/modal_header.php';

$document_id = intval($_GET['id']);

$sql = mysqli_query($mysqli, "SELECT * FROM documents WHERE document_id = $document_id LIMIT 1");

$row = mysqli_fetch_assoc($sql);
$document_name = nullable_htmlentities($row['document_name']);
$document_description = nullable_htmlentities($row['document_description']);
$document_type = nullable_htmlentities($row['document_type'] ?? 'General');
$document_content = nullable_htmlentities($row['document_content']);
$document_folder_id = intval($row['document_folder_id']);
$document_client_visible = intval($row['document_client_visible']);
$client_id = intval($row['document_client_id']);

// Generate the HTML form content using output buffering.
ob_start();
?>

<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fa fa-fw fa-file-alt mr-2"></i>Editing document: <strong><?php echo $document_name; ?></strong></h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>
<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="document_id" value="<?php echo $document_id; ?>">

    <div class="modal-body">

        <div class="form-group">
            <input type="text" class="form-control" name="name" maxlength="200" value="<?php echo $document_name; ?>" placeholder="Name" required>
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
            <textarea class="form-control tinymce" name="content"><?php echo $document_content; ?></textarea>
        </div>

        <label>Description</label>
        <div class="form-group">
            <div class="input-group">
                <div class="input-group-prepend">
                    <span class="input-group-text"><i class="fa fa-fw fa-align-left"></i></span>
                </div>
                <input type="text" class="form-control" name="description" value="<?php echo $document_description; ?>" placeholder="Short summary of the document">
            </div>
        </div>

    </div>
    <div class="modal-footer">
        <button type="submit" name="edit_document" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Save</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>

<?php
require_once '../../../includes/modal_footer.php';
