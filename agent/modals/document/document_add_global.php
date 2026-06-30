<?php

require_once '../../../includes/modal_header.php';

// ITFLOW_GLOBAL_NEW_DOCUMENT_OB_START_FIX
// modal_footer.php expects modal body output to be buffered, matching the standard modal pattern.
ob_start();

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
