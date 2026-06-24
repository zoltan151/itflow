<?php

// Load core/session/settings first so redirects can happen before any layout output.
require_once $_SERVER['DOCUMENT_ROOT'] . '/config.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/functions.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/check_login.php';

enforceUserPermission('module_client');

if (empty($config_internal_workspace_enable)) {
    flash_alert("Internal Workspace is disabled. Enable it under Administration > Defaults.", 'warning');
    header("Location: /agent/clients.php");
    exit;
}

if (!empty($config_internal_client_id)) {
    $client_id = intval($config_internal_client_id);
    header("Location: /agent/client_overview.php?client_id=$client_id");
    exit;
}

// No Internal Organization Record is configured yet, so render the setup UI.
require_once "includes/inc_all.php";

function currentUserIsAdminForInternalWorkspaceSetup() {
    global $mysqli, $session_user_id;
    $session_user_id = intval($session_user_id ?? 0);
    if ($session_user_id <= 0) {
        return false;
    }
    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "
        SELECT role_is_admin
        FROM users
        LEFT JOIN user_roles ON user_role_id = role_id
        WHERE user_id = $session_user_id
        LIMIT 1
    "));
    return intval($row['role_is_admin'] ?? 0) === 1;
}

$is_internal_setup_admin = currentUserIsAdminForInternalWorkspaceSetup();

if (isset($_POST['setup_internal_workspace'])) {
    validateCSRFToken($_POST['csrf_token']);

    if (!$is_internal_setup_admin) {
        flash_alert("Only administrators can configure the Internal Workspace.", 'error');
        redirect("internal.php");
    }

    $internal_client_id = intval($_POST['internal_client_id'] ?? 0);
    $internal_workspace_record_mode = sanitizeInput($_POST['internal_workspace_record_mode'] ?? 'existing');
    $internal_create_client_name = sanitizeInput($_POST['internal_create_client_name'] ?? '');
    $internal_workspace_name = sanitizeInput($_POST['internal_workspace_name'] ?? 'Internal');
    if (empty($internal_workspace_name)) {
        $internal_workspace_name = 'Internal';
    }
    $internal_hide_from_clients = intval($_POST['internal_hide_from_clients'] ?? 0);

    if ($internal_workspace_record_mode === 'create' && !empty($internal_create_client_name)) {
        $existing_internal_client = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT client_id FROM clients WHERE client_name = '$internal_create_client_name' AND client_archived_at IS NULL LIMIT 1"));
        if ($existing_internal_client) {
            $internal_client_id = intval($existing_internal_client['client_id']);
        } else {
            mysqli_query($mysqli, "INSERT INTO clients SET client_name = '$internal_create_client_name', client_internal = 1");
            $internal_client_id = mysqli_insert_id($mysqli);
        }
    }

    if ($internal_client_id <= 0) {
        flash_alert("Select an existing organization or enter a new Internal organization name.", 'error');
        redirect("internal.php");
    }

    mysqli_query($mysqli, "UPDATE settings SET config_internal_workspace_enable = 1, config_internal_client_id = $internal_client_id, config_internal_workspace_name = '$internal_workspace_name', config_internal_hide_from_clients = $internal_hide_from_clients WHERE company_id = 1");
    mysqli_query($mysqli, "UPDATE clients SET client_internal = 0");
    mysqli_query($mysqli, "UPDATE clients SET client_internal = 1 WHERE client_id = $internal_client_id");

    logAction("Settings", "Edit", "$session_name configured Internal Workspace", 0, $internal_client_id);
    flash_alert("Internal Workspace configured");
    redirect("internal.php");
}

$sql_internal_client_select = mysqli_query($mysqli, "SELECT client_id, client_name FROM clients WHERE client_archived_at IS NULL ORDER BY client_name ASC");

?>


<style>
    /* Keep the global top navigation clickable above the Internal Workspace setup surface. */
    .main-header,
    .main-header .navbar-nav,
    .main-header .dropdown-menu {
        position: relative;
        z-index: 2050 !important;
        pointer-events: auto;
    }
    .content-wrapper {
        position: relative;
        z-index: 1;
    }
</style>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-home mr-2"></i><?php echo nullable_htmlentities($config_internal_workspace_name ?: 'Internal'); ?></h3>
    </div>
    <div class="card-body">
        <?php if ($is_internal_setup_admin) { ?>
            <div class="alert alert-info">
                <strong>Internal Workspace is enabled, but no Internal Organization Record has been selected yet.</strong><br>
                Select an existing organization or create a new one below. ITFlow will use that record for internal docs, credentials, assets, domains, vendors, tickets, and related data.
            </div>

            <form action="internal.php" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <div class="form-group">
                    <label>Internal Menu Name</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span>
                        </div>
                        <input type="text" class="form-control" name="internal_workspace_name" maxlength="100" value="<?php echo nullable_htmlentities($config_internal_workspace_name ?: 'Internal'); ?>" placeholder="Internal">
                    </div>
                </div>

                <div class="form-group">
                    <label>Internal Organization Setup</label>
                    <div class="btn-group btn-group-toggle d-flex" data-toggle="buttons">
                        <label class="btn btn-outline-secondary flex-fill active" for="internalWorkspaceModeExisting">
                            <input type="radio" name="internal_workspace_record_mode" id="internalWorkspaceModeExisting" value="existing" checked>
                            <i class="fas fa-fw fa-users mr-1"></i>Use Existing Organization
                        </label>
                        <label class="btn btn-outline-secondary flex-fill" for="internalWorkspaceModeCreate">
                            <input type="radio" name="internal_workspace_record_mode" id="internalWorkspaceModeCreate" value="create">
                            <i class="fas fa-fw fa-plus-circle mr-1"></i>Create New Internal Organization
                        </label>
                    </div>
                </div>

                <div class="form-group internal-workspace-mode-panel" id="internalWorkspaceExistingPanel">
                    <label>Use Existing Organization</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-users"></i></span>
                        </div>
                        <select class="form-control select2" name="internal_client_id">
                            <option value="0">- Select Existing Organization -</option>
                            <?php while ($row = mysqli_fetch_assoc($sql_internal_client_select)) {
                                $internal_client_id_select = intval($row['client_id']);
                                $internal_client_name_select = nullable_htmlentities($row['client_name']);
                            ?>
                                <option value="<?php echo $internal_client_id_select; ?>"><?php echo $internal_client_name_select; ?></option>
                            <?php } ?>
                        </select>
                    </div>
                </div>

                <div class="form-group internal-workspace-mode-panel" id="internalWorkspaceCreatePanel">
                    <label>Create New Internal Organization</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-plus-circle"></i></span>
                        </div>
                        <input type="text" class="form-control" name="internal_create_client_name" maxlength="200" placeholder="Example: <?php echo nullable_htmlentities($company_name ?? 'Internal Organization'); ?> Internal">
                    </div>
                    <small class="text-secondary">If an active organization with this exact name already exists, ITFlow will reuse it instead of creating a duplicate.</small>
                </div>

                <div class="form-group">
                    <div class="custom-control custom-switch">
                        <input type="checkbox" class="custom-control-input" name="internal_hide_from_clients" value="1" id="internalHideFromClientsSwitch" <?php if (($config_internal_hide_from_clients ?? 1) == 1) { echo "checked"; } ?>>
                        <label class="custom-control-label text-bold" for="internalHideFromClientsSwitch">Hide Internal Workspace from Clients list</label>
                    </div>
                </div>

                <button type="submit" name="setup_internal_workspace" class="btn btn-primary text-bold"><i class="fas fa-check mr-2"></i>Save Internal Workspace</button>
            </form>
        <?php } else { ?>
            <div class="alert alert-warning mb-0">
                <strong>Internal Workspace has not been configured yet.</strong><br>
                Ask an administrator to select or create the Internal Organization Record under Administration &gt; Defaults or from this page.
            </div>
        <?php } ?>
    </div>
</div>


<script>
document.addEventListener('DOMContentLoaded', function () {
    function toggleInternalWorkspaceModePanels() {
        var mode = document.querySelector('input[name="internal_workspace_record_mode"]:checked');
        var selectedMode = mode ? mode.value : 'existing';
        var existingPanel = document.getElementById('internalWorkspaceExistingPanel');
        var createPanel = document.getElementById('internalWorkspaceCreatePanel');
        if (existingPanel) { existingPanel.style.display = selectedMode === 'existing' ? '' : 'none'; }
        if (createPanel) { createPanel.style.display = selectedMode === 'create' ? '' : 'none'; }
    }

    document.querySelectorAll('input[name="internal_workspace_record_mode"]').forEach(function (el) {
        el.addEventListener('change', toggleInternalWorkspaceModePanels);
    });
    toggleInternalWorkspaceModePanels();
});
</script>

<?php require_once "../includes/footer.php"; ?>
