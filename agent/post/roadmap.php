<?php
// ITFLOW_PLATFORM_ROADMAP_PHASE3B

/*
 * ITFlow - Roadmap POST handler
 */

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

function sanitizeRoadmapOption($value, $allowed, $fallback) {
    $value = sanitizeInput($value);

    if (in_array($value, $allowed, true)) {
        return $value;
    }

    return $fallback;
}

$roadmap_statuses = ['Backlog', 'Planned', 'In Development', 'Coming Soon', 'Shipped'];
$roadmap_categories = ['Documentation', 'Credentials', 'Client Portal', 'Automation', 'Integrations', 'AI', 'Reporting', 'Security', 'Other'];
$roadmap_priorities = ['Low', 'Medium', 'High', 'Critical'];

if (isset($_POST['add_roadmap_item'])) {

    validateCSRFToken($_POST['csrf_token']);

    enforceUserPermission('module_config', 2);

    $title = sanitizeInput($_POST['roadmap_item_title'] ?? '');
    $description = sanitizeInput($_POST['roadmap_item_description'] ?? '');
    $category = sanitizeRoadmapOption($_POST['roadmap_item_category'] ?? '', $roadmap_categories, 'Other');
    $status = sanitizeRoadmapOption($_POST['roadmap_item_status'] ?? '', $roadmap_statuses, 'Backlog');
    $priority = sanitizeRoadmapOption($_POST['roadmap_item_priority'] ?? '', $roadmap_priorities, 'Medium');
    $target_version = sanitizeInput($_POST['roadmap_item_target_version'] ?? '');
    $notes = sanitizeInput($_POST['roadmap_item_notes'] ?? '');

    if (!$title) {
        flash_alert("Roadmap item title is required", 'error');
        redirect("roadmap.php");
    }

    mysqli_query(
        $mysqli,
        "INSERT INTO roadmap_items SET
            roadmap_item_title = '$title',
            roadmap_item_description = '$description',
            roadmap_item_category = '$category',
            roadmap_item_status = '$status',
            roadmap_item_priority = '$priority',
            roadmap_item_target_version = '$target_version',
            roadmap_item_notes = '$notes',
            roadmap_item_created_by = $session_user_id"
    );

    $roadmap_item_id = mysqli_insert_id($mysqli);

    logAction("Roadmap", "Create", "$session_name created roadmap item $title", 0, $roadmap_item_id);

    flash_alert("Roadmap item <strong>$title</strong> created");

    redirect("roadmap.php");

}

if (isset($_POST['edit_roadmap_item'])) {

    validateCSRFToken($_POST['csrf_token']);

    enforceUserPermission('module_config', 2);

    $roadmap_item_id = intval($_POST['roadmap_item_id']);
    $title = sanitizeInput($_POST['roadmap_item_title'] ?? '');
    $description = sanitizeInput($_POST['roadmap_item_description'] ?? '');
    $category = sanitizeRoadmapOption($_POST['roadmap_item_category'] ?? '', $roadmap_categories, 'Other');
    $status = sanitizeRoadmapOption($_POST['roadmap_item_status'] ?? '', $roadmap_statuses, 'Backlog');
    $priority = sanitizeRoadmapOption($_POST['roadmap_item_priority'] ?? '', $roadmap_priorities, 'Medium');
    $target_version = sanitizeInput($_POST['roadmap_item_target_version'] ?? '');
    $notes = sanitizeInput($_POST['roadmap_item_notes'] ?? '');

    if (!$title) {
        flash_alert("Roadmap item title is required", 'error');
        redirect("roadmap.php");
    }

    mysqli_query(
        $mysqli,
        "UPDATE roadmap_items SET
            roadmap_item_title = '$title',
            roadmap_item_description = '$description',
            roadmap_item_category = '$category',
            roadmap_item_status = '$status',
            roadmap_item_priority = '$priority',
            roadmap_item_target_version = '$target_version',
            roadmap_item_notes = '$notes',
            roadmap_item_updated_at = NOW(),
            roadmap_item_updated_by = $session_user_id
         WHERE roadmap_item_id = $roadmap_item_id"
    );

    logAction("Roadmap", "Edit", "$session_name edited roadmap item $title", 0, $roadmap_item_id);

    flash_alert("Roadmap item <strong>$title</strong> updated");

    redirect("roadmap.php");

}

if (isset($_GET['archive_roadmap_item'])) {

    validateCSRFToken($_GET['csrf_token']);

    enforceUserPermission('module_config', 2);

    $roadmap_item_id = intval($_GET['archive_roadmap_item']);

    mysqli_query($mysqli, "UPDATE roadmap_items SET roadmap_item_archived_at = NOW(), roadmap_item_updated_at = NOW(), roadmap_item_updated_by = $session_user_id WHERE roadmap_item_id = $roadmap_item_id");

    logAction("Roadmap", "Archive", "$session_name archived roadmap item", 0, $roadmap_item_id);

    flash_alert("Roadmap item archived");

    redirect("roadmap.php");

}

if (isset($_GET['restore_roadmap_item'])) {

    validateCSRFToken($_GET['csrf_token']);

    enforceUserPermission('module_config', 2);

    $roadmap_item_id = intval($_GET['restore_roadmap_item']);

    mysqli_query($mysqli, "UPDATE roadmap_items SET roadmap_item_archived_at = NULL, roadmap_item_updated_at = NOW(), roadmap_item_updated_by = $session_user_id WHERE roadmap_item_id = $roadmap_item_id");

    logAction("Roadmap", "Restore", "$session_name restored roadmap item", 0, $roadmap_item_id);

    flash_alert("Roadmap item restored");

    redirect("roadmap.php?archived=1");

}

if (isset($_GET['delete_roadmap_item'])) {

    validateCSRFToken($_GET['csrf_token']);

    enforceUserPermission('module_config', 3);

    $roadmap_item_id = intval($_GET['delete_roadmap_item']);

    mysqli_query($mysqli, "DELETE FROM roadmap_items WHERE roadmap_item_id = $roadmap_item_id");

    logAction("Roadmap", "Delete", "$session_name deleted roadmap item", 0, $roadmap_item_id);

    flash_alert("Roadmap item deleted");

    redirect("roadmap.php?archived=1");

}
