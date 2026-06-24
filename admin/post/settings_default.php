<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_default_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $start_page = sanitizeInput($_POST['start_page']);
    $expense_account = intval($_POST['expense_account']);
    $payment_account = intval($_POST['payment_account']);
    $payment_method = sanitizeInput($_POST['payment_method']);
    $expense_payment_method = sanitizeInput($_POST['expense_payment_method']);
    $transfer_from_account = intval($_POST['transfer_from_account']);
    $transfer_to_account = intval($_POST['transfer_to_account']);
    $calendar = intval($_POST['calendar']);
    $net_terms = intval($_POST['net_terms']);
    $hourly_rate = floatval($_POST['hourly_rate']);
    $internal_workspace_enable = intval($_POST['internal_workspace_enable'] ?? 0);
    $internal_client_id = intval($_POST['internal_client_id'] ?? 0);
    $internal_workspace_record_mode = sanitizeInput($_POST['internal_workspace_record_mode'] ?? 'existing');
    $internal_create_client_name = sanitizeInput($_POST['internal_create_client_name'] ?? '');
    $internal_workspace_name = sanitizeInput($_POST['internal_workspace_name'] ?? 'Internal');
    if (empty($internal_workspace_name)) {
        $internal_workspace_name = 'Internal';
    }
    $internal_hide_from_clients = intval($_POST['internal_hide_from_clients'] ?? 0);

    // Create a new internal organization directly from Defaults when requested.
    // If an active organization with the same name already exists, use that record instead of creating a duplicate.
    if ($internal_workspace_record_mode === 'create' && !empty($internal_create_client_name)) {
        $existing_internal_client = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT client_id FROM clients WHERE client_name = '$internal_create_client_name' AND client_archived_at IS NULL LIMIT 1"));

        if ($existing_internal_client) {
            $internal_client_id = intval($existing_internal_client['client_id']);
        } else {
            mysqli_query($mysqli, "INSERT INTO clients SET client_name = '$internal_create_client_name', client_internal = 1");
            $internal_client_id = mysqli_insert_id($mysqli);
        }

        if ($internal_client_id > 0) {
            $internal_workspace_enable = 1;
        }
    }

    mysqli_query($mysqli,"UPDATE settings SET config_start_page = '$start_page', config_default_expense_account = $expense_account, config_default_payment_account = $payment_account, config_default_payment_method = '$payment_method', config_default_expense_payment_method = '$expense_payment_method', config_default_transfer_from_account = $transfer_from_account, config_default_transfer_to_account = $transfer_to_account, config_default_calendar = $calendar, config_default_net_terms = $net_terms, config_default_hourly_rate = $hourly_rate, config_internal_workspace_enable = $internal_workspace_enable, config_internal_client_id = $internal_client_id, config_internal_workspace_name = '$internal_workspace_name', config_internal_hide_from_clients = $internal_hide_from_clients WHERE company_id = 1");

    mysqli_query($mysqli, "UPDATE clients SET client_internal = 0");
    if ($internal_workspace_enable && $internal_client_id > 0) {
        mysqli_query($mysqli, "UPDATE clients SET client_internal = 1 WHERE client_id = $internal_client_id");
    }

    logAction("Settings", "Edit", "$session_name edited default settings");

    flash_alert("Default settings edited");

    redirect();

}
