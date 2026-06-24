<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");




if (isset($_POST['edit_ticket_reply_target_status_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $config_ticket_reply_target_status_id = intval($_POST['config_ticket_reply_target_status_id'] ?? 0);

    $status_sql = mysqli_query(
        $mysqli,
        "SELECT ticket_status_id FROM ticket_statuses WHERE ticket_status_id = $config_ticket_reply_target_status_id AND ticket_status_active = 1 LIMIT 1"
    );

    if (!$status_sql || mysqli_num_rows($status_sql) === 0) {
        flash_alert("Invalid reply target status selected", 'error');
        redirect();
    }

    mysqli_query(
        $mysqli,
        "UPDATE settings SET config_ticket_reply_target_status_id = $config_ticket_reply_target_status_id WHERE company_id = 1"
    );

    logAction("Settings", "Edit", "$session_name edited ticket reply target status settings");

    flash_alert("Ticket Reply Target Status Settings updated");

    redirect();

}


if (isset($_POST['edit_ticket_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $config_ticket_prefix = sanitizeInput($_POST['config_ticket_prefix']);
    $config_ticket_next_number = intval($_POST['config_ticket_next_number']);
    $config_ticket_email_parse = intval($_POST['config_ticket_email_parse'] ?? 0);
    $config_ticket_email_parse_unknown_senders = intval($_POST['config_ticket_email_parse_unknown_senders'] ?? 0);
    $config_ticket_default_billable = intval($_POST['config_ticket_default_billable'] ?? 0);
    $config_ticket_autoclose_hours = intval($_POST['config_ticket_autoclose_hours']);
    $config_ticket_new_ticket_notification_email = '';
    if (filter_var($_POST['config_ticket_new_ticket_notification_email'], FILTER_VALIDATE_EMAIL)) {
        $config_ticket_new_ticket_notification_email = sanitizeInput($_POST['config_ticket_new_ticket_notification_email']);
    }
    $config_ticket_default_view = intval($_POST['config_ticket_default_view']);
    $config_ticket_moving_columns = intval($_POST['config_ticket_moving_columns']);
    $config_ticket_ordering = intval($_POST['config_ticket_ordering']);
    $config_ticket_timer_autostart = intval($_POST['config_ticket_timer_autostart']);
    $config_ticket_inbound_cc_watcher_mode = sanitizeInput($_POST['config_ticket_inbound_cc_watcher_mode'] ?? 'all');
    if (!in_array($config_ticket_inbound_cc_watcher_mode, ['all', 'known_contacts', 'disabled'], true)) {
        $config_ticket_inbound_cc_watcher_mode = 'all';
    }
    $config_ticket_watcher_reply_type = sanitizeInput($_POST['config_ticket_watcher_reply_type'] ?? 'client');
    if (!in_array($config_ticket_watcher_reply_type, ['client', 'internal'], true)) {
        $config_ticket_watcher_reply_type = 'client';
    }
    $config_ticket_initial_history_enable = intval($_POST['config_ticket_initial_history_enable'] ?? 0);
    $config_ticket_mail_queue_history_enable = intval($_POST['config_ticket_mail_queue_history_enable'] ?? 0);
    $config_ticket_mail_queue_watcher_cc_enable = intval($_POST['config_ticket_mail_queue_watcher_cc_enable'] ?? 0);
    $config_ticket_resolved_feedback_enable = intval($_POST['config_ticket_resolved_feedback_enable'] ?? 0);
    $config_ticket_resolved_feedback_message_enable = intval($_POST['config_ticket_resolved_feedback_message_enable'] ?? 0);
    $config_ticket_resolved_feedback_review_enable = intval($_POST['config_ticket_resolved_feedback_review_enable'] ?? 0);
    $config_ticket_resolved_feedback_review_heading_enable = intval($_POST['config_ticket_resolved_feedback_review_heading_enable'] ?? 0);
    $config_ticket_resolved_feedback_review_message_enable = intval($_POST['config_ticket_resolved_feedback_review_message_enable'] ?? 0);
    $config_ticket_resolved_feedback_review_button_enable = intval($_POST['config_ticket_resolved_feedback_review_button_enable'] ?? 0);
    $config_ticket_resolved_feedback_private_enable = intval($_POST['config_ticket_resolved_feedback_private_enable'] ?? 0);
    $config_ticket_resolved_feedback_private_heading_enable = intval($_POST['config_ticket_resolved_feedback_private_heading_enable'] ?? 0);
    $config_ticket_resolved_feedback_private_message_enable = intval($_POST['config_ticket_resolved_feedback_private_message_enable'] ?? 0);
    $config_ticket_resolved_feedback_private_button_enable = intval($_POST['config_ticket_resolved_feedback_private_button_enable'] ?? 0);
    $config_ticket_resolved_feedback_message = mysqli_real_escape_string($mysqli, sanitizeInput($_POST['config_ticket_resolved_feedback_message'] ?? ''));
    $config_ticket_resolved_feedback_message_order = intval($_POST['config_ticket_resolved_feedback_message_order'] ?? 10);
    $config_ticket_resolved_feedback_review_order = intval($_POST['config_ticket_resolved_feedback_review_order'] ?? 30);
    $config_ticket_resolved_feedback_private_order = intval($_POST['config_ticket_resolved_feedback_private_order'] ?? 20);
    $config_ticket_resolved_feedback_review_heading = mysqli_real_escape_string($mysqli, sanitizeInput($_POST['config_ticket_resolved_feedback_review_heading'] ?? 'Happy with our service?'));
    if ($config_ticket_resolved_feedback_review_heading === '') {
        $config_ticket_resolved_feedback_review_heading = 'Happy with our service?';
    }
    $config_ticket_resolved_feedback_review_message = mysqli_real_escape_string($mysqli, sanitizeInput($_POST['config_ticket_resolved_feedback_review_message'] ?? ''));
    $config_ticket_resolved_feedback_private_heading = mysqli_real_escape_string($mysqli, sanitizeInput($_POST['config_ticket_resolved_feedback_private_heading'] ?? 'Something we can improve?'));
    if ($config_ticket_resolved_feedback_private_heading === '') {
        $config_ticket_resolved_feedback_private_heading = 'Something we can improve?';
    }
    $config_ticket_resolved_feedback_private_message = mysqli_real_escape_string($mysqli, sanitizeInput($_POST['config_ticket_resolved_feedback_private_message'] ?? ''));

    $config_ticket_resolved_feedback_review_button_color = sanitizeInput($_POST['config_ticket_resolved_feedback_review_button_color'] ?? '#16a34a');
    if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $config_ticket_resolved_feedback_review_button_color)) {
        $config_ticket_resolved_feedback_review_button_color = '#16a34a';
    }
    $config_ticket_resolved_feedback_review_button_color = mysqli_real_escape_string($mysqli, $config_ticket_resolved_feedback_review_button_color);

    $config_ticket_resolved_feedback_private_button_color = sanitizeInput($_POST['config_ticket_resolved_feedback_private_button_color'] ?? '#d97706');
    if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $config_ticket_resolved_feedback_private_button_color)) {
        $config_ticket_resolved_feedback_private_button_color = '#d97706';
    }
    $config_ticket_resolved_feedback_private_button_color = mysqli_real_escape_string($mysqli, $config_ticket_resolved_feedback_private_button_color);

    $config_ticket_resolved_feedback_review_url = '';
    if (!empty($_POST['config_ticket_resolved_feedback_review_url']) && filter_var($_POST['config_ticket_resolved_feedback_review_url'], FILTER_VALIDATE_URL)) {
        $config_ticket_resolved_feedback_review_url = sanitizeInput($_POST['config_ticket_resolved_feedback_review_url']);
    }
    $config_ticket_resolved_feedback_review_url = mysqli_real_escape_string($mysqli, $config_ticket_resolved_feedback_review_url);
    $config_ticket_resolved_feedback_review_text = mysqli_real_escape_string($mysqli, sanitizeInput($_POST['config_ticket_resolved_feedback_review_text'] ?? 'Leave a Review'));
    if ($config_ticket_resolved_feedback_review_text === '') {
        $config_ticket_resolved_feedback_review_text = 'Leave a Review';
    }
    $config_ticket_resolved_feedback_private_url = '';
    if (!empty($_POST['config_ticket_resolved_feedback_private_url']) && filter_var($_POST['config_ticket_resolved_feedback_private_url'], FILTER_VALIDATE_URL)) {
        $config_ticket_resolved_feedback_private_url = sanitizeInput($_POST['config_ticket_resolved_feedback_private_url']);
    }
    $config_ticket_resolved_feedback_private_url = mysqli_real_escape_string($mysqli, $config_ticket_resolved_feedback_private_url);
    $config_ticket_resolved_feedback_private_text = mysqli_real_escape_string($mysqli, sanitizeInput($_POST['config_ticket_resolved_feedback_private_text'] ?? 'Send Private Feedback'));
    if ($config_ticket_resolved_feedback_private_text === '') {
        $config_ticket_resolved_feedback_private_text = 'Send Private Feedback';
    }

    mysqli_query($mysqli,"UPDATE settings SET config_ticket_prefix = '$config_ticket_prefix', config_ticket_next_number = $config_ticket_next_number, config_ticket_email_parse = $config_ticket_email_parse, config_ticket_email_parse_unknown_senders = $config_ticket_email_parse_unknown_senders, config_ticket_autoclose_hours = $config_ticket_autoclose_hours, config_ticket_new_ticket_notification_email = '$config_ticket_new_ticket_notification_email', config_ticket_default_billable = $config_ticket_default_billable, config_ticket_default_view = $config_ticket_default_view, config_ticket_moving_columns = $config_ticket_moving_columns, config_ticket_ordering = $config_ticket_ordering, config_ticket_timer_autostart = $config_ticket_timer_autostart, config_ticket_resolved_feedback_enable = $config_ticket_resolved_feedback_enable, config_ticket_resolved_feedback_message_enable = $config_ticket_resolved_feedback_message_enable, config_ticket_resolved_feedback_message = '$config_ticket_resolved_feedback_message', config_ticket_resolved_feedback_message_order = $config_ticket_resolved_feedback_message_order, config_ticket_resolved_feedback_review_enable = $config_ticket_resolved_feedback_review_enable, config_ticket_resolved_feedback_review_heading_enable = $config_ticket_resolved_feedback_review_heading_enable, config_ticket_resolved_feedback_review_heading = '$config_ticket_resolved_feedback_review_heading', config_ticket_resolved_feedback_review_message_enable = $config_ticket_resolved_feedback_review_message_enable, config_ticket_resolved_feedback_review_message = '$config_ticket_resolved_feedback_review_message', config_ticket_resolved_feedback_review_button_enable = $config_ticket_resolved_feedback_review_button_enable, config_ticket_resolved_feedback_review_url = '$config_ticket_resolved_feedback_review_url', config_ticket_resolved_feedback_review_text = '$config_ticket_resolved_feedback_review_text', config_ticket_resolved_feedback_review_order = $config_ticket_resolved_feedback_review_order, config_ticket_resolved_feedback_review_button_color = '$config_ticket_resolved_feedback_review_button_color', config_ticket_resolved_feedback_private_enable = $config_ticket_resolved_feedback_private_enable, config_ticket_resolved_feedback_private_heading_enable = $config_ticket_resolved_feedback_private_heading_enable, config_ticket_resolved_feedback_private_heading = '$config_ticket_resolved_feedback_private_heading', config_ticket_resolved_feedback_private_message_enable = $config_ticket_resolved_feedback_private_message_enable, config_ticket_resolved_feedback_private_message = '$config_ticket_resolved_feedback_private_message', config_ticket_resolved_feedback_private_button_enable = $config_ticket_resolved_feedback_private_button_enable, config_ticket_resolved_feedback_private_url = '$config_ticket_resolved_feedback_private_url', config_ticket_resolved_feedback_private_text = '$config_ticket_resolved_feedback_private_text', config_ticket_resolved_feedback_private_order = $config_ticket_resolved_feedback_private_order, config_ticket_resolved_feedback_private_button_color = '$config_ticket_resolved_feedback_private_button_color' WHERE company_id = 1");

    mysqli_query($mysqli, "UPDATE settings SET config_ticket_inbound_cc_watcher_mode = '$config_ticket_inbound_cc_watcher_mode', config_ticket_watcher_reply_type = '$config_ticket_watcher_reply_type', config_ticket_initial_history_enable = $config_ticket_initial_history_enable, config_ticket_mail_queue_history_enable = $config_ticket_mail_queue_history_enable, config_ticket_mail_queue_watcher_cc_enable = $config_ticket_mail_queue_watcher_cc_enable WHERE company_id = 1");

    logAction("Settings", "Edit", "$session_name edited ticket settings");

    flash_alert("Ticket Settings updated");

    redirect();

}
