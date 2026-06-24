<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_notification_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $config_enable_cron = intval($_POST['config_enable_cron'] ?? 0);
    $config_send_invoice_reminders = intval($_POST['config_send_invoice_reminders'] ?? 0);
    $config_recurring_auto_send_invoice = intval($_POST['config_recurring_auto_send_invoice'] ?? 0);
    $config_ticket_client_general_notifications = intval($_POST['config_ticket_client_general_notifications'] ?? 0);
    $config_app_notifications_enable = intval($_POST['config_app_notifications_enable'] ?? 0);
    $config_app_notify_mail_queue_backlog_threshold = max(1, intval($_POST['config_app_notify_mail_queue_backlog_threshold'] ?? 50));
    $config_app_notify_cron_success_enable = intval($_POST['config_app_notify_cron_success_enable'] ?? 0);
    $config_app_notify_cron_failure_enable = intval($_POST['config_app_notify_cron_failure_enable'] ?? 0);
    $config_tech_email_notify_cron_failure_enable = intval($_POST['config_tech_email_notify_cron_failure_enable'] ?? 0);
    $config_create_ticket_notify_cron_failure_enable = intval($_POST['config_create_ticket_notify_cron_failure_enable'] ?? 0);
    $config_app_notify_update_available_enable = intval($_POST['config_app_notify_update_available_enable'] ?? 0);
    $config_tech_email_notify_update_available_enable = intval($_POST['config_tech_email_notify_update_available_enable'] ?? 0);
    $config_app_notify_update_success_enable = intval($_POST['config_app_notify_update_success_enable'] ?? 0);
    $config_app_notify_update_failure_enable = intval($_POST['config_app_notify_update_failure_enable'] ?? 0);
    $config_tech_email_notify_update_failure_enable = intval($_POST['config_tech_email_notify_update_failure_enable'] ?? 0);
    $config_create_ticket_notify_update_failure_enable = intval($_POST['config_create_ticket_notify_update_failure_enable'] ?? 0);
    $config_app_notify_system_enable = intval($_POST['config_app_notify_system_enable'] ?? 0);
    $config_app_notify_backup_success_enable = intval($_POST['config_app_notify_backup_success_enable'] ?? 0);
    $config_app_notify_backup_failure_enable = intval($_POST['config_app_notify_backup_failure_enable'] ?? 0);
    $config_tech_email_notify_backup_failure_enable = intval($_POST['config_tech_email_notify_backup_failure_enable'] ?? 0);
    $config_create_ticket_notify_backup_failure_enable = intval($_POST['config_create_ticket_notify_backup_failure_enable'] ?? 0);
    $config_app_notify_email_parser_health_enable = intval($_POST['config_app_notify_email_parser_health_enable'] ?? 0);
    $config_tech_email_notify_email_parser_health_enable = intval($_POST['config_tech_email_notify_email_parser_health_enable'] ?? 0);
    $config_create_ticket_notify_email_parser_health_enable = intval($_POST['config_create_ticket_notify_email_parser_health_enable'] ?? 0);
    $config_app_notify_mail_queue_health_enable = intval($_POST['config_app_notify_mail_queue_health_enable'] ?? 0);
    $config_tech_email_notify_mail_queue_health_enable = intval($_POST['config_tech_email_notify_mail_queue_health_enable'] ?? 0);
    $config_create_ticket_notify_mail_queue_health_enable = intval($_POST['config_create_ticket_notify_mail_queue_health_enable'] ?? 0);
    $config_app_notify_domain_refresh_success_enable = intval($_POST['config_app_notify_domain_refresh_success_enable'] ?? 0);
    $config_app_notify_domain_refresh_failure_enable = intval($_POST['config_app_notify_domain_refresh_failure_enable'] ?? 0);
    $config_tech_email_notify_domain_refresh_failure_enable = intval($_POST['config_tech_email_notify_domain_refresh_failure_enable'] ?? 0);
    $config_create_ticket_notify_domain_refresh_failure_enable = intval($_POST['config_create_ticket_notify_domain_refresh_failure_enable'] ?? 0);
    $config_app_notify_certificate_refresh_success_enable = intval($_POST['config_app_notify_certificate_refresh_success_enable'] ?? 0);
    $config_app_notify_certificate_refresh_failure_enable = intval($_POST['config_app_notify_certificate_refresh_failure_enable'] ?? 0);
    $config_tech_email_notify_certificate_refresh_failure_enable = intval($_POST['config_tech_email_notify_certificate_refresh_failure_enable'] ?? 0);
    $config_create_ticket_notify_certificate_refresh_failure_enable = intval($_POST['config_create_ticket_notify_certificate_refresh_failure_enable'] ?? 0);
    $config_app_notify_security_enable = intval($_POST['config_app_notify_security_enable'] ?? 0);
    $config_tech_email_notify_security_enable = intval($_POST['config_tech_email_notify_security_enable'] ?? 0);
    $config_app_notify_admin_enable = intval($_POST['config_app_notify_admin_enable'] ?? 0);
    $config_tech_email_notify_admin_enable = intval($_POST['config_tech_email_notify_admin_enable'] ?? 0);
    $config_app_notify_api_key_enable = intval($_POST['config_app_notify_api_key_enable'] ?? 0);
    $config_tech_email_notify_api_key_enable = intval($_POST['config_tech_email_notify_api_key_enable'] ?? 0);
    $config_app_notify_domain_expire_enable = intval($_POST['config_app_notify_domain_expire_enable'] ?? 0);
    $config_tech_email_notify_domain_expire_enable = intval($_POST['config_tech_email_notify_domain_expire_enable'] ?? 0);
    $config_client_email_notify_domain_expire_enable = intval($_POST['config_client_email_notify_domain_expire_enable'] ?? 0);
    $config_create_ticket_notify_domain_expire_enable = intval($_POST['config_create_ticket_notify_domain_expire_enable'] ?? 0);
    $config_app_notify_certificate_expire_enable = intval($_POST['config_app_notify_certificate_expire_enable'] ?? 0);
    $config_tech_email_notify_certificate_expire_enable = intval($_POST['config_tech_email_notify_certificate_expire_enable'] ?? 0);
    $config_client_email_notify_certificate_expire_enable = intval($_POST['config_client_email_notify_certificate_expire_enable'] ?? 0);
    $config_create_ticket_notify_certificate_expire_enable = intval($_POST['config_create_ticket_notify_certificate_expire_enable'] ?? 0);
    $config_app_notify_asset_warranty_expire_enable = intval($_POST['config_app_notify_asset_warranty_expire_enable'] ?? 0);
    $config_tech_email_notify_asset_warranty_expire_enable = intval($_POST['config_tech_email_notify_asset_warranty_expire_enable'] ?? 0);
    $config_client_email_notify_asset_warranty_expire_enable = intval($_POST['config_client_email_notify_asset_warranty_expire_enable'] ?? 0);
    $config_create_ticket_notify_asset_warranty_expire_enable = intval($_POST['config_create_ticket_notify_asset_warranty_expire_enable'] ?? 0);
    $config_app_notify_ticket_enable = intval($_POST['config_app_notify_ticket_enable'] ?? 0);
    $config_app_notify_pending_ticket_enable = intval($_POST['config_app_notify_pending_ticket_enable'] ?? 0);
    $config_tech_email_notify_pending_ticket_enable = intval($_POST['config_tech_email_notify_pending_ticket_enable'] ?? 0);
    $config_app_notify_recurring_ticket_enable = intval($_POST['config_app_notify_recurring_ticket_enable'] ?? 0);
    $config_app_notify_task_enable = intval($_POST['config_app_notify_task_enable'] ?? 0);
    $config_app_notify_ticket_sla_enable = intval($_POST['config_app_notify_ticket_sla_enable'] ?? 0);
    $config_tech_email_notify_ticket_sla_enable = intval($_POST['config_tech_email_notify_ticket_sla_enable'] ?? 0);
    $config_create_ticket_notify_ticket_sla_enable = intval($_POST['config_create_ticket_notify_ticket_sla_enable'] ?? 0);
    $config_app_notify_ticket_reopened_enable = intval($_POST['config_app_notify_ticket_reopened_enable'] ?? 0);
    $config_tech_email_notify_ticket_reopened_enable = intval($_POST['config_tech_email_notify_ticket_reopened_enable'] ?? 0);
    $config_app_notify_high_priority_ticket_enable = intval($_POST['config_app_notify_high_priority_ticket_enable'] ?? 0);
    $config_tech_email_notify_high_priority_ticket_enable = intval($_POST['config_tech_email_notify_high_priority_ticket_enable'] ?? 0);
    $config_create_ticket_notify_high_priority_ticket_enable = intval($_POST['config_create_ticket_notify_high_priority_ticket_enable'] ?? 0);
    $config_app_notify_billing_enable = intval($_POST['config_app_notify_billing_enable'] ?? 0);
    $config_client_email_notify_billing_enable = intval($_POST['config_client_email_notify_billing_enable'] ?? 0);
    $config_app_notify_payment_failure_enable = intval($_POST['config_app_notify_payment_failure_enable'] ?? 0);
    $config_tech_email_notify_payment_failure_enable = intval($_POST['config_tech_email_notify_payment_failure_enable'] ?? 0);
    $config_app_notify_autopay_failure_enable = intval($_POST['config_app_notify_autopay_failure_enable'] ?? 0);
    $config_tech_email_notify_autopay_failure_enable = intval($_POST['config_tech_email_notify_autopay_failure_enable'] ?? 0);
    $config_app_notify_quote_enable = intval($_POST['config_app_notify_quote_enable'] ?? 0);
    $config_tech_email_notify_quote_enable = intval($_POST['config_tech_email_notify_quote_enable'] ?? 0);
    $config_client_email_notify_quote_enable = intval($_POST['config_client_email_notify_quote_enable'] ?? 0);
    $config_app_notify_mail_failure_enable = intval($_POST['config_app_notify_mail_failure_enable'] ?? 0);
    $config_tech_email_notify_mail_failure_enable = intval($_POST['config_tech_email_notify_mail_failure_enable'] ?? 0);

    $config_notification_domain_expire_days = notificationSanitizeDaysCsv($_POST['config_notification_domain_expire_days'] ?? '45,7,1');
    $config_notification_certificate_expire_days = notificationSanitizeDaysCsv($_POST['config_notification_certificate_expire_days'] ?? '45,7,1');
    $config_notification_asset_warranty_expire_days = notificationSanitizeDaysCsv($_POST['config_notification_asset_warranty_expire_days'] ?? '45,7,1');
    $config_notification_tech_email_recipients = mysqli_real_escape_string($mysqli, trim($_POST['config_notification_tech_email_recipients'] ?? ''));

    // Keep the legacy domain-expiry setting in sync with the new category toggle.
    $config_enable_alert_domain_expire = $config_app_notify_domain_expire_enable;

    mysqli_query($mysqli,"UPDATE settings SET
        config_send_invoice_reminders = $config_send_invoice_reminders,
        config_recurring_auto_send_invoice = $config_recurring_auto_send_invoice,
        config_enable_cron = $config_enable_cron,
        config_enable_alert_domain_expire = $config_enable_alert_domain_expire,
        config_ticket_client_general_notifications = $config_ticket_client_general_notifications,
        config_app_notifications_enable = $config_app_notifications_enable,
        config_notification_domain_expire_days = '$config_notification_domain_expire_days',
        config_notification_certificate_expire_days = '$config_notification_certificate_expire_days',
        config_notification_asset_warranty_expire_days = '$config_notification_asset_warranty_expire_days',
        config_notification_tech_email_recipients = '$config_notification_tech_email_recipients',
        config_app_notify_mail_queue_backlog_threshold = $config_app_notify_mail_queue_backlog_threshold,
        config_app_notify_cron_success_enable = $config_app_notify_cron_success_enable,
        config_app_notify_cron_failure_enable = $config_app_notify_cron_failure_enable,
        config_tech_email_notify_cron_failure_enable = $config_tech_email_notify_cron_failure_enable,
        config_create_ticket_notify_cron_failure_enable = $config_create_ticket_notify_cron_failure_enable,
        config_app_notify_update_available_enable = $config_app_notify_update_available_enable,
        config_tech_email_notify_update_available_enable = $config_tech_email_notify_update_available_enable,
        config_app_notify_update_success_enable = $config_app_notify_update_success_enable,
        config_app_notify_update_failure_enable = $config_app_notify_update_failure_enable,
        config_tech_email_notify_update_failure_enable = $config_tech_email_notify_update_failure_enable,
        config_create_ticket_notify_update_failure_enable = $config_create_ticket_notify_update_failure_enable,
        config_app_notify_system_enable = $config_app_notify_system_enable,
        config_app_notify_backup_success_enable = $config_app_notify_backup_success_enable,
        config_app_notify_backup_failure_enable = $config_app_notify_backup_failure_enable,
        config_tech_email_notify_backup_failure_enable = $config_tech_email_notify_backup_failure_enable,
        config_create_ticket_notify_backup_failure_enable = $config_create_ticket_notify_backup_failure_enable,
        config_app_notify_email_parser_health_enable = $config_app_notify_email_parser_health_enable,
        config_tech_email_notify_email_parser_health_enable = $config_tech_email_notify_email_parser_health_enable,
        config_create_ticket_notify_email_parser_health_enable = $config_create_ticket_notify_email_parser_health_enable,
        config_app_notify_mail_queue_health_enable = $config_app_notify_mail_queue_health_enable,
        config_tech_email_notify_mail_queue_health_enable = $config_tech_email_notify_mail_queue_health_enable,
        config_create_ticket_notify_mail_queue_health_enable = $config_create_ticket_notify_mail_queue_health_enable,
        config_app_notify_domain_refresh_success_enable = $config_app_notify_domain_refresh_success_enable,
        config_app_notify_domain_refresh_failure_enable = $config_app_notify_domain_refresh_failure_enable,
        config_tech_email_notify_domain_refresh_failure_enable = $config_tech_email_notify_domain_refresh_failure_enable,
        config_create_ticket_notify_domain_refresh_failure_enable = $config_create_ticket_notify_domain_refresh_failure_enable,
        config_app_notify_certificate_refresh_success_enable = $config_app_notify_certificate_refresh_success_enable,
        config_app_notify_certificate_refresh_failure_enable = $config_app_notify_certificate_refresh_failure_enable,
        config_tech_email_notify_certificate_refresh_failure_enable = $config_tech_email_notify_certificate_refresh_failure_enable,
        config_create_ticket_notify_certificate_refresh_failure_enable = $config_create_ticket_notify_certificate_refresh_failure_enable,
        config_app_notify_security_enable = $config_app_notify_security_enable,
        config_tech_email_notify_security_enable = $config_tech_email_notify_security_enable,
        config_app_notify_admin_enable = $config_app_notify_admin_enable,
        config_tech_email_notify_admin_enable = $config_tech_email_notify_admin_enable,
        config_app_notify_api_key_enable = $config_app_notify_api_key_enable,
        config_tech_email_notify_api_key_enable = $config_tech_email_notify_api_key_enable,
        config_app_notify_domain_expire_enable = $config_app_notify_domain_expire_enable,
        config_tech_email_notify_domain_expire_enable = $config_tech_email_notify_domain_expire_enable,
        config_client_email_notify_domain_expire_enable = $config_client_email_notify_domain_expire_enable,
        config_create_ticket_notify_domain_expire_enable = $config_create_ticket_notify_domain_expire_enable,
        config_app_notify_certificate_expire_enable = $config_app_notify_certificate_expire_enable,
        config_tech_email_notify_certificate_expire_enable = $config_tech_email_notify_certificate_expire_enable,
        config_client_email_notify_certificate_expire_enable = $config_client_email_notify_certificate_expire_enable,
        config_create_ticket_notify_certificate_expire_enable = $config_create_ticket_notify_certificate_expire_enable,
        config_app_notify_asset_warranty_expire_enable = $config_app_notify_asset_warranty_expire_enable,
        config_tech_email_notify_asset_warranty_expire_enable = $config_tech_email_notify_asset_warranty_expire_enable,
        config_client_email_notify_asset_warranty_expire_enable = $config_client_email_notify_asset_warranty_expire_enable,
        config_create_ticket_notify_asset_warranty_expire_enable = $config_create_ticket_notify_asset_warranty_expire_enable,
        config_app_notify_ticket_enable = $config_app_notify_ticket_enable,
        config_app_notify_pending_ticket_enable = $config_app_notify_pending_ticket_enable,
        config_tech_email_notify_pending_ticket_enable = $config_tech_email_notify_pending_ticket_enable,
        config_app_notify_recurring_ticket_enable = $config_app_notify_recurring_ticket_enable,
        config_app_notify_task_enable = $config_app_notify_task_enable,
        config_app_notify_ticket_sla_enable = $config_app_notify_ticket_sla_enable,
        config_tech_email_notify_ticket_sla_enable = $config_tech_email_notify_ticket_sla_enable,
        config_create_ticket_notify_ticket_sla_enable = $config_create_ticket_notify_ticket_sla_enable,
        config_app_notify_ticket_reopened_enable = $config_app_notify_ticket_reopened_enable,
        config_tech_email_notify_ticket_reopened_enable = $config_tech_email_notify_ticket_reopened_enable,
        config_app_notify_high_priority_ticket_enable = $config_app_notify_high_priority_ticket_enable,
        config_tech_email_notify_high_priority_ticket_enable = $config_tech_email_notify_high_priority_ticket_enable,
        config_create_ticket_notify_high_priority_ticket_enable = $config_create_ticket_notify_high_priority_ticket_enable,
        config_app_notify_billing_enable = $config_app_notify_billing_enable,
        config_client_email_notify_billing_enable = $config_client_email_notify_billing_enable,
        config_app_notify_payment_failure_enable = $config_app_notify_payment_failure_enable,
        config_tech_email_notify_payment_failure_enable = $config_tech_email_notify_payment_failure_enable,
        config_app_notify_autopay_failure_enable = $config_app_notify_autopay_failure_enable,
        config_tech_email_notify_autopay_failure_enable = $config_tech_email_notify_autopay_failure_enable,
        config_app_notify_quote_enable = $config_app_notify_quote_enable,
        config_tech_email_notify_quote_enable = $config_tech_email_notify_quote_enable,
        config_client_email_notify_quote_enable = $config_client_email_notify_quote_enable,
        config_app_notify_mail_failure_enable = $config_app_notify_mail_failure_enable,
        config_tech_email_notify_mail_failure_enable = $config_tech_email_notify_mail_failure_enable
        WHERE company_id = 1");

    logAction("Settings", "Edit", "$session_name edited notification settings");

    flash_alert("Notification Settings updated");

    redirect();

}
