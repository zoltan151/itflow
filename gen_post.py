from pathlib import Path
base=Path('/mnt/data/v24424_work')
items = [
('cron_success',1,0,0,0),('cron_failure',1,1,0,1),('update_available',1,1,0,0),('update_success',1,0,0,0),('update_failure',1,1,0,1),('system',1,0,0,0),('backup_success',1,0,0,0),('backup_failure',1,1,0,1),('email_parser_health',1,1,0,1),('mail_queue_health',1,1,0,1),('domain_refresh_success',1,0,0,0),('domain_refresh_failure',1,1,0,1),('certificate_refresh_success',1,0,0,0),('certificate_refresh_failure',1,1,0,1),('security',1,1,0,0),('admin',1,1,0,0),('api_key',1,1,0,0),('domain_expire',1,1,1,1),('certificate_expire',1,1,1,1),('asset_warranty_expire',1,1,1,1),('ticket',1,0,0,0),('pending_ticket',1,1,0,0),('recurring_ticket',1,0,0,0),('task',1,0,0,0),('ticket_sla',1,1,0,1),('ticket_reopened',1,1,0,0),('high_priority_ticket',1,1,0,1),('billing',1,0,1,0),('payment_failure',1,1,0,0),('autopay_failure',1,1,0,0),('quote',1,1,1,0),('mail_failure',1,1,0,0)]
app_prefix={'cron_success':'config_app_notify_cron_success_enable','cron_failure':'config_app_notify_cron_failure_enable','update_available':'config_app_notify_update_available_enable','update_success':'config_app_notify_update_success_enable','update_failure':'config_app_notify_update_failure_enable','system':'config_app_notify_system_enable','backup_success':'config_app_notify_backup_success_enable','backup_failure':'config_app_notify_backup_failure_enable','email_parser_health':'config_app_notify_email_parser_health_enable','mail_queue_health':'config_app_notify_mail_queue_health_enable','domain_refresh_success':'config_app_notify_domain_refresh_success_enable','domain_refresh_failure':'config_app_notify_domain_refresh_failure_enable','certificate_refresh_success':'config_app_notify_certificate_refresh_success_enable','certificate_refresh_failure':'config_app_notify_certificate_refresh_failure_enable','security':'config_app_notify_security_enable','admin':'config_app_notify_admin_enable','api_key':'config_app_notify_api_key_enable','domain_expire':'config_app_notify_domain_expire_enable','certificate_expire':'config_app_notify_certificate_expire_enable','asset_warranty_expire':'config_app_notify_asset_warranty_expire_enable','ticket':'config_app_notify_ticket_enable','pending_ticket':'config_app_notify_pending_ticket_enable','recurring_ticket':'config_app_notify_recurring_ticket_enable','task':'config_app_notify_task_enable','ticket_sla':'config_app_notify_ticket_sla_enable','ticket_reopened':'config_app_notify_ticket_reopened_enable','high_priority_ticket':'config_app_notify_high_priority_ticket_enable','billing':'config_app_notify_billing_enable','payment_failure':'config_app_notify_payment_failure_enable','autopay_failure':'config_app_notify_autopay_failure_enable','quote':'config_app_notify_quote_enable','mail_failure':'config_app_notify_mail_failure_enable'}
assign=[]; columns=[]
for suffix,app,tech,client,ticket in items:
    if app:
        col=app_prefix[suffix]; assign.append(f"    ${col} = intval($_POST['{col}'] ?? 0);"); columns.append(col)
    if tech:
        col=f"config_tech_email_notify_{suffix}_enable"; assign.append(f"    ${col} = intval($_POST['{col}'] ?? 0);"); columns.append(col)
    if client:
        col=f"config_client_email_notify_{suffix}_enable"; assign.append(f"    ${col} = intval($_POST['{col}'] ?? 0);"); columns.append(col)
    if ticket:
        col=f"config_create_ticket_notify_{suffix}_enable"; assign.append(f"    ${col} = intval($_POST['{col}'] ?? 0);"); columns.append(col)
seen=set(); unique=[]
for c in columns:
    if c not in seen:
        unique.append(c); seen.add(c)
columns=unique
extra_assign = """
    $config_notification_domain_expire_days = notificationSanitizeDaysCsv($_POST['config_notification_domain_expire_days'] ?? '45,7,1');
    $config_notification_certificate_expire_days = notificationSanitizeDaysCsv($_POST['config_notification_certificate_expire_days'] ?? '45,7,1');
    $config_notification_asset_warranty_expire_days = notificationSanitizeDaysCsv($_POST['config_notification_asset_warranty_expire_days'] ?? '45,7,1');
    $config_notification_tech_email_recipients = mysqli_real_escape_string($mysqli, trim($_POST['config_notification_tech_email_recipients'] ?? ''));
"""
update_lines=[
"        config_send_invoice_reminders = $config_send_invoice_reminders",
"        config_recurring_auto_send_invoice = $config_recurring_auto_send_invoice",
"        config_enable_cron = $config_enable_cron",
"        config_enable_alert_domain_expire = $config_enable_alert_domain_expire",
"        config_ticket_client_general_notifications = $config_ticket_client_general_notifications",
"        config_app_notifications_enable = $config_app_notifications_enable",
"        config_notification_domain_expire_days = '$config_notification_domain_expire_days'",
"        config_notification_certificate_expire_days = '$config_notification_certificate_expire_days'",
"        config_notification_asset_warranty_expire_days = '$config_notification_asset_warranty_expire_days'",
"        config_notification_tech_email_recipients = '$config_notification_tech_email_recipients'",
"        config_app_notify_mail_queue_backlog_threshold = $config_app_notify_mail_queue_backlog_threshold",
]
for c in columns:
    if c!='config_app_notify_mail_queue_backlog_threshold': update_lines.append(f"        {c} = ${c}")
content = """<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_notification_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $config_enable_cron = intval($_POST['config_enable_cron'] ?? 0);
    $config_send_invoice_reminders = intval($_POST['config_send_invoice_reminders'] ?? 0);
    $config_recurring_auto_send_invoice = intval($_POST['config_recurring_auto_send_invoice'] ?? 0);
    $config_ticket_client_general_notifications = intval($_POST['config_ticket_client_general_notifications'] ?? 0);
    $config_app_notifications_enable = intval($_POST['config_app_notifications_enable'] ?? 0);
    $config_app_notify_mail_queue_backlog_threshold = max(1, intval($_POST['config_app_notify_mail_queue_backlog_threshold'] ?? 50));
""" + "\n".join(assign) + "\n" + extra_assign + """
    // Keep the legacy domain-expiry setting in sync with the new category toggle.
    $config_enable_alert_domain_expire = $config_app_notify_domain_expire_enable;

    mysqli_query($mysqli,"UPDATE settings SET
""" + ",\n".join(update_lines) + """
        WHERE company_id = 1");

    logAction("Settings", "Edit", "$session_name edited notification settings");

    flash_alert("Notification Settings updated");

    redirect();

}
"""
(base/'admin/post/settings_notification.php').write_text(content)
print(len(columns),'columns')
