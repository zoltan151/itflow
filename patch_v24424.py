from pathlib import Path
base=Path('/mnt/data/v24424_work')
# version
p=base/'includes/database_version.php'
s=p.read_text(); s=s.replace('2.4.4.23','2.4.4.24'); p.write_text(s)
# load global settings add vars after mail queue threshold
p=base/'includes/load_global_settings.php'
s=p.read_text()
insert="""$config_notification_domain_expire_days = $row['config_notification_domain_expire_days'] ?? '45,7,1';
$config_notification_certificate_expire_days = $row['config_notification_certificate_expire_days'] ?? '45,7,1';
$config_notification_asset_warranty_expire_days = $row['config_notification_asset_warranty_expire_days'] ?? '45,7,1';
$config_notification_tech_email_recipients = $row['config_notification_tech_email_recipients'] ?? '';

// Matrix channel controls - Tech Email Notify / Client Email Notify / Create Ticket
$config_tech_email_notify_cron_failure_enable = intval($row['config_tech_email_notify_cron_failure_enable'] ?? 0);
$config_tech_email_notify_update_failure_enable = intval($row['config_tech_email_notify_update_failure_enable'] ?? 0);
$config_tech_email_notify_backup_failure_enable = intval($row['config_tech_email_notify_backup_failure_enable'] ?? 0);
$config_tech_email_notify_email_parser_health_enable = intval($row['config_tech_email_notify_email_parser_health_enable'] ?? 0);
$config_tech_email_notify_mail_queue_health_enable = intval($row['config_tech_email_notify_mail_queue_health_enable'] ?? 0);
$config_tech_email_notify_domain_refresh_failure_enable = intval($row['config_tech_email_notify_domain_refresh_failure_enable'] ?? 0);
$config_tech_email_notify_certificate_refresh_failure_enable = intval($row['config_tech_email_notify_certificate_refresh_failure_enable'] ?? 0);
$config_tech_email_notify_domain_expire_enable = intval($row['config_tech_email_notify_domain_expire_enable'] ?? 0);
$config_tech_email_notify_certificate_expire_enable = intval($row['config_tech_email_notify_certificate_expire_enable'] ?? 0);
$config_tech_email_notify_asset_warranty_expire_enable = intval($row['config_tech_email_notify_asset_warranty_expire_enable'] ?? 0);
$config_tech_email_notify_pending_ticket_enable = intval($row['config_tech_email_notify_pending_ticket_enable'] ?? 0);
$config_tech_email_notify_ticket_sla_enable = intval($row['config_tech_email_notify_ticket_sla_enable'] ?? 0);
$config_tech_email_notify_ticket_reopened_enable = intval($row['config_tech_email_notify_ticket_reopened_enable'] ?? 0);
$config_tech_email_notify_high_priority_ticket_enable = intval($row['config_tech_email_notify_high_priority_ticket_enable'] ?? 0);
$config_tech_email_notify_payment_failure_enable = intval($row['config_tech_email_notify_payment_failure_enable'] ?? 0);
$config_tech_email_notify_autopay_failure_enable = intval($row['config_tech_email_notify_autopay_failure_enable'] ?? 0);
$config_tech_email_notify_quote_enable = intval($row['config_tech_email_notify_quote_enable'] ?? 0);
$config_tech_email_notify_mail_failure_enable = intval($row['config_tech_email_notify_mail_failure_enable'] ?? 0);

$config_client_email_notify_domain_expire_enable = intval($row['config_client_email_notify_domain_expire_enable'] ?? 0);
$config_client_email_notify_certificate_expire_enable = intval($row['config_client_email_notify_certificate_expire_enable'] ?? 0);
$config_client_email_notify_asset_warranty_expire_enable = intval($row['config_client_email_notify_asset_warranty_expire_enable'] ?? 0);
$config_client_email_notify_quote_enable = intval($row['config_client_email_notify_quote_enable'] ?? 0);
$config_client_email_notify_billing_enable = intval($row['config_client_email_notify_billing_enable'] ?? 0);

$config_create_ticket_notify_cron_failure_enable = intval($row['config_create_ticket_notify_cron_failure_enable'] ?? 0);
$config_create_ticket_notify_update_failure_enable = intval($row['config_create_ticket_notify_update_failure_enable'] ?? 0);
$config_create_ticket_notify_backup_failure_enable = intval($row['config_create_ticket_notify_backup_failure_enable'] ?? 0);
$config_create_ticket_notify_email_parser_health_enable = intval($row['config_create_ticket_notify_email_parser_health_enable'] ?? 0);
$config_create_ticket_notify_mail_queue_health_enable = intval($row['config_create_ticket_notify_mail_queue_health_enable'] ?? 0);
$config_create_ticket_notify_domain_refresh_failure_enable = intval($row['config_create_ticket_notify_domain_refresh_failure_enable'] ?? 0);
$config_create_ticket_notify_certificate_refresh_failure_enable = intval($row['config_create_ticket_notify_certificate_refresh_failure_enable'] ?? 0);
$config_create_ticket_notify_domain_expire_enable = intval($row['config_create_ticket_notify_domain_expire_enable'] ?? 0);
$config_create_ticket_notify_certificate_expire_enable = intval($row['config_create_ticket_notify_certificate_expire_enable'] ?? 0);
$config_create_ticket_notify_asset_warranty_expire_enable = intval($row['config_create_ticket_notify_asset_warranty_expire_enable'] ?? 0);
$config_create_ticket_notify_ticket_sla_enable = intval($row['config_create_ticket_notify_ticket_sla_enable'] ?? 0);
$config_create_ticket_notify_high_priority_ticket_enable = intval($row['config_create_ticket_notify_high_priority_ticket_enable'] ?? 0);
"""
needle="$config_app_notify_mail_queue_backlog_threshold = intval($row['config_app_notify_mail_queue_backlog_threshold'] ?? 50);\n"
if insert.split('\n')[0] not in s:
    s=s.replace(needle, needle+insert)
p.write_text(s)
