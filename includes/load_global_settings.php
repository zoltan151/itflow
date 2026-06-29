<?php

// Query Settings
$sql_settings = mysqli_query($mysqli, "SELECT * FROM settings WHERE company_id = 1");
$row = mysqli_fetch_assoc($sql_settings);

// Database version
DEFINE("CURRENT_DATABASE_VERSION", $row['config_current_database_version']);

// Microsoft OAuth
$config_azure_client_id = $row['config_azure_client_id'];
$config_azure_client_secret = $row['config_azure_client_secret'];

// Mail - SMTP
$config_smtp_provider = $row['config_smtp_provider'];
$config_smtp_host = $row['config_smtp_host'];
$config_smtp_port = intval($row['config_smtp_port']);
$config_smtp_encryption = $row['config_smtp_encryption'];
$config_smtp_username = $row['config_smtp_username'];
$config_smtp_password = $row['config_smtp_password'];
$config_mail_from_email = $row['config_mail_from_email'];
$config_mail_from_name = $row['config_mail_from_name'];

// Mail - IMAP
$config_imap_provider = $row['config_imap_provider'];
$config_imap_host = $row['config_imap_host'];
$config_imap_port = intval($row['config_imap_port']);
$config_imap_encryption = $row['config_imap_encryption'];
$config_imap_username = $row['config_imap_username'];
$config_imap_password = $row['config_imap_password'];

// Mail OAUTH2
$config_mail_oauth_client_id = $row['config_mail_oauth_client_id'];
$config_mail_oauth_client_secret = $row['config_mail_oauth_client_secret'];
$config_mail_oauth_tenant_id = $row['config_mail_oauth_tenant_id'];
$config_mail_oauth_refresh_token = $row['config_mail_oauth_refresh_token'];
$config_mail_oauth_access_token = $row['config_mail_oauth_access_token'];
$config_mail_oauth_access_token_expires_at = $row['config_mail_oauth_access_token_expires_at'];

// Defaults
$config_start_page = $row['config_start_page'] ?? 'clients.php';
$config_default_transfer_from_account = intval($row['config_default_transfer_from_account']);
$config_default_transfer_to_account = intval($row['config_default_transfer_to_account']);
$config_default_payment_account = intval($row['config_default_payment_account']);
$config_default_expense_account = intval($row['config_default_expense_account']);
$config_default_payment_method = $row['config_default_payment_method'];
$config_default_expense_payment_method = $row['config_default_expense_payment_method'];
$config_default_calendar = intval($row['config_default_calendar']);
$config_default_net_terms = intval($row['config_default_net_terms']);
$config_default_hourly_rate = floatval($row['config_default_hourly_rate']);

// Internal Workspace
$config_internal_workspace_enable = intval($row['config_internal_workspace_enable'] ?? 0);
$config_internal_client_id = intval($row['config_internal_client_id'] ?? 0);
$config_internal_workspace_name = $row['config_internal_workspace_name'] ?? 'Internal';
$config_internal_hide_from_clients = intval($row['config_internal_hide_from_clients'] ?? 1);

// Invoice
$config_invoice_prefix = $row['config_invoice_prefix'];
$config_invoice_next_number = intval($row['config_invoice_next_number']);
$config_invoice_footer = $row['config_invoice_footer'];
$config_invoice_from_name = $row['config_invoice_from_name'];
$config_invoice_from_email = $row['config_invoice_from_email'];
$config_invoice_late_fee_enable = intval($row['config_invoice_late_fee_enable']);
$config_invoice_late_fee_percent = floatval($row['config_invoice_late_fee_percent']);
$config_invoice_paid_notification_email = $row['config_invoice_paid_notification_email'];
$config_invoice_show_tax_id = intval($row['config_invoice_show_tax_id']);

// Recurring Invoices
$config_recurring_invoice_prefix = $row['config_recurring_invoice_prefix'];
$config_recurring_invoice_next_number = intval($row['config_recurring_invoice_next_number']);

// Quotes
$config_quote_prefix = $row['config_quote_prefix'];
$config_quote_next_number = intval($row['config_quote_next_number']);
$config_quote_footer = $row['config_quote_footer'];
$config_quote_from_name = $row['config_quote_from_name'];
$config_quote_from_email = $row['config_quote_from_email'];
$config_quote_notification_email = $row['config_quote_notification_email'];

// Projects
$config_project_prefix = $row['config_project_prefix'];
$config_project_next_number = intval($row['config_project_next_number']);

// Tickets
$config_ticket_prefix = $row['config_ticket_prefix'];
$config_ticket_next_number = intval($row['config_ticket_next_number']);
$config_ticket_from_name = $row['config_ticket_from_name'];
$config_ticket_from_email = $row['config_ticket_from_email'];
$config_ticket_email_parse = intval($row['config_ticket_email_parse']);
$config_ticket_email_parse_unknown_senders = intval($row['config_ticket_email_parse_unknown_senders']);
$config_ticket_client_general_notifications = intval($row['config_ticket_client_general_notifications']);
$config_ticket_autoclose_hours = intval($row['config_ticket_autoclose_hours']);
$config_ticket_new_ticket_notification_email = $row['config_ticket_new_ticket_notification_email'];
$config_ticket_attention_notification_email = $row['config_ticket_attention_notification_email'] ?? ($config_ticket_new_ticket_notification_email ?? '');
$config_ticket_agent_notification_route_from_emails = $row['config_ticket_agent_notification_route_from_emails'] ?? '';
$config_ticket_agent_notification_route_to_email = $row['config_ticket_agent_notification_route_to_email'] ?? '';
$config_ticket_reply_target_status_id = intval($row['config_ticket_reply_target_status_id'] ?? 0);
$config_ticket_inbound_cc_watcher_mode = $row['config_ticket_inbound_cc_watcher_mode'] ?? 'all';
$config_ticket_watcher_reply_type = $row['config_ticket_watcher_reply_type'] ?? 'client';
$config_ticket_initial_history_enable = intval($row['config_ticket_initial_history_enable'] ?? 1);
$config_ticket_mail_queue_history_enable = intval($row['config_ticket_mail_queue_history_enable'] ?? 1);
$config_ticket_mail_queue_watcher_cc_enable = intval($row['config_ticket_mail_queue_watcher_cc_enable'] ?? 1);
$config_ticket_default_billable = intval($row['config_ticket_default_billable']);
$config_ticket_default_view = intval($row['config_ticket_default_view']);
$config_ticket_moving_columns = intval($row['config_ticket_moving_columns']);
$config_ticket_ordering = intval($row['config_ticket_ordering']);
$config_ticket_timer_autostart = intval($row['config_ticket_timer_autostart']);
$config_ticket_resolved_feedback_enable = intval($row['config_ticket_resolved_feedback_enable'] ?? 0);
$config_ticket_resolved_feedback_message_enable = intval($row['config_ticket_resolved_feedback_message_enable'] ?? 1);
$config_ticket_resolved_feedback_message = $row['config_ticket_resolved_feedback_message'] ?? '';
$config_ticket_resolved_feedback_message_order = intval($row['config_ticket_resolved_feedback_message_order'] ?? 10);
$config_ticket_resolved_feedback_review_enable = intval($row['config_ticket_resolved_feedback_review_enable'] ?? 1);
$config_ticket_resolved_feedback_review_heading_enable = intval($row['config_ticket_resolved_feedback_review_heading_enable'] ?? 1);
$config_ticket_resolved_feedback_review_heading = $row['config_ticket_resolved_feedback_review_heading'] ?? 'Happy with our service?';
$config_ticket_resolved_feedback_review_message_enable = intval($row['config_ticket_resolved_feedback_review_message_enable'] ?? 1);
$config_ticket_resolved_feedback_review_message = $row['config_ticket_resolved_feedback_review_message'] ?? '';
$config_ticket_resolved_feedback_review_button_enable = intval($row['config_ticket_resolved_feedback_review_button_enable'] ?? 1);
$config_ticket_resolved_feedback_review_url = $row['config_ticket_resolved_feedback_review_url'] ?? '';
$config_ticket_resolved_feedback_review_text = $row['config_ticket_resolved_feedback_review_text'] ?? 'Leave a Review';
$config_ticket_resolved_feedback_review_order = intval($row['config_ticket_resolved_feedback_review_order'] ?? 30);
$config_ticket_resolved_feedback_review_button_color = $row['config_ticket_resolved_feedback_review_button_color'] ?? '#16a34a';
$config_ticket_resolved_feedback_private_enable = intval($row['config_ticket_resolved_feedback_private_enable'] ?? 1);
$config_ticket_resolved_feedback_private_heading_enable = intval($row['config_ticket_resolved_feedback_private_heading_enable'] ?? 1);
$config_ticket_resolved_feedback_private_heading = $row['config_ticket_resolved_feedback_private_heading'] ?? 'Something we can improve?';
$config_ticket_resolved_feedback_private_message_enable = intval($row['config_ticket_resolved_feedback_private_message_enable'] ?? 1);
$config_ticket_resolved_feedback_private_message = $row['config_ticket_resolved_feedback_private_message'] ?? '';
$config_ticket_resolved_feedback_private_button_enable = intval($row['config_ticket_resolved_feedback_private_button_enable'] ?? 1);
$config_ticket_resolved_feedback_private_url = $row['config_ticket_resolved_feedback_private_url'] ?? '';
$config_ticket_resolved_feedback_private_text = $row['config_ticket_resolved_feedback_private_text'] ?? 'Send Private Feedback';
$config_ticket_resolved_feedback_private_order = intval($row['config_ticket_resolved_feedback_private_order'] ?? 20);
$config_ticket_resolved_feedback_private_button_color = $row['config_ticket_resolved_feedback_private_button_color'] ?? '#d97706';

// Cron
$config_enable_cron = intval($row['config_enable_cron']);
// In-app Notifications
$config_app_notifications_enable = intval($row['config_app_notifications_enable'] ?? 0);
$config_app_notify_cron_success_enable = intval($row['config_app_notify_cron_success_enable'] ?? 0);
$config_app_notify_cron_failure_enable = intval($row['config_app_notify_cron_failure_enable'] ?? 0);
$config_app_notify_domain_expire_enable = intval($row['config_app_notify_domain_expire_enable'] ?? 0);
$config_app_notify_certificate_expire_enable = intval($row['config_app_notify_certificate_expire_enable'] ?? 0);
$config_app_notify_asset_warranty_expire_enable = intval($row['config_app_notify_asset_warranty_expire_enable'] ?? 0);
$config_app_notify_pending_ticket_enable = intval($row['config_app_notify_pending_ticket_enable'] ?? 0);
$config_app_notify_ticket_enable = intval($row['config_app_notify_ticket_enable'] ?? 0);
$config_app_notify_recurring_ticket_enable = intval($row['config_app_notify_recurring_ticket_enable'] ?? 0);
$config_app_notify_task_enable = intval($row['config_app_notify_task_enable'] ?? 0);
$config_app_notify_mail_failure_enable = intval($row['config_app_notify_mail_failure_enable'] ?? 0);
$config_app_notify_update_enable = intval($row['config_app_notify_update_enable'] ?? 0);
$config_app_notify_update_available_enable = intval($row['config_app_notify_update_available_enable'] ?? 0);
$config_app_notify_update_success_enable = intval($row['config_app_notify_update_success_enable'] ?? 0);
$config_app_notify_update_failure_enable = intval($row['config_app_notify_update_failure_enable'] ?? 0);
$config_app_notify_billing_enable = intval($row['config_app_notify_billing_enable'] ?? 0);
$config_app_notify_system_enable = intval($row['config_app_notify_system_enable'] ?? 0);
$config_app_notify_email_parser_health_enable = intval($row['config_app_notify_email_parser_health_enable'] ?? 0);
$config_app_notify_mail_queue_health_enable = intval($row['config_app_notify_mail_queue_health_enable'] ?? 0);
$config_app_notify_mail_queue_backlog_threshold = intval($row['config_app_notify_mail_queue_backlog_threshold'] ?? 50);
$config_notification_domain_expire_days = $row['config_notification_domain_expire_days'] ?? '45,7,1';
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
$config_app_notify_domain_refresh_health_enable = intval($row['config_app_notify_domain_refresh_health_enable'] ?? 0);
$config_app_notify_domain_refresh_success_enable = intval($row['config_app_notify_domain_refresh_success_enable'] ?? 0);
$config_app_notify_domain_refresh_failure_enable = intval($row['config_app_notify_domain_refresh_failure_enable'] ?? 0);
$config_app_notify_certificate_refresh_health_enable = intval($row['config_app_notify_certificate_refresh_health_enable'] ?? 0);
$config_app_notify_certificate_refresh_success_enable = intval($row['config_app_notify_certificate_refresh_success_enable'] ?? 0);
$config_app_notify_certificate_refresh_failure_enable = intval($row['config_app_notify_certificate_refresh_failure_enable'] ?? 0);
$config_app_notify_backup_enable = intval($row['config_app_notify_backup_enable'] ?? 0);
$config_app_notify_backup_success_enable = intval($row['config_app_notify_backup_success_enable'] ?? 0);
$config_app_notify_backup_failure_enable = intval($row['config_app_notify_backup_failure_enable'] ?? 0);
$config_app_notify_security_enable = intval($row['config_app_notify_security_enable'] ?? 0);
$config_app_notify_admin_enable = intval($row['config_app_notify_admin_enable'] ?? 0);
$config_app_notify_ticket_sla_enable = intval($row['config_app_notify_ticket_sla_enable'] ?? 0);
$config_app_notify_ticket_reopened_enable = intval($row['config_app_notify_ticket_reopened_enable'] ?? 0);
$config_app_notify_high_priority_ticket_enable = intval($row['config_app_notify_high_priority_ticket_enable'] ?? 0);
$config_app_notify_payment_failure_enable = intval($row['config_app_notify_payment_failure_enable'] ?? 0);
$config_app_notify_autopay_failure_enable = intval($row['config_app_notify_autopay_failure_enable'] ?? 0);
$config_app_notify_quote_enable = intval($row['config_app_notify_quote_enable'] ?? 0);
$config_app_notify_api_key_enable = intval($row['config_app_notify_api_key_enable'] ?? 0);


// Alerts & Notifications
$config_recurring_auto_send_invoice = intval($row['config_recurring_auto_send_invoice']);
$config_enable_alert_domain_expire = intval($row['config_enable_alert_domain_expire']);
$config_send_invoice_reminders = intval($row['config_send_invoice_reminders']);
$config_invoice_overdue_reminders = intval($row['config_invoice_overdue_reminders']);

// Modules
$config_module_enable_itdoc = intval($row['config_module_enable_itdoc']);
$config_module_enable_ticketing = intval($row['config_module_enable_ticketing']);
$config_module_enable_accounting = intval($row['config_module_enable_accounting']);
$config_client_portal_enable = intval($row['config_client_portal_enable']);

// Login
$config_login_message = $row['config_login_message'];
$config_login_key_required = $row['config_login_key_required'];
$config_login_key_secret = $row['config_login_key_secret'];
$config_login_remember_me_expire = intval($row['config_login_remember_me_expire']);
$config_log_retention = intval($row['config_log_retention']);

// Locale
$config_currency_format = "US_en";
$config_timezone = $row['config_timezone'];
$config_date_format = "M d, Y";
$config_time_format = "g:i A";

// Theme
$config_theme = $row['config_theme'];
$config_sidebar_brand_display = $row['config_sidebar_brand_display'] ?? 'name';
$config_sidebar_brand_background_mode = $row['config_sidebar_brand_background_mode'] ?? 'none';
$config_sidebar_brand_background_color = $row['config_sidebar_brand_background_color'] ?? '#343a40';
$config_sidebar_brand_background_opacity = intval($row['config_sidebar_brand_background_opacity'] ?? 100);
$config_sidebar_brand_layout = $row['config_sidebar_brand_layout'] ?? 'logo_left';
$config_sidebar_brand_logo_size = $row['config_sidebar_brand_logo_size'] ?? 'medium';
$config_sidebar_brand_name_size = $row['config_sidebar_brand_name_size'] ?? 'medium'; // Legacy alias; retained for older DB/settings compatibility.
$config_sidebar_brand_text_size = $row['config_sidebar_brand_text_size'] ?? ($row['config_sidebar_brand_name_size'] ?? 'medium');
$config_sidebar_brand_text_source = $row['config_sidebar_brand_text_source'] ?? 'company';
$config_sidebar_brand_custom_text = $row['config_sidebar_brand_custom_text'] ?? '';
$config_sidebar_brand_text_color_mode = $row['config_sidebar_brand_text_color_mode'] ?? 'default';
$config_sidebar_brand_text_color = $row['config_sidebar_brand_text_color'] ?? '#ffffff';
$config_sidebar_brand_text_color_opacity = intval($row['config_sidebar_brand_text_color_opacity'] ?? 100);

// Telemetry
$config_telemetry = intval($row['config_telemetry']);

// Destructive Deletes
$config_destructive_deletes_enable = intval($row['config_destructive_deletes_enable']);

// White label
$config_whitelabel_enabled = intval($row['config_whitelabel_enabled']);
$config_whitelabel_key = $row['config_whitelabel_key'];


// Select Arrays
$colors_array = array (
    'lightblue',
    'blue',
    'green',
    'cyan',
    'yellow',
    'red',
    'black',
    'gray-dark',
    'gray',
    'light',
    'indigo',
    'navy',
    'purple',
    'fuchsia',
    'pink',
    'maroon',
    'orange',
    'lime',
    'teal',
    'olive'
);

$records_per_page_array = array ('5','10','15','20','30','50','100');

include_once "settings_localization_array.php";

$asset_types_array = array (
    'Laptop'=>'fa-laptop',
    'Desktop'=>'fa-desktop',
    'Server'=>'fa-server',
    'Phone'=>'fa-phone',
    'Mobile Phone'=>'fa-mobile-alt',
    'Tablet'=>'fa-tablet-alt',
    'Firewall/Router'=>'fa-fire-alt',
    'Switch'=>'fa-network-wired',
    'Access Point'=>'fa-wifi',
    'Printer'=>'fa-print',
    'Display'=>'fa-tv',
    'Camera'=>'fa-video',
    'Virtual Machine'=>'fa-cloud',
    'Other'=>'fa-tag'
);

// Neutral mail infrastructure settings.
$config_mail_infrastructure_addresses = $row['config_mail_infrastructure_addresses'] ?? '';
$config_mail_group_sender_resolver = intval($row['config_mail_group_sender_resolver'] ?? 1);
$config_mail_hide_infrastructure_addresses = intval($row['config_mail_hide_infrastructure_addresses'] ?? 1);

// Neutral internal mail domain and delegation settings.
$config_mail_internal_domains = $row['config_mail_internal_domains'] ?? '';
$config_mail_internal_delegation_enable = intval($row['config_mail_internal_delegation_enable'] ?? 1);
$config_mail_ignored_unknown_thread_mode = $row['config_mail_ignored_unknown_thread_mode'] ?? 'external_only';

