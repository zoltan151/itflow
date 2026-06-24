<?php

require_once "includes/inc_all_admin.php";

function notificationSwitch($name, $id, $checked = 0, $class = '') {
    $checked_attr = intval($checked) === 1 ? 'checked' : '';
    echo '<div class="custom-control custom-switch d-flex justify-content-center">';
    echo '<input type="checkbox" class="custom-control-input ' . $class . '" name="' . $name . '" value="1" id="' . $id . '" ' . $checked_attr . '>';
    echo '<label class="custom-control-label" for="' . $id . '"></label>';
    echo '</div>';
}

function notificationDisabledCell($text = '') {
    echo '<td class="text-center text-muted align-middle">';
    echo '<span title="Not applicable">&mdash;</span>';
    if ($text) { echo '<br><small>' . nullable_htmlentities($text) . '</small>'; }
    echo '</td>';
}

function notificationSectionRow($title, $section_id) {
    echo '<tr class="bg-light notification-section-toggle" data-section="' . nullable_htmlentities($section_id) . '" style="cursor:pointer;">';
    echo '<th colspan="5" class="text-uppercase text-secondary small py-2"><i class="fas fa-fw fa-chevron-right mr-2 notification-section-icon"></i>' . nullable_htmlentities($title) . '<span class="badge badge-secondary ml-2 notification-enabled-count">0 enabled</span></th>';
    echo '</tr>';
}

function notificationRow($section_id, $icon, $label, $description, $appToggleName = null, $appToggleId = null, $appChecked = 0, $techToggleName = null, $techToggleId = null, $techChecked = 0, $clientToggleName = null, $clientToggleId = null, $clientChecked = 0, $ticketToggleName = null, $ticketToggleId = null, $ticketChecked = 0) {
    echo '<tr class="notification-section-row ' . nullable_htmlentities($section_id) . '">';
    echo '<td><div class="text-bold"><i class="fas fa-fw ' . nullable_htmlentities($icon) . ' mr-2"></i>' . nullable_htmlentities($label) . '</div>';
    if ($description) { echo '<small class="text-secondary">' . nullable_htmlentities($description) . '</small>'; }
    echo '</td>';

    echo '<td class="text-center align-middle">';
    if ($appToggleName && $appToggleId) { notificationSwitch($appToggleName, $appToggleId, $appChecked, 'app-notification-category matrix-notification-toggle'); } else { echo '<span class="text-muted">&mdash;</span>'; }
    echo '</td>';

    echo '<td class="text-center align-middle">';
    if ($techToggleName && $techToggleId) { notificationSwitch($techToggleName, $techToggleId, $techChecked, 'tech-email-notification-category matrix-notification-toggle'); } else { echo '<span class="text-muted">&mdash;</span>'; }
    echo '</td>';

    echo '<td class="text-center align-middle">';
    if ($clientToggleName && $clientToggleId) { notificationSwitch($clientToggleName, $clientToggleId, $clientChecked, 'client-email-notification-category matrix-notification-toggle'); } else { echo '<span class="text-muted">&mdash;</span>'; }
    echo '</td>';

    echo '<td class="text-center align-middle">';
    if ($ticketToggleName && $ticketToggleId) { notificationSwitch($ticketToggleName, $ticketToggleId, $ticketChecked, 'create-ticket-notification-category matrix-notification-toggle'); } else { echo '<span class="text-muted">&mdash;</span>'; }
    echo '</td>';
    echo '</tr>';
}

ob_start();
notificationSwitch('config_ticket_client_general_notifications', 'ticketNotificationSwitch', $config_ticket_client_general_notifications ?? 0, 'client-email-notification-category');
$clientTicketNotifySwitch = ob_get_clean();

?>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-bell mr-2"></i>Notifications</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <div class="form-group">
                <div class="custom-control custom-switch">
                    <input type="checkbox" class="custom-control-input" name="config_enable_cron" <?php if ($config_enable_cron == 1) { echo "checked"; } ?> value="1" id="enableCronSwitch">
                    <label class="custom-control-label text-bold" for="enableCronSwitch">Enable Cron <small class="text-secondary">(cron scripts must also be scheduled on the server)</small></label>
                </div>
            </div>

            <div class="form-group">
                <div class="custom-control custom-switch">
                    <input type="checkbox" class="custom-control-input" name="config_app_notifications_enable" <?php if (($config_app_notifications_enable ?? 0) == 1) { echo "checked"; } ?> value="1" id="appNotificationsMasterSwitch">
                    <label class="custom-control-label text-bold" for="appNotificationsMasterSwitch">Enable in-app notifications</label>
                </div>
                <small class="text-secondary">Master control for top-bar bell notifications. Email and ticket actions are controlled separately in the matrix.</small>
            </div>

            <div class="form-group">
                <label>Tech Email Notify Recipients</label>
                <input type="text" class="form-control" name="config_notification_tech_email_recipients" placeholder="helpdesk@example.com, noc@example.com" value="<?php echo nullable_htmlentities($config_notification_tech_email_recipients ?? ''); ?>">
                <small class="text-secondary">Comma-separated recipients for Tech Email Notify. If blank, ITFlow falls back to the configured new-ticket notification mailbox, then active internal users.</small>
            </div>

            <div class="card bg-light border mb-3">
                <div class="card-body py-2">
                    <div class="d-flex flex-wrap align-items-center">
                        <span class="text-bold text-secondary mr-3 mb-1"><i class="fas fa-sliders-h mr-1"></i>Bulk Actions</span>

                        <div class="btn-group btn-group-sm mr-2 mb-1">
                            <button type="button" class="btn btn-outline-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                App Notify
                            </button>
                            <div class="dropdown-menu">
                                <button type="button" class="dropdown-item" id="enableAllNotificationCategories"><i class="fas fa-check mr-2 text-success"></i>Enable All</button>
                                <button type="button" class="dropdown-item" id="disableAllNotificationCategories"><i class="fas fa-times mr-2 text-danger"></i>Disable All</button>
                            </div>
                        </div>

                        <div class="btn-group btn-group-sm mr-2 mb-1">
                            <button type="button" class="btn btn-outline-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                Tech Email Notify
                            </button>
                            <div class="dropdown-menu">
                                <button type="button" class="dropdown-item" id="enableTechEmailCategories"><i class="fas fa-check mr-2 text-success"></i>Enable All</button>
                                <button type="button" class="dropdown-item" id="disableTechEmailCategories"><i class="fas fa-times mr-2 text-danger"></i>Disable All</button>
                            </div>
                        </div>

                        <div class="btn-group btn-group-sm mr-2 mb-1">
                            <button type="button" class="btn btn-outline-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                Client Email Notify
                            </button>
                            <div class="dropdown-menu">
                                <button type="button" class="dropdown-item" id="enableClientEmailCategories"><i class="fas fa-check mr-2 text-success"></i>Enable All</button>
                                <button type="button" class="dropdown-item" id="disableClientEmailCategories"><i class="fas fa-times mr-2 text-danger"></i>Disable All</button>
                            </div>
                        </div>

                        <div class="btn-group btn-group-sm mb-1">
                            <button type="button" class="btn btn-outline-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                                Create Ticket
                            </button>
                            <div class="dropdown-menu">
                                <button type="button" class="dropdown-item" id="enableTicketCategories"><i class="fas fa-check mr-2 text-success"></i>Enable All</button>
                                <button type="button" class="dropdown-item" id="disableTicketCategories"><i class="fas fa-times mr-2 text-danger"></i>Disable All</button>
                            </div>
                        </div>
                    </div>
                    <small class="text-muted d-block mt-1">Use bulk actions sparingly. The matrix below is the source of truth.</small>
                </div>
            </div>

            <div class="table-responsive">
                <table class="table table-bordered table-striped">
                    <thead class="thead-dark">
                        <tr>
                            <th style="width: 44%;">Notification</th>
                            <th class="text-center" style="width: 12%;">App Notify</th>
                            <th class="text-center" style="width: 14%;">Tech Email Notify</th>
                            <th class="text-center" style="width: 15%;">Client Email Notify</th>
                            <th class="text-center" style="width: 15%;">Create Ticket</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php notificationSectionRow('System / Cron', 'notificationSection0'); ?>
<?php notificationRow('notificationSection0', 'fa-check-circle', 'Cron execution success', 'Routine cron success message. Disabled by default because it is usually noise.', 'config_app_notify_cron_success_enable', 'app_cron_success', $config_app_notify_cron_success_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection0', 'fa-exclamation-triangle', 'Cron / system failures', 'Cron failures and system-health warning/error events.', 'config_app_notify_cron_failure_enable', 'app_cron_failure', $config_app_notify_cron_failure_enable ?? 0, 'config_tech_email_notify_cron_failure_enable', 'tech_cron_failure', $config_tech_email_notify_cron_failure_enable ?? 0, null, null, 0, 'config_create_ticket_notify_cron_failure_enable', 'ticket_cron_failure', $config_create_ticket_notify_cron_failure_enable ?? 0); ?>
<?php notificationRow('notificationSection0', 'fa-download', 'ITFlow update available', 'Notify when an ITFlow update is available.', 'config_app_notify_update_available_enable', 'app_update_available', $config_app_notify_update_available_enable ?? 0, 'config_tech_email_notify_update_available_enable', 'tech_update_available', $config_tech_email_notify_update_available_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection0', 'fa-check-circle', 'ITFlow update completed', 'Successful update completion notifications. Usually disabled to avoid noise.', 'config_app_notify_update_success_enable', 'app_update_success', $config_app_notify_update_success_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection0', 'fa-exclamation-triangle', 'ITFlow update failed', 'Update failure notifications. Recommended for admins.', 'config_app_notify_update_failure_enable', 'app_update_failure', $config_app_notify_update_failure_enable ?? 0, 'config_tech_email_notify_update_failure_enable', 'tech_update_failure', $config_tech_email_notify_update_failure_enable ?? 0, null, null, 0, 'config_create_ticket_notify_update_failure_enable', 'ticket_update_failure', $config_create_ticket_notify_update_failure_enable ?? 0); ?>
<?php notificationRow('notificationSection0', 'fa-cog', 'Other system notifications', 'Fallback category for settings/security/system notifications that do not fit a more specific row.', 'config_app_notify_system_enable', 'app_system', $config_app_notify_system_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection0', 'fa-database', 'Backup completed', 'Successful backup completion notifications. Usually disabled to avoid noise.', 'config_app_notify_backup_success_enable', 'app_backup_success', $config_app_notify_backup_success_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection0', 'fa-exclamation-triangle', 'Backup failed', 'Backup failure notifications. Recommended for admins.', 'config_app_notify_backup_failure_enable', 'app_backup_failure', $config_app_notify_backup_failure_enable ?? 0, 'config_tech_email_notify_backup_failure_enable', 'tech_backup_failure', $config_tech_email_notify_backup_failure_enable ?? 0, null, null, 0, 'config_create_ticket_notify_backup_failure_enable', 'ticket_backup_failure', $config_create_ticket_notify_backup_failure_enable ?? 0); ?>
<?php notificationSectionRow('Health / Operations', 'notificationSection1'); ?>
<?php notificationRow('notificationSection1', 'fa-envelope-open-text', 'Email parser health', 'IMAP/OAuth failures, parser lock issues, and inbound email processing failures.', 'config_app_notify_email_parser_health_enable', 'app_email_parser_health', $config_app_notify_email_parser_health_enable ?? 0, 'config_tech_email_notify_email_parser_health_enable', 'tech_email_parser_health', $config_tech_email_notify_email_parser_health_enable ?? 0, null, null, 0, 'config_create_ticket_notify_email_parser_health_enable', 'ticket_email_parser_health', $config_create_ticket_notify_email_parser_health_enable ?? 0); ?>
<?php notificationRow('notificationSection1', 'fa-paper-plane', 'Mail queue health', 'SMTP/OAuth failures, stuck queue warnings, and send failures.', 'config_app_notify_mail_queue_health_enable', 'app_mail_queue_health', $config_app_notify_mail_queue_health_enable ?? 0, 'config_tech_email_notify_mail_queue_health_enable', 'tech_mail_queue_health', $config_tech_email_notify_mail_queue_health_enable ?? 0, null, null, 0, 'config_create_ticket_notify_mail_queue_health_enable', 'ticket_mail_queue_health', $config_create_ticket_notify_mail_queue_health_enable ?? 0); ?>
<?php notificationRow('notificationSection1', 'fa-sync-alt', 'Domain refresh completed', 'Successful domain metadata refresh notifications. Usually disabled to avoid noise.', 'config_app_notify_domain_refresh_success_enable', 'app_domain_refresh_success', $config_app_notify_domain_refresh_success_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection1', 'fa-exclamation-triangle', 'Domain refresh failed', 'Domain metadata refresh, RDAP/WHOIS/DNS, and vendor auto-map failure notifications.', 'config_app_notify_domain_refresh_failure_enable', 'app_domain_refresh_failure', $config_app_notify_domain_refresh_failure_enable ?? 0, 'config_tech_email_notify_domain_refresh_failure_enable', 'tech_domain_refresh_failure', $config_tech_email_notify_domain_refresh_failure_enable ?? 0, null, null, 0, 'config_create_ticket_notify_domain_refresh_failure_enable', 'ticket_domain_refresh_failure', $config_create_ticket_notify_domain_refresh_failure_enable ?? 0); ?>
<?php notificationRow('notificationSection1', 'fa-certificate', 'Certificate refresh completed', 'Successful SSL certificate refresh notifications. Usually disabled to avoid noise.', 'config_app_notify_certificate_refresh_success_enable', 'app_certificate_refresh_success', $config_app_notify_certificate_refresh_success_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection1', 'fa-exclamation-triangle', 'Certificate refresh failed', 'Certificate refresh failure notifications and related SSL metadata issues.', 'config_app_notify_certificate_refresh_failure_enable', 'app_certificate_refresh_failure', $config_app_notify_certificate_refresh_failure_enable ?? 0, 'config_tech_email_notify_certificate_refresh_failure_enable', 'tech_certificate_refresh_failure', $config_tech_email_notify_certificate_refresh_failure_enable ?? 0, null, null, 0, 'config_create_ticket_notify_certificate_refresh_failure_enable', 'ticket_certificate_refresh_failure', $config_create_ticket_notify_certificate_refresh_failure_enable ?? 0); ?>
<tr class='notification-section-row notificationSection1'><td><div class='text-bold'><i class='fas fa-fw fa-layer-group mr-2'></i>Mail queue backlog threshold</div><small class='text-secondary'>Creates a mail queue health notification when unsent queued mail reaches this count.</small></td><td colspan='4'><input type='number' min='1' class='form-control form-control-sm' name='config_app_notify_mail_queue_backlog_threshold' value='<?php echo intval($config_app_notify_mail_queue_backlog_threshold ?? 50); ?>'></td></tr>
<?php notificationSectionRow('Security / Admin', 'notificationSection2'); ?>
<?php notificationRow('notificationSection2', 'fa-shield-alt', 'Security / login alerts', 'Authentication, suspicious login, and security health notifications.', 'config_app_notify_security_enable', 'app_security', $config_app_notify_security_enable ?? 0, 'config_tech_email_notify_security_enable', 'tech_security', $config_tech_email_notify_security_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection2', 'fa-user-cog', 'Administrative changes', 'Users, roles, settings, and other administrative change notifications.', 'config_app_notify_admin_enable', 'app_admin', $config_app_notify_admin_enable ?? 0, 'config_tech_email_notify_admin_enable', 'tech_admin', $config_tech_email_notify_admin_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection2', 'fa-key', 'API key changes', 'API key creation/deletion/change notifications.', 'config_app_notify_api_key_enable', 'app_api_key', $config_app_notify_api_key_enable ?? 0, 'config_tech_email_notify_api_key_enable', 'tech_api_key', $config_tech_email_notify_api_key_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationSectionRow('Expirations', 'notificationSection3'); ?>
<?php notificationRow('notificationSection3', 'fa-globe', 'Domain expiration notice', 'Domain expiry notices using the configurable warning-day thresholds below.', 'config_app_notify_domain_expire_enable', 'app_domain_expire', $config_app_notify_domain_expire_enable ?? 0, 'config_tech_email_notify_domain_expire_enable', 'tech_domain_expire', $config_tech_email_notify_domain_expire_enable ?? 0, 'config_client_email_notify_domain_expire_enable', 'client_domain_expire', $config_client_email_notify_domain_expire_enable ?? 0, 'config_create_ticket_notify_domain_expire_enable', 'ticket_domain_expire', $config_create_ticket_notify_domain_expire_enable ?? 0); ?>
<?php notificationRow('notificationSection3', 'fa-lock', 'Certificate expiration notice', 'SSL certificate expiry notices using the configurable warning-day thresholds below.', 'config_app_notify_certificate_expire_enable', 'app_certificate_expire', $config_app_notify_certificate_expire_enable ?? 0, 'config_tech_email_notify_certificate_expire_enable', 'tech_certificate_expire', $config_tech_email_notify_certificate_expire_enable ?? 0, 'config_client_email_notify_certificate_expire_enable', 'client_certificate_expire', $config_client_email_notify_certificate_expire_enable ?? 0, 'config_create_ticket_notify_certificate_expire_enable', 'ticket_certificate_expire', $config_create_ticket_notify_certificate_expire_enable ?? 0); ?>
<?php notificationRow('notificationSection3', 'fa-desktop', 'Asset warranty expiration notice', 'Asset warranty expiry notices using the configurable warning-day thresholds below.', 'config_app_notify_asset_warranty_expire_enable', 'app_asset_warranty_expire', $config_app_notify_asset_warranty_expire_enable ?? 0, 'config_tech_email_notify_asset_warranty_expire_enable', 'tech_asset_warranty_expire', $config_tech_email_notify_asset_warranty_expire_enable ?? 0, 'config_client_email_notify_asset_warranty_expire_enable', 'client_asset_warranty_expire', $config_client_email_notify_asset_warranty_expire_enable ?? 0, 'config_create_ticket_notify_asset_warranty_expire_enable', 'ticket_asset_warranty_expire', $config_create_ticket_notify_asset_warranty_expire_enable ?? 0); ?>
<tr class='notification-section-row notificationSection3'>
<td><div class='text-bold'><i class='fas fa-fw fa-calendar-alt mr-2'></i>Expiration warning days</div><small class='text-secondary'>Comma-separated day thresholds. Values are deduplicated, sorted, and capped at 365.</small></td>
<td colspan='4'>
<div class='form-row'>
<div class='col-md-4 mb-2'><label class='small text-secondary mb-1'>Domain days</label><input type='text' class='form-control form-control-sm' name='config_notification_domain_expire_days' value='<?php echo nullable_htmlentities($config_notification_domain_expire_days ?? "45,7,1"); ?>'></div>
<div class='col-md-4 mb-2'><label class='small text-secondary mb-1'>Certificate days</label><input type='text' class='form-control form-control-sm' name='config_notification_certificate_expire_days' value='<?php echo nullable_htmlentities($config_notification_certificate_expire_days ?? "45,7,1"); ?>'></div>
<div class='col-md-4 mb-2'><label class='small text-secondary mb-1'>Asset warranty days</label><input type='text' class='form-control form-control-sm' name='config_notification_asset_warranty_expire_days' value='<?php echo nullable_htmlentities($config_notification_asset_warranty_expire_days ?? "45,7,1"); ?>'></div>
</div>
</td>
</tr>
<?php notificationSectionRow('Tickets', 'notificationSection4'); ?>
<?php notificationRow('notificationSection4', 'fa-ticket-alt', 'Ticket assignment / update notifications', 'Assigned-to-you, opened-by-you, watcher/task ticket bell notifications.', 'config_app_notify_ticket_enable', 'app_ticket', $config_app_notify_ticket_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection4', 'fa-inbox', 'Pending unassigned tickets', 'Notification for new tickets pending assignment.', 'config_app_notify_pending_ticket_enable', 'app_pending_ticket', $config_app_notify_pending_ticket_enable ?? 0, 'config_tech_email_notify_pending_ticket_enable', 'tech_pending_ticket', $config_tech_email_notify_pending_ticket_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection4', 'fa-redo-alt', 'Recurring ticket notifications', 'Recurring ticket assignment notifications.', 'config_app_notify_recurring_ticket_enable', 'app_recurring_ticket', $config_app_notify_recurring_ticket_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection4', 'fa-tasks', 'Ticket task notifications', 'Ticket task approval and task-related notifications.', 'config_app_notify_task_enable', 'app_task', $config_app_notify_task_enable ?? 0, null, null, 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection4', 'fa-stopwatch', 'Ticket SLA / age warnings', 'Ticket age/SLA threshold warnings when generated by cron or ticket workflows.', 'config_app_notify_ticket_sla_enable', 'app_ticket_sla', $config_app_notify_ticket_sla_enable ?? 0, 'config_tech_email_notify_ticket_sla_enable', 'tech_ticket_sla', $config_tech_email_notify_ticket_sla_enable ?? 0, null, null, 0, 'config_create_ticket_notify_ticket_sla_enable', 'ticket_ticket_sla', $config_create_ticket_notify_ticket_sla_enable ?? 0); ?>
<?php notificationRow('notificationSection4', 'fa-undo', 'Ticket reopened', 'Notifications when tickets are reopened or client replies to resolved/pending closure tickets.', 'config_app_notify_ticket_reopened_enable', 'app_ticket_reopened', $config_app_notify_ticket_reopened_enable ?? 0, 'config_tech_email_notify_ticket_reopened_enable', 'tech_ticket_reopened', $config_tech_email_notify_ticket_reopened_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection4', 'fa-fire', 'High priority tickets', 'Urgent/high-priority ticket creation or escalation notifications.', 'config_app_notify_high_priority_ticket_enable', 'app_high_priority_ticket', $config_app_notify_high_priority_ticket_enable ?? 0, 'config_tech_email_notify_high_priority_ticket_enable', 'tech_high_priority_ticket', $config_tech_email_notify_high_priority_ticket_enable ?? 0, null, null, 0, 'config_create_ticket_notify_high_priority_ticket_enable', 'ticket_high_priority_ticket', $config_create_ticket_notify_high_priority_ticket_enable ?? 0); ?>
<?php notificationSectionRow('Billing / Mail', 'notificationSection5'); ?>
<?php notificationRow('notificationSection5', 'fa-file-invoice-dollar', 'Billing notifications', 'Invoice, payment, and quote in-app notifications.', 'config_app_notify_billing_enable', 'app_billing', $config_app_notify_billing_enable ?? 0, null, null, 0, 'config_client_email_notify_billing_enable', 'client_billing', $config_client_email_notify_billing_enable ?? 0, null, null, 0); ?>
<?php notificationRow('notificationSection5', 'fa-credit-card', 'Payment failures', 'Stripe/payment processing errors and failed payment notifications.', 'config_app_notify_payment_failure_enable', 'app_payment_failure', $config_app_notify_payment_failure_enable ?? 0, 'config_tech_email_notify_payment_failure_enable', 'tech_payment_failure', $config_tech_email_notify_payment_failure_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection5', 'fa-sync', 'Autopay failures', 'Automatic payment failure notifications.', 'config_app_notify_autopay_failure_enable', 'app_autopay_failure', $config_app_notify_autopay_failure_enable ?? 0, 'config_tech_email_notify_autopay_failure_enable', 'tech_autopay_failure', $config_tech_email_notify_autopay_failure_enable ?? 0, null, null, 0, null, null, 0); ?>
<?php notificationRow('notificationSection5', 'fa-file-signature', 'Quote notifications', 'Quote accepted/declined notifications.', 'config_app_notify_quote_enable', 'app_quote', $config_app_notify_quote_enable ?? 0, 'config_tech_email_notify_quote_enable', 'tech_quote', $config_tech_email_notify_quote_enable ?? 0, 'config_client_email_notify_quote_enable', 'client_quote', $config_client_email_notify_quote_enable ?? 0, null, null, 0); ?>
<?php notificationRow('notificationSection5', 'fa-envelope', 'Mail failures', 'Failed email / mail queue notification rows.', 'config_app_notify_mail_failure_enable', 'app_mail_failure', $config_app_notify_mail_failure_enable ?? 0, 'config_tech_email_notify_mail_failure_enable', 'tech_mail_failure', $config_tech_email_notify_mail_failure_enable ?? 0, null, null, 0, null, null, 0); ?>
                        <?php notificationSectionRow('Client Communications', 'notificationSectionClientComms'); ?>
                        <?php notificationRow('notificationSectionClientComms', 'fa-bell', 'Client ticket emails', 'Send automatic client-facing emails when tickets are raised, updated, or closed.', null, null, 0, null, null, 0, 'config_ticket_client_general_notifications', 'ticketNotificationSwitchMatrix', $config_ticket_client_general_notifications ?? 0, null, null, 0); ?>
                        <?php notificationRow('notificationSectionClientComms', 'fa-clock', 'Invoice reminders', 'Send overdue invoice reminders to client billing contacts.', null, null, 0, null, null, 0, 'config_send_invoice_reminders', 'sendInvoiceRemindersSwitch', $config_send_invoice_reminders ?? 0, null, null, 0); ?>
                        <?php notificationRow('notificationSectionClientComms', 'fa-redo-alt', 'Send recurring invoices', 'Automatically email generated recurring invoices to client billing contacts.', null, null, 0, null, null, 0, 'config_recurring_auto_send_invoice', 'sendRecurringSwitch', $config_recurring_auto_send_invoice ?? 0, null, null, 0); ?>
                    </tbody>
                </table>
            </div>

            <button type="submit" name="edit_notification_settings" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Save</button>
        </form>
    </div>
</div>

<script>
function setChecked(selector, value) { document.querySelectorAll(selector).forEach(function (el) { el.checked = value; }); updateNotificationEnabledCounts(); }
document.getElementById('enableAllNotificationCategories').addEventListener('click', function () { setChecked('.app-notification-category', true); });
document.getElementById('disableAllNotificationCategories').addEventListener('click', function () { setChecked('.app-notification-category', false); });
document.getElementById('enableTechEmailCategories').addEventListener('click', function () { setChecked('.tech-email-notification-category', true); });
document.getElementById('disableTechEmailCategories').addEventListener('click', function () { setChecked('.tech-email-notification-category', false); });
document.getElementById('enableClientEmailCategories').addEventListener('click', function () { setChecked('.client-email-notification-category', true); });
document.getElementById('disableClientEmailCategories').addEventListener('click', function () { setChecked('.client-email-notification-category', false); });
document.getElementById('enableTicketCategories').addEventListener('click', function () { setChecked('.create-ticket-notification-category', true); });
document.getElementById('disableTicketCategories').addEventListener('click', function () { setChecked('.create-ticket-notification-category', false); });

function updateNotificationEnabledCounts() {
    document.querySelectorAll('.notification-section-toggle').forEach(function (header) {
        var section = header.dataset.section;
        var rows = document.querySelectorAll('.notification-section-row.' + section);
        var enabled = 0;
        rows.forEach(function (row) { row.querySelectorAll('.matrix-notification-toggle:checked').forEach(function () { enabled++; }); });
        var badge = header.querySelector('.notification-enabled-count');
        if (badge) { badge.textContent = enabled + ' enabled'; }
    });
}

document.querySelectorAll('.notification-section-row').forEach(function (row) { row.style.display = 'none'; });
document.querySelectorAll('.notification-section-toggle').forEach(function (header) {
    header.addEventListener('click', function () {
        var section = header.dataset.section;
        var rows = document.querySelectorAll('.notification-section-row.' + section);
        var icon = header.querySelector('.notification-section-icon');
        var isHidden = rows.length && rows[0].style.display === 'none';
        rows.forEach(function (row) { row.style.display = isHidden ? '' : 'none'; });
        if (icon) { icon.classList.toggle('fa-chevron-right', !isHidden); icon.classList.toggle('fa-chevron-down', isHidden); }
    });
});
document.querySelectorAll('.matrix-notification-toggle').forEach(function (el) { el.addEventListener('change', updateNotificationEnabledCounts); });
updateNotificationEnabledCounts();
</script>

<?php
require_once "../includes/footer.php";
