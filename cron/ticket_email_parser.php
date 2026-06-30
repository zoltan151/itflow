<?php
/*
 * CRON - Email Parser (Webklex PHP-IMAP)
 * Process emails and create/update tickets using Webklex\PHPIMAP instead of native IMAP
 */

// Start the timer
$script_start_time = microtime(true);

// Set working directory to the directory this cron script lives at.
chdir(dirname(__FILE__));

// Ensure we're running from command line
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

// Autoload (Webklex & any composer deps)
require_once "../plugins/vendor/autoload.php";

// Get ITFlow config & helper functions
require_once "../config.php";

// Set Timezone
require_once "../includes/inc_set_timezone.php";
require_once "../functions.php";

// Get settings for the "default" company
require_once "../includes/load_global_settings.php";


// ITFLOW_EMAIL_REPLY_REOPEN_ACTIVITY_LOG
if (!function_exists('itflowLogEmailReplyTicketReopen')) {
    function itflowLogEmailReplyTicketReopen($ticket_id, $client_id = 0, $previous_status = '')
    {
        global $mysqli;

        $ticket_id = intval($ticket_id);
        $client_id = intval($client_id);
        $previous_status = trim((string)$previous_status);

        if ($ticket_id <= 0 || !isset($mysqli)) {
            return;
        }

        static $itflow_logged_email_reopens = [];

        if (isset($itflow_logged_email_reopens[$ticket_id])) {
            return;
        }

        $ticket_sql = mysqli_query($mysqli, "SELECT ticket_prefix, ticket_number, ticket_subject, ticket_client_id FROM tickets WHERE ticket_id = $ticket_id LIMIT 1");

        if (!$ticket_sql || mysqli_num_rows($ticket_sql) == 0) {
            return;
        }

        $ticket_row = mysqli_fetch_assoc($ticket_sql);

        if ($client_id <= 0) {
            $client_id = intval($ticket_row['ticket_client_id'] ?? 0);
        }

        $ticket_prefix = $ticket_row['ticket_prefix'] ?? '';
        $ticket_number = $ticket_row['ticket_number'] ?? '';
        $ticket_subject = $ticket_row['ticket_subject'] ?? '';

        $ticket_label = trim($ticket_prefix . $ticket_number);
        if ($ticket_label === '') {
            $ticket_label = (string)$ticket_id;
        }

        $previous_status_message = '';
        if ($previous_status !== '') {
            $previous_status_message = " Previous status: $previous_status.";
        }

        $message = "Ticket #$ticket_label was automatically reopened because a customer replied by email.$previous_status_message";

        if ($ticket_subject !== '') {
            $message .= " Subject: $ticket_subject";
        }

        if (function_exists('logAction')) {
            logAction("Ticket", "Reopen", $message, $client_id, $ticket_id);
            $itflow_logged_email_reopens[$ticket_id] = true;
            return;
        }

        $log_table_exists = mysqli_query($mysqli, "SHOW TABLES LIKE 'logs'");
        if (!$log_table_exists || mysqli_num_rows($log_table_exists) == 0) {
            return;
        }

        $columns = [];
        $column_sql = mysqli_query($mysqli, "SHOW COLUMNS FROM logs");
        if ($column_sql) {
            while ($column = mysqli_fetch_assoc($column_sql)) {
                $columns[$column['Field']] = true;
            }
        }

        $insert = [];

        if (isset($columns['log_type'])) {
            $insert['log_type'] = 'Ticket';
        }
        if (isset($columns['log_action'])) {
            $insert['log_action'] = 'Reopen';
        }
        if (isset($columns['log_description'])) {
            $insert['log_description'] = $message;
        }
        if (isset($columns['log_client_id'])) {
            $insert['log_client_id'] = $client_id;
        }
        if (isset($columns['log_item_id'])) {
            $insert['log_item_id'] = $ticket_id;
        }
        if (isset($columns['log_created_at'])) {
            $insert['log_created_at'] = date('Y-m-d H:i:s');
        }

        if (empty($insert)) {
            return;
        }

        $sets = [];
        foreach ($insert as $column => $value) {
            $safe_column = preg_replace('/[^A-Za-z0-9_]/', '', $column);
            $safe_value = mysqli_real_escape_string($mysqli, (string)$value);
            $sets[] = "`$safe_column` = '$safe_value'";
        }

        mysqli_query($mysqli, "INSERT INTO logs SET " . implode(", ", $sets));

        $itflow_logged_email_reopens[$ticket_id] = true;
    }
}





// ITFLOW_EMAIL_REPLY_REOPEN_ACTIVITY_GUARD
if (!function_exists('itflowShouldLogEmailReplyTicketReopen')) {
    function itflowShouldLogEmailReplyTicketReopen($previous_status_id, $new_status_id)
    {
        $previous_status_id = intval($previous_status_id);
        $new_status_id = intval($new_status_id);

        if ($previous_status_id <= 0 || $new_status_id <= 0 || $previous_status_id === $new_status_id) {
            return false;
        }

        $previous_status_name = '';

        if (function_exists('parserGetTicketStatusNameById')) {
            $previous_status_name = strtolower(trim((string)parserGetTicketStatusNameById($previous_status_id)));
        }

        if ($previous_status_name === '') {
            return false;
        }

        // Only log a true reopen when the previous state was a resolved/completed-style state.
        // Do not log this for normal client replies on already-open/in-progress tickets.
        $reopen_candidate_statuses = [
            'resolved',
            'complete',
            'completed',
            'done',
            'fixed',
            'solved'
        ];

        foreach ($reopen_candidate_statuses as $candidate) {
            if (strpos($previous_status_name, $candidate) !== false) {
                return true;
            }
        }

        return false;
    }
}


// ITFLOW_EMAIL_PARSER_DISPLAY_NAME_CLEANUP
if (!function_exists('parserCleanEmailDisplayName')) {
    function parserCleanEmailDisplayName(string $name, string $email = ''): string {
        $name = trim($name);
        $email = trim($email);

        if ($name === '') {
            return '';
        }

        // Normalize HTML entities and common escaped quote/backslash artifacts from mail headers.
        $name = html_entity_decode($name, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Repeatedly remove slashes because some Google Group / forwarded headers arrive double-escaped.
        for ($i = 0; $i < 4; $i++) {
            $unslashed = stripslashes($name);
            if ($unslashed === $name) {
                break;
            }
            $name = $unslashed;
        }

        $name = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name);
        $name = trim($name);

        // Remove leading/trailing quote wrappers and leftover slashes.
        for ($i = 0; $i < 4; $i++) {
            $before = $name;
            $name = trim($name);
            $name = trim($name, " \t\n\r\0\x0B\\\"'`“”‘’<>");
            $name = preg_replace('/^(?:\\\\+|"+|\'+|`+)+/u', '', $name);
            $name = preg_replace('/(?:\\\\+|"+|\'+|`+)+$/u', '', $name);
            $name = trim($name);
            if ($name === $before) {
                break;
            }
        }

        // Collapse quote/backslash junk that can remain between words.
        $name = preg_replace('/\\\\+/', '', $name);
        $name = preg_replace('/"{2,}/', '"', $name);
        $name = preg_replace("/'{2,}/", "'", $name);
        $name = preg_replace('/\s+/', ' ', $name);
        $name = trim($name, " \t\n\r\0\x0B\\\"'`“”‘’<>");

        // If the parser accidentally used the email address as the name, leave it blank
        // so the normal fallback can use the email/local part.
        if ($email !== '' && strcasecmp($name, $email) === 0) {
            return '';
        }

        // If the display name still contains an address wrapper, remove the address.
        if ($email !== '') {
            $quoted_email = preg_quote($email, '/');
            $name = preg_replace('/<\s*' . $quoted_email . '\s*>/i', '', $name);
            $name = trim($name, " \t\n\r\0\x0B\\\"'`“”‘’<>");
        }

        return $name;
    }
}

$config_ticket_prefix = sanitizeInput($config_ticket_prefix);
$config_ticket_from_name = sanitizeInput($config_ticket_from_name);
$config_ticket_email_parse_unknown_senders = intval($row['config_ticket_email_parse_unknown_senders']);

// Neutral internal mail domain and delegation settings.
$config_mail_internal_domains = $row['config_mail_internal_domains'] ?? '';
$config_mail_internal_delegation_enable = intval($row['config_mail_internal_delegation_enable'] ?? 1);
$config_mail_ignored_unknown_thread_mode = $row['config_mail_ignored_unknown_thread_mode'] ?? 'external_only';


// Get company name & phone & timezone
$sql = mysqli_query($mysqli, "SELECT * FROM companies, settings WHERE companies.company_id = settings.company_id AND companies.company_id = 1");
$row = mysqli_fetch_assoc($sql);
$company_name = sanitizeInput($row['company_name']);
$company_phone = sanitizeInput(formatPhoneNumber($row['company_phone'], $row['company_phone_country_code']));

// Check setting enabled
if ($config_ticket_email_parse == 0) {
    logApp("Cron-Email-Parser", "error", "Cron Email Parser unable to run - not enabled in admin settings.");
    exit("Email Parser: Feature is not enabled - check Settings > Ticketing > Email-to-ticket parsing. See https://docs.itflow.org/ticket_email_parse  -- Quitting..");
}

// System temp directory & lock
$temp_dir = sys_get_temp_dir();
$lock_file_path = "{$temp_dir}/itflow_email_parser_{$installation_id}.lock";

if (file_exists($lock_file_path)) {
    $file_age = time() - filemtime($lock_file_path);
    if ($file_age > 300) {
        unlink($lock_file_path);
        logApp("Cron-Email-Parser", "warning", "Cron Email Parser detected a lock file was present but was over 5 minutes old so it removed it.");
    } else {
        logApp("Cron-Email-Parser", "warning", "Lock file present. Cron Email Parser attempted to execute but was already executing, so instead it terminated.");
        exit("Script is already running. Exiting.");
    }
}
file_put_contents($lock_file_path, "Locked");

// Ensure lock gets removed even on fatal error
register_shutdown_function(function() use ($lock_file_path) {
    if (file_exists($lock_file_path)) {
        @unlink($lock_file_path);
    }
});

// Allowed attachment extensions
$allowed_extensions = array('jpg', 'jpeg', 'gif', 'png', 'webp', 'svg', 'pdf', 'txt', 'md', 'doc', 'docx', 'csv', 'xls', 'xlsx', 'xlsm', 'zip', 'tar', 'gz');


/**
 * Build the visible conversation-history block for the initial ticket-created email.
 * The original requester and CC'd parties should get the context they originally sent,
 * but the block is sanitized again because inbound email HTML is untrusted input.
 */
function parserBuildInitialConversationHistoryBlock(string $ticket_message_html): string {
    $html = trim($ticket_message_html);

    if ($html === '') {
        return '';
    }

    // Strip document-level and active/dangerous content before echoing the original
    // request back to the customer and CC'd watchers.
    $html = preg_replace('/<!DOCTYPE[^>]*>/i', '', $html);
    $html = preg_replace('/<\/?(html|head|body)[^>]*>/i', '', $html);
    $html = preg_replace('/<\s*(script|style|iframe|object|embed|form|input|button|select|textarea|link|meta|base)[^>]*>.*?<\s*\/\s*\1\s*>/is', '', $html);
    $html = preg_replace('/<\s*(script|style|iframe|object|embed|form|input|button|select|textarea|link|meta|base)\b[^>]*\/?\s*>/is', '', $html);

    // Remove inline event handlers and javascript/data URL vectors. This is not a full
    // HTML sanitizer, but it meaningfully reduces risk while preserving readable context.
    $html = preg_replace('/\s+on[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/i', '', $html);
    $html = preg_replace('/\s+(href|src)\s*=\s*("|\')\s*(javascript|data)\s*:[^"\']*("|\')/i', '', $html);

    // Keep the notification email sane. The original .eml is still attached to the ticket
    // if the full source is needed.
    if (strlen($html) > 30000) {
        $html = substr($html, 0, 30000) . "<br><br><i>[Original request truncated in notification email. Open the ticket for the full message.]</i>";
    }

    if (trim(strip_tags($html)) === '') {
        return '';
    }

    return "<hr style='border:0;border-top:1px solid #dddddd;margin:24px 0;'>"
        . "<div style='font-weight:bold;color:#666666;margin-bottom:10px;'>Conversation history</div>"
        . "<blockquote style='border-left:3px solid #dddddd;margin:0;padding-left:12px;color:#333333;'>"
        . "<div style='font-size:12px;color:#777777;margin-bottom:8px;'>Original request</div>"
        . $html
        . "</blockquote>";
}

/** ------------------------------------------------------------------
 * Ticket / Reply helpers (unchanged)
 * ------------------------------------------------------------------ */
function addTicket($contact_id, $contact_name, $contact_email, $client_id, $date, $subject, $message, $attachments, $original_message_file, $ccs, array $mail_context = []) {
    global $mysqli, $config_app_name, $company_name, $company_phone, $config_ticket_prefix, $config_ticket_client_general_notifications, $config_ticket_new_ticket_notification_email, $config_base_url, $config_ticket_from_name, $config_ticket_from_email, $config_ticket_default_billable, $allowed_extensions, $config_imap_username, $config_smtp_username, $config_mail_from_email, $config_ticket_inbound_cc_watcher_mode, $config_ticket_initial_history_enable;
    $bad_pattern = "/do[\W_]*not[\W_]*reply|no[\W_]*reply/i"; // Email addresses to ignore

    // Atomically increment and get the new ticket number
    mysqli_query($mysqli, "
        UPDATE settings
        SET
            config_ticket_next_number = LAST_INSERT_ID(config_ticket_next_number),
            config_ticket_next_number = config_ticket_next_number + 1
        WHERE company_id = 1
    ");

    $ticket_number = mysqli_insert_id($mysqli);

    // Clean up the message
    $message = trim($message);
    // Remove DOCTYPE and meta tags
    $message = preg_replace('/<!DOCTYPE[^>]*>/i', '', $message);
    $message = preg_replace('/<meta[^>]*>/i', '', $message);
    // Remove <html>, <head>, <body> and their closing tags
    $message = preg_replace('/<\/?(html|head|body)[^>]*>/i', '', $message);
    // Collapse excess whitespace
    $message = preg_replace('/\s+/', ' ', $message);
    // Convert newlines to <br>
    $message = nl2br($message);
    // Wrap final formatted message
    $message = "<i>Email from: <b>$contact_name</b> &lt;$contact_email&gt; at $date:-</i> <br><br><div style='line-height:1.5;'>$message</div>";

    $ticket_prefix_esc = mysqli_real_escape_string($mysqli, $config_ticket_prefix);
    $message_esc = mysqli_real_escape_string($mysqli, $message);
    $contact_email_esc = mysqli_real_escape_string($mysqli, $contact_email);
    $client_id = intval($client_id);

    $url_key = randomString(32);

    // Build the external CC list for the ticket-created notification. These addresses
    // are also inserted as watchers below, but the notification should be one outbound
    // email to the requester with everyone else CC'd, not one isolated email per watcher.
    $exclude_from_thread = array_merge([
        $contact_email,
        $config_ticket_from_email ?? '',
        $config_imap_username ?? '',
        $config_smtp_username ?? '',
        $config_mail_from_email ?? '',
    ], function_exists('itflowConfiguredMailInfrastructureAddresses') ? itflowConfiguredMailInfrastructureAddresses() : []);
    if (!empty($mail_context['exclude_emails']) && is_array($mail_context['exclude_emails'])) {
        $exclude_from_thread = array_merge($exclude_from_thread, $mail_context['exclude_emails']);
    }
    $thread_ccs = parserNormalizeEmailList(is_array($ccs) ? $ccs : [], $exclude_from_thread, $bad_pattern);

    $inbound_cc_watcher_mode = (string)($config_ticket_inbound_cc_watcher_mode ?? 'all');
    if (!in_array($inbound_cc_watcher_mode, ['all', 'known_contacts', 'disabled'], true)) {
        $inbound_cc_watcher_mode = 'all';
    }

    if ($inbound_cc_watcher_mode === 'disabled') {
        $thread_ccs = [];
    } elseif ($inbound_cc_watcher_mode === 'known_contacts') {
        $thread_ccs = parserFilterKnownContactEmails($thread_ccs, $client_id);
    }

    mysqli_query($mysqli, "INSERT INTO tickets SET ticket_prefix = '$ticket_prefix_esc', ticket_number = $ticket_number, ticket_source = 'Email', ticket_subject = '$subject', ticket_details = '$message_esc', ticket_priority = 'Low', ticket_status = 1, ticket_billable = $config_ticket_default_billable, ticket_created_by = 0, ticket_contact_id = $contact_id, ticket_url_key = '$url_key', ticket_client_id = $client_id");
    $id = mysqli_insert_id($mysqli);

    // Logging
    logAction("Ticket", "Create", "Email parser: Client contact $contact_email_esc created ticket $ticket_prefix_esc$ticket_number ($subject) ($id)", $client_id, $id);

    mkdirMissing('../uploads/tickets/');
    $att_dir = "../uploads/tickets/" . $id . "/";
    mkdirMissing($att_dir);

    // Move original .eml into the ticket folder
    rename("../uploads/tmp/{$original_message_file}", "{$att_dir}/{$original_message_file}");
    $original_message_file_esc = mysqli_real_escape_string($mysqli, $original_message_file);
    mysqli_query($mysqli, "INSERT INTO ticket_attachments SET ticket_attachment_name = 'Original-parsed-email.eml', ticket_attachment_reference_name = '$original_message_file_esc', ticket_attachment_ticket_id = $id");

    // Save non-inline attachments
    foreach ($attachments as $attachment) {
        $att_name = $attachment['name'];
        $att_extension = strtolower(pathinfo($att_name, PATHINFO_EXTENSION));

        if (in_array($att_extension, $allowed_extensions)) {
            $att_saved_filename = md5(uniqid(rand(), true)) . '.' . $att_extension;
            $att_saved_path = $att_dir . $att_saved_filename;
            file_put_contents($att_saved_path, $attachment['content']);

            $ticket_attachment_name = sanitizeInput($att_name);
            $ticket_attachment_reference_name = sanitizeInput($att_saved_filename);

            $ticket_attachment_name_esc = mysqli_real_escape_string($mysqli, $ticket_attachment_name);
            $ticket_attachment_reference_name_esc = mysqli_real_escape_string($mysqli, $ticket_attachment_reference_name);
            mysqli_query($mysqli, "INSERT INTO ticket_attachments SET ticket_attachment_name = '$ticket_attachment_name_esc', ticket_attachment_reference_name = '$ticket_attachment_reference_name_esc', ticket_attachment_ticket_id = $id");
        } else {
            $ticket_attachment_name_esc = mysqli_real_escape_string($mysqli, $att_name);
            logAction("Ticket", "Edit", "Email parser: Blocked attachment $ticket_attachment_name_esc from Client contact $contact_email_esc for ticket $ticket_prefix_esc$ticket_number", $client_id, $id);
        }
    }

    // Add unknown guests as ticket watcher
    if ($client_id == 0 && !preg_match($bad_pattern, $contact_email_esc)) {
        mysqli_query($mysqli, "INSERT INTO ticket_watchers SET watcher_email = '$contact_email_esc', watcher_ticket_id = $id");
    }

    // Add CCs as ticket watchers
    foreach ($thread_ccs as $cc) {
        $cc_esc = mysqli_real_escape_string($mysqli, $cc);
        @mysqli_query($mysqli, "INSERT IGNORE INTO ticket_watchers SET watcher_email = '$cc_esc', watcher_ticket_id = $id");
    }

    // External email
    $data = [];
    if ($config_ticket_client_general_notifications == 1 && empty($mail_context['suppress_customer_notification']) && !preg_match($bad_pattern, $contact_email)) {
        $subject_email = "Ticket created - [$config_ticket_prefix$ticket_number] - $subject";
        $initial_conversation_history = intval($config_ticket_initial_history_enable ?? 1) === 1 ? parserBuildInitialConversationHistoryBlock($message) : '';
        $body = "<i style='color: #808080'>##- Please type your reply above this line -##</i><br><br>Hello $contact_name,<br><br>Thank you for your email. A ticket regarding &quot;$subject&quot; has been automatically created for you.<br><br>Ticket: $config_ticket_prefix$ticket_number<br>Subject: $subject<br>Status: New<br>Portal: <a href='https://$config_base_url/guest/guest_view_ticket.php?ticket_id=$id&url_key=$url_key'>View ticket</a>";
        if ($initial_conversation_history !== '') {
            $body .= "<br><br>" . $initial_conversation_history;
        }
        $body .= "<br><br>--<br>$company_name - Support<br>$config_ticket_from_email<br>$company_phone";

        // No-DB CC/threading bridge: store send metadata as an invisible HTML comment
        // in email_content. The patched mail_queue.php strips this marker before sending
        // and uses it to add CC, Reply-To, In-Reply-To, and References headers.
        $body = parserEmbedMailQueueMeta($body, [
            'cc' => $thread_ccs,
            'reply_to' => $config_ticket_from_email,
            'in_reply_to' => $mail_context['in_reply_to'] ?? '',
            'references' => $mail_context['references'] ?? ''
        ]);

        $data[] = [
            'from' => $config_ticket_from_email,
            'from_name' => $config_ticket_from_name,
            'recipient' => $contact_email,
            'recipient_name' => $contact_name,
            'subject' => $subject_email,
            'body' => mysqli_real_escape_string($mysqli, $body),
            'cc' => $thread_ccs,
            'reply_to' => $config_ticket_from_email,
            'in_reply_to' => $mail_context['in_reply_to'] ?? '',
            'references' => $mail_context['references'] ?? ''
        ];
    }

    // Internal email
    if ($config_ticket_new_ticket_notification_email) {
        if ($client_id == 0) {
            $client_name = "Guest";
            $client_uri = '';
        } else {
            $client_sql = mysqli_query($mysqli, "SELECT client_name FROM clients WHERE client_id = $client_id");
            $client_row = mysqli_fetch_assoc($client_sql);
            $client_name = sanitizeInput($client_row['client_name']);
            $client_uri = "&client_id=$client_id";
        }
        $email_subject = "$config_app_name - New Ticket - [$config_ticket_prefix$ticket_number] $client_name: $subject";
        $email_body = "Hello, <br><br>This is a notification that a new ticket has been raised in ITFlow. <br>Client: $client_name<br>Priority: Low (email parsed)<br>Ticket: $config_ticket_prefix$ticket_number<br>Subject: $subject<br>Status: New<br>Link: https://$config_base_url/agent/ticket.php?ticket_id=$id$client_uri <br><br>--------------------------------<br><br><b>$subject</b><br>$message";

        $data[] = [
            'from' => $config_ticket_from_email,
            'from_name' => $config_ticket_from_name,
            'recipient' => $config_ticket_new_ticket_notification_email,
            'recipient_name' => $config_ticket_from_name,
            'subject' => $email_subject,
            'body' => mysqli_real_escape_string($mysqli, $email_body)
        ];
    }

    addToMailQueue($data);
    customAction('ticket_create', $id);

    return true;
}


function parserIsTicketWatcherEmail(int $ticket_id, string $email): bool {
    global $mysqli;

    $ticket_id = intval($ticket_id);
    $email = parserNormalizeEmail($email);

    if ($ticket_id <= 0 || $email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $email_esc = mysqli_real_escape_string($mysqli, $email);
    $watcher_sql = mysqli_query(
        $mysqli,
        "SELECT watcher_email FROM ticket_watchers WHERE watcher_ticket_id = $ticket_id AND LOWER(watcher_email) = '$email_esc' LIMIT 1"
    );

    return ($watcher_sql && mysqli_num_rows($watcher_sql) > 0);
}


function parserFilterKnownContactEmails(array $emails, int $client_id): array {
    global $mysqli;

    $client_id = intval($client_id);
    if ($client_id <= 0) {
        return [];
    }

    $known = [];
    foreach ($emails as $email) {
        $email = parserNormalizeEmail((string)$email);
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            continue;
        }

        $email_esc = mysqli_real_escape_string($mysqli, $email);
        $contact_sql = mysqli_query(
            $mysqli,
            "SELECT contact_id FROM contacts WHERE LOWER(contact_email) = '$email_esc' AND contact_client_id = $client_id AND contact_archived_at IS NULL LIMIT 1"
        );

        if ($contact_sql && mysqli_num_rows($contact_sql) > 0) {
            $known[$email] = true;
        }
    }

    return array_keys($known);
}


function parserGetTicketStatusIdByName(string $status_name): int {
    global $mysqli;

    $status_name = trim($status_name);
    if ($status_name === '') {
        return 0;
    }

    $status_name_esc = mysqli_real_escape_string($mysqli, $status_name);
    $status_sql = mysqli_query(
        $mysqli,
        "SELECT ticket_status_id FROM ticket_statuses WHERE ticket_status_name = '$status_name_esc' AND ticket_status_active = 1 LIMIT 1"
    );

    if ($status_sql && ($status = mysqli_fetch_assoc($status_sql))) {
        return intval($status['ticket_status_id'] ?? 0);
    }

    return 0;
}

function parserGetTicketStatusNameById(int $status_id): string {
    global $mysqli;

    $status_id = intval($status_id);
    if ($status_id <= 0) {
        return '';
    }

    $status_sql = mysqli_query(
        $mysqli,
        "SELECT ticket_status_name FROM ticket_statuses WHERE ticket_status_id = $status_id AND ticket_status_active = 1 LIMIT 1"
    );

    if ($status_sql && ($status = mysqli_fetch_assoc($status_sql))) {
        return sanitizeInput($status['ticket_status_name'] ?? '');
    }

    return '';
}

function parserIsActiveTicketStatusId(int $status_id): bool {
    global $mysqli;

    $status_id = intval($status_id);
    if ($status_id <= 0) {
        return false;
    }

    $status_sql = mysqli_query(
        $mysqli,
        "SELECT ticket_status_id FROM ticket_statuses WHERE ticket_status_id = $status_id AND ticket_status_active = 1 LIMIT 1"
    );

    return ($status_sql && mysqli_num_rows($status_sql) > 0);
}

function parserResolveReplyTargetStatusId(): int {
    global $config_ticket_reply_target_status_id;

    $configured_status_id = intval($config_ticket_reply_target_status_id ?? 0);
    if (parserIsActiveTicketStatusId($configured_status_id)) {
        return $configured_status_id;
    }

    $open_id = parserGetTicketStatusIdByName('Open');
    if ($open_id > 0) {
        return $open_id;
    }

    return 2;
}

function parserResolveClosedStatusId(): int {
    $closed_id = parserGetTicketStatusIdByName('Closed');
    return $closed_id > 0 ? $closed_id : 5;
}

function parserBuildReplyTargetStatusNotificationBody(
    int $ticket_id,
    string $ticket_prefix,
    int $ticket_number,
    string $ticket_subject,
    string $client_name,
    int $client_id,
    string $reply_from_email,
    string $date,
    string $latest_reply_html,
    string $reply_target_status_name
): string {
    global $config_base_url, $company_name, $config_ticket_from_email, $company_phone;

    $client_uri = $client_id > 0 ? "&client_id=$client_id" : '';
    $ticket_link = "https://$config_base_url/agent/ticket.php?ticket_id=$ticket_id$client_uri";
    $client_label = $client_name !== '' ? $client_name : 'Guest / Unknown';

    $reply_html = queueSafeForHelpdeskNotification($latest_reply_html);

    return "Hello,<br><br>"
        . "A client/watcher reply was received and this ticket now needs attention.<br><br>"
        . "Client: $client_label<br>"
        . "Ticket: $ticket_prefix$ticket_number<br>"
        . "Subject: $ticket_subject<br>"
        . "Status: $reply_target_status_name<br>"
        . "Reply From: $reply_from_email<br>"
        . "Reply Date: $date<br>"
        . "Link: <a href='$ticket_link'>$ticket_link</a><br><br>"
        . "--------------------------------<br>"
        . $reply_html
        . "<br><br>--<br>$company_name - Support<br>$config_ticket_from_email<br>$company_phone";
}

function queueSafeForHelpdeskNotification(string $html): string {
    $html = trim($html);
    if ($html === '') {
        return '';
    }

    $html = queueStripMailMetaIfPresent($html);
    $html = preg_replace('/<!DOCTYPE[^>]*>/i', '', $html);
    $html = preg_replace('/<\/?(?:html|head|body)[^>]*>/i', '', $html);
    $html = preg_replace('/<\s*(script|style|iframe|object|embed|form|input|button|select|textarea|link|meta|base)[^>]*>.*?<\s*\/\s*\1\s*>/is', '', $html);
    $html = preg_replace('/<\s*(script|style|iframe|object|embed|form|input|button|select|textarea|link|meta|base)\b[^>]*\/?\s*>/is', '', $html);
    $html = preg_replace('/\s+on[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/i', '', $html);
    $html = preg_replace('/\s+(href|src)\s*=\s*("|\')\s*(javascript|data)\s*:[^"\']*("|\')/i', '', $html);

    if (strlen($html) > 30000) {
        $html = substr($html, 0, 30000) . "<br><br><i>[Reply truncated in notification email. Open the ticket for the full message.]</i>";
    }

    return $html;
}

function queueStripMailMetaIfPresent(string $html): string {
    return preg_replace('/^\s*<!--\s*ITFLOW_MAIL_META:[A-Za-z0-9+\/]+=*\s*-->\s*/', '', $html, 1);
}

function addReply($from_email, $date, $subject, $ticket_number, $message, $attachments) {
    global $mysqli, $config_app_name, $company_name, $company_phone, $config_ticket_prefix, $config_base_url, $config_ticket_from_name, $config_ticket_from_email, $config_ticket_new_ticket_notification_email, $config_ticket_reply_target_status_id, $config_ticket_watcher_reply_type, $allowed_extensions;

    $ticket_reply_type = 'Client';
    // $message contains the raw HTML body from IMAP

    // 1) Remove the reply separator and everything below it (HTML-aware)
    // This matches: <i ...>##- Please type your reply above this line -##</i> and EVERYTHING after it
    $message = preg_replace(
        '/<i[^>]*>##-\s*Please\s+type\s+your\s+reply\s+above\s+this\s+line\s*-##<\/i>.*$/is',
        '',
        $message
    );

    // 2) Clean up the remaining message

    // Remove DOCTYPE and meta tags
    $message = preg_replace('/<!DOCTYPE[^>]*>/i', '', $message);
    $message = preg_replace('/<meta[^>]*>/i', '', $message);

    // Remove <html>, <head>, <body> and their closing tags
    $message = preg_replace('/<\/?(html|head|body)[^>]*>/i', '', $message);

    // Trim leading/trailing whitespace
    $message = trim($message);

    // Normalize line breaks to spaces
    $message = preg_replace('/\r\n|\r|\n/', ' ', $message);

    // Convert to <br> for HTML display
    $message = nl2br($message);

    // 3) Final wrapper
    $message = "<i>Email from: $from_email at $date:-</i><br><br><div style='line-height:1.5;'>$message</div>";

    $ticket_number_esc = intval($ticket_number);
    $message_esc = mysqli_real_escape_string($mysqli, $message);
    $from_email_esc = mysqli_real_escape_string($mysqli, $from_email);

    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT ticket_id, ticket_subject, ticket_status, ticket_contact_id, ticket_client_id, contact_email, client_name
        FROM tickets
        LEFT JOIN contacts on tickets.ticket_contact_id = contacts.contact_id
        LEFT JOIN clients on tickets.ticket_client_id = clients.client_id
        WHERE ticket_number = $ticket_number_esc LIMIT 1"));

    if ($row) {
        $ticket_id = intval($row['ticket_id']);
        $ticket_subject = sanitizeInput($row['ticket_subject']);
        $ticket_status = sanitizeInput($row['ticket_status']);
        $ticket_reply_contact = intval($row['ticket_contact_id']);
        $ticket_contact_email = sanitizeInput($row['contact_email']);
        $client_id = intval($row['ticket_client_id']);
        if ($client_id) {
            $client_uri = "&client_id=$client_id";
        } else {
            $client_uri = '';
        }
        $client_name = sanitizeInput($row['client_name']);

        if ($ticket_status == parserResolveClosedStatusId()) {
            $config_ticket_prefix_esc = mysqli_real_escape_string($mysqli, $config_ticket_prefix);
            $ticket_number_esc2 = mysqli_real_escape_string($mysqli, $ticket_number);

            appNotify("Ticket", "Email parser: $from_email attempted to re-open ticket $config_ticket_prefix_esc$ticket_number_esc2 (ID $ticket_id) - check inbox manually to see email", "/agent/ticket.php?ticket_id=$ticket_id$client_uri", $client_id);

            $email_subject = "Action required: This ticket is already closed";
            $email_body = "Hi there, <br><br>You've tried to reply to a ticket that is closed - we won't see your response. <br><br>Please raise a new ticket by sending a new e-mail to our support address below. <br><br>--<br>$company_name - Support<br>$config_ticket_from_email<br>$company_phone";

            $data = [
                [
                    'from' => $config_ticket_from_email,
                    'from_name' => $config_ticket_from_name,
                    'recipient' => $from_email,
                    'recipient_name' => $from_email,
                    'subject' => $email_subject,
                    'body' => mysqli_real_escape_string($mysqli, $email_body)
                ]
            ];

            addToMailQueue($data);
            return true;
        }

        if (empty($ticket_contact_email) || parserNormalizeEmail($ticket_contact_email) !== parserNormalizeEmail($from_email)) {
            $from_email_esc2 = mysqli_real_escape_string($mysqli, parserNormalizeEmail($from_email));
            $row2 = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT contact_id FROM contacts WHERE LOWER(contact_email) = '$from_email_esc2' AND contact_client_id = $client_id LIMIT 1"));
            if ($row2) {
                $ticket_reply_contact = intval($row2['contact_id']);
                $ticket_reply_type = 'Client';
            } elseif (parserIsTicketWatcherEmail($ticket_id, $from_email)) {
                // CC/watchers are valid participants in the customer thread. Store as configured.
                $watcher_reply_type = (string)($config_ticket_watcher_reply_type ?? 'client');
                $ticket_reply_type = ($watcher_reply_type === 'internal') ? 'Internal' : 'Client';
                $ticket_reply_contact = '0';
            } else {
                $ticket_reply_type = 'Internal';
                $ticket_reply_contact = '0';
                $message = "<b>WARNING: Contact email mismatch</b><br>$message";
                $message_esc = mysqli_real_escape_string($mysqli, $message);
            }
        }

        mysqli_query($mysqli, "INSERT INTO ticket_replies SET ticket_reply = '$message_esc', ticket_reply_type = '$ticket_reply_type', ticket_reply_time_worked = '00:00:00', ticket_reply_by = $ticket_reply_contact, ticket_reply_ticket_id = $ticket_id");
        $reply_id = mysqli_insert_id($mysqli);

        $ticket_dir = "../uploads/tickets/" . $ticket_id . "/";
        mkdirMissing($ticket_dir);

        foreach ($attachments as $attachment) {
            $att_name = $attachment['name'];
            $att_extension = strtolower(pathinfo($att_name, PATHINFO_EXTENSION));

            if (in_array($att_extension, $allowed_extensions)) {
                $att_saved_filename = md5(uniqid(rand(), true)) . '.' . $att_extension;
                $att_saved_path = $ticket_dir . $att_saved_filename;
                file_put_contents($att_saved_path, $attachment['content']);

                $ticket_attachment_name = sanitizeInput($att_name);
                $ticket_attachment_reference_name = sanitizeInput($att_saved_filename);

                $ticket_attachment_name_esc = mysqli_real_escape_string($mysqli, $ticket_attachment_name);
                $ticket_attachment_reference_name_esc = mysqli_real_escape_string($mysqli, $ticket_attachment_reference_name);
                mysqli_query($mysqli, "INSERT INTO ticket_attachments SET ticket_attachment_name = '$ticket_attachment_name_esc', ticket_attachment_reference_name = '$ticket_attachment_reference_name_esc', ticket_attachment_reply_id = $reply_id, ticket_attachment_ticket_id = $ticket_id");
            } else {
                $ticket_attachment_name_esc = mysqli_real_escape_string($mysqli, $att_name);
                logAction("Ticket", "Edit", "Email parser: Blocked attachment $ticket_attachment_name_esc from Client contact $from_email_esc for ticket $config_ticket_prefix$ticket_number_esc", $client_id, $ticket_id);
            }
        }

        $ticket_assigned_to_sql = mysqli_query($mysqli, "SELECT ticket_assigned_to FROM tickets WHERE ticket_id = $ticket_id LIMIT 1");
        if ($ticket_assigned_to_sql) {
            $row3 = mysqli_fetch_assoc($ticket_assigned_to_sql);
            $ticket_assigned_to = intval($row3['ticket_assigned_to']);

            if ($ticket_assigned_to) {
                $tech_sql = mysqli_query($mysqli, "SELECT user_email, user_name FROM users WHERE user_id = $ticket_assigned_to LIMIT 1");
                $tech_row = mysqli_fetch_assoc($tech_sql);
                $tech_email = sanitizeInput($tech_row['user_email']);
                $tech_name = sanitizeInput($tech_row['user_name']);

                $email_subject = "$config_app_name - Ticket updated - [$config_ticket_prefix$ticket_number] $ticket_subject";
                $email_body    = "Hello $tech_name,<br><br>A new reply has been added to the below ticket.<br><br>Client: $client_name<br>Ticket: $config_ticket_prefix$ticket_number<br>Subject: $ticket_subject<br>Link: https://$config_base_url/agent/ticket.php?ticket_id=$ticket_id$client_uri<br><br>--------------------------------<br>$message_esc";

                $data = [
                    [
                        'from' => $config_ticket_from_email,
                        'from_name' => $config_ticket_from_name,
                        'recipient' => $tech_email,
                        'recipient_name' => $tech_name,
                        'subject' => mysqli_real_escape_string($mysqli, $email_subject),
                        'body' => mysqli_real_escape_string($mysqli, $email_body)
                    ]
                ];
                addToMailQueue($data);
            }
        }

        $reply_target_status_id = parserResolveReplyTargetStatusId();
        $reply_target_status_name = parserGetTicketStatusNameById($reply_target_status_id);
        if ($reply_target_status_name === '') {
            $reply_target_status_name = 'Configured Reply Target Status';
        }
        $previous_ticket_status_id = intval($ticket_status);
        $status_changed_to_reply_target = false;

        if ($ticket_reply_type === 'Client') {
            mysqli_query($mysqli, "UPDATE tickets SET ticket_status = $reply_target_status_id, ticket_resolved_at = NULL WHERE ticket_id = $ticket_id AND ticket_client_id = $client_id LIMIT 1");
            $status_changed_to_reply_target = ($reply_target_status_id > 0 && $previous_ticket_status_id !== $reply_target_status_id);

            if ($status_changed_to_reply_target && itflowShouldLogEmailReplyTicketReopen($previous_ticket_status_id, $reply_target_status_id)) {
                itflowLogEmailReplyTicketReopen($ticket_id, $client_id, parserGetTicketStatusNameById($previous_ticket_status_id)); // ITFLOW_EMAIL_REPLY_REOPEN_ACTIVITY_LOG_CALL
            }
        }

        if ($status_changed_to_reply_target && !empty($config_ticket_new_ticket_notification_email)) {
            $helpdesk_notify_email = sanitizeInput($config_ticket_new_ticket_notification_email);
            if (filter_var($helpdesk_notify_email, FILTER_VALIDATE_EMAIL)) {
                $email_subject = "$config_app_name - $reply_target_status_name - [$config_ticket_prefix$ticket_number] $ticket_subject";
                $email_body = parserBuildReplyTargetStatusNotificationBody(
                    $ticket_id,
                    $config_ticket_prefix,
                    intval($ticket_number),
                    $ticket_subject,
                    $client_name,
                    $client_id,
                    $from_email,
                    $date,
                    $message,
                    $reply_target_status_name
                );

                $data = [
                    [
                        'from' => $config_ticket_from_email,
                        'from_name' => $config_ticket_from_name,
                        'recipient' => $helpdesk_notify_email,
                        'recipient_name' => 'Helpdesk Notifications',
                        'subject' => mysqli_real_escape_string($mysqli, $email_subject),
                        'body' => mysqli_real_escape_string($mysqli, $email_body)
                    ]
                ];
                addToMailQueue($data);
                logApp("Cron-Email-Parser", "info", "Ticket $config_ticket_prefix$ticket_number changed to $reply_target_status_name after client/watcher reply from $from_email and notification queued to $helpdesk_notify_email.");
            } else {
                logApp("Cron-Email-Parser", "warning", "Ticket $config_ticket_prefix$ticket_number changed to $reply_target_status_name but config_ticket_new_ticket_notification_email is not a valid email address.");
            }
        }

        logAction("Ticket", "Edit", "Email parser: Client contact $from_email_esc updated ticket $config_ticket_prefix$ticket_number_esc ($subject)", $client_id, $ticket_id);
        customAction('ticket_reply_client', $ticket_id);
        return true;
    } else {
        return false;
    }
}



/** ------------------------------------------------------------------
 * Sender resolver for Google Groups / mailing-list rewrites
 * ------------------------------------------------------------------ */
function parserNormalizeEmail(?string $email): string {
    $email = strtolower(trim((string)$email));
    if (stripos($email, 'mailto:') === 0) {
        $email = substr($email, 7);
    }
    return trim($email, " \t\n\r\0\x0B<>\"'.,;");
}

function parserGetRawHeaderValues(string $raw_headers, string $header_name): array {
    $unfolded = preg_replace("/\r?\n[ \t]+/", " ", $raw_headers);
    $values = [];
    if (preg_match_all('/^' . preg_quote($header_name, '/') . ':\s*(.+)$/mi', $unfolded, $matches)) {
        foreach ($matches[1] as $value) {
            $value = trim($value);
            if ($value !== '') {
                $values[] = $value;
            }
        }
    }
    return $values;
}

function parserDecodeHeaderValue(?string $header_value): string {
    $decoded = trim((string)$header_value);
    if ($decoded === '') {
        return '';
    }

    if (function_exists('iconv_mime_decode')) {
        $tmp = @iconv_mime_decode($decoded, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
        if ($tmp !== false && $tmp !== '') {
            $decoded = $tmp;
        }
    }

    return trim($decoded);
}

function parserExtractEmailCandidate(?string $header_value, string $source): ?array {
    $decoded = parserDecodeHeaderValue($header_value);
    if ($decoded === '') {
        return null;
    }

    $email = null;
    if (preg_match('/<([^<>,;\s]+@[^<>,;\s]+)>/', $decoded, $match)) {
        $email = parserNormalizeEmail($match[1]);
    } elseif (preg_match('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', $decoded, $match)) {
        $email = parserNormalizeEmail($match[0]);
    }

    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return null;
    }

    $name = trim(preg_replace('/<[^>]*>/', '', $decoded));
    $name = trim(str_ireplace($email, '', $name));
    $name = trim($name, " \t\n\r\0\x0B\"'");

    return [
        'email' => $email,
        'name' => $name ?: null,
        'source' => $source,
        'raw' => $decoded,
    ];
}

function parserAddAddressCandidate(array &$candidates, ?string $email, ?string $name, string $source, ?string $raw = null): void {
    $email = parserNormalizeEmail($email);
    if ($email && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $candidates[] = [
            'email' => $email,
            'name' => $name ? trim($name) : null,
            'source' => $source,
            'raw' => $raw ?: $email,
        ];
    }
}

function parserAddCandidatesFromAddressCollection(array &$candidates, $collection, string $source): void {
    if (!$collection) {
        return;
    }

    try {
        if (is_object($collection) && method_exists($collection, 'toArray')) {
            foreach ($collection->toArray() as $address) {
                if ($address instanceof \Webklex\PHPIMAP\Address || is_object($address)) {
                    parserAddAddressCandidate($candidates, $address->mail ?? null, $address->personal ?? null, $source);
                } elseif (is_string($address)) {
                    $candidate = parserExtractEmailCandidate($address, $source);
                    if ($candidate) $candidates[] = $candidate;
                }
            }
            return;
        }

        if (is_object($collection) && method_exists($collection, 'count') && method_exists($collection, 'first') && $collection->count()) {
            $address = $collection->first();
            if ($address) {
                parserAddAddressCandidate($candidates, $address->mail ?? null, $address->personal ?? null, $source);
            }
            return;
        }

        if (is_array($collection) || $collection instanceof \Traversable) {
            foreach ($collection as $address) {
                if ($address instanceof \Webklex\PHPIMAP\Address || is_object($address)) {
                    parserAddAddressCandidate($candidates, $address->mail ?? null, $address->personal ?? null, $source);
                } elseif (is_string($address)) {
                    $candidate = parserExtractEmailCandidate($address, $source);
                    if ($candidate) $candidates[] = $candidate;
                }
            }
        }
    } catch (\Throwable $e) {
        // Keep parsing email even if a non-standard header object behaves badly.
    }
}

function parserGetReplyToCandidates($message): array {
    $candidates = [];

    try {
        if (is_object($message) && method_exists($message, 'getReplyTo')) {
            parserAddCandidatesFromAddressCollection($candidates, $message->getReplyTo(), 'parsed Reply-To');
        }
    } catch (\Throwable $e) {
        // Fall through to header-object/raw parsing.
    }

    try {
        if (isset($message->header->reply_to)) {
            $reply_to = $message->header->reply_to;
            if (is_string($reply_to)) {
                $candidate = parserExtractEmailCandidate($reply_to, 'header Reply-To');
                if ($candidate) $candidates[] = $candidate;
            } elseif (is_object($reply_to) && method_exists($reply_to, 'toArray')) {
                parserAddCandidatesFromAddressCollection($candidates, $reply_to, 'header Reply-To');
            } else {
                $candidate = parserExtractEmailCandidate((string)$reply_to, 'header Reply-To');
                if ($candidate) $candidates[] = $candidate;
            }
        }
    } catch (\Throwable $e) {
        // Ignore and rely on raw headers.
    }

    return $candidates;
}

function parserIsAutomatedAddress(?string $email): bool {
    $email = parserNormalizeEmail($email);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return true;
    }
    $local_part = strtolower(strtok($email, '@') ?: '');
    return (bool)preg_match('/^(mailer-daemon|postmaster|bounce|bounces|mta|no-reply|noreply)([+._-]|$)/i', $local_part);
}

function parserCandidateDebugSummary(array $candidates): string {
    if (!$candidates) {
        return 'none';
    }

    $parts = [];
    foreach ($candidates as $candidate) {
        $source = $candidate['source'] ?? 'unknown';
        $email = $candidate['email'] ?? 'invalid';
        $parts[] = "$source=$email";
    }
    return implode('; ', array_unique($parts));
}

function parserResolveGroupRewrittenSender($message, string $raw_headers, string $from_email, string $from_name, array $local_addresses): array {
    $local_addresses = array_values(array_unique(array_filter(array_map('parserNormalizeEmail', $local_addresses))));
    $from_email_lc = parserNormalizeEmail($from_email);

    // Do not trust Reply-To/X-* globally. Only override when Gmail/Google Groups delivered the message
    // as one of the configured infrastructure addresses.
    if (!in_array($from_email_lc, $local_addresses, true)) {
        return [$from_email, $from_name, null, 'not-local-from'];
    }

    $candidates = [];

    // Prefer headers intended to preserve original sender identity, then fall back to Reply-To.
    foreach (['X-Original-Sender', 'X-Original-From', 'X-Google-Original-From', 'Original-From'] as $header_name) {
        foreach (parserGetRawHeaderValues($raw_headers, $header_name) as $value) {
            $candidate = parserExtractEmailCandidate($value, $header_name);
            if ($candidate) $candidates[] = $candidate;
        }
    }

    foreach (parserGetReplyToCandidates($message) as $candidate) {
        $candidates[] = $candidate;
    }

    foreach (parserGetRawHeaderValues($raw_headers, 'Reply-To') as $value) {
        $candidate = parserExtractEmailCandidate($value, 'raw Reply-To');
        if ($candidate) $candidates[] = $candidate;
    }

    foreach ($candidates as $candidate) {
        $candidate_email = parserNormalizeEmail($candidate['email'] ?? '');
        if (!$candidate_email || !filter_var($candidate_email, FILTER_VALIDATE_EMAIL)) {
            continue;
        }
        if (in_array($candidate_email, $local_addresses, true)) {
            continue;
        }
        if (parserIsAutomatedAddress($candidate_email)) {
            continue;
        }

        $candidate_name = trim((string)($candidate['name'] ?? ''));
        if ($candidate_name === '') {
            // Clean up names like "'Allied IT' via Support" when Google rewrites From.
            $candidate_name = preg_replace('/\s+via\s+.+$/i', '', $from_name);
            $candidate_name = trim($candidate_name, " \t\n\r\0\x0B\"'");
        }
        if ($candidate_name === '') {
            $candidate_name = $candidate_email;
        }

        return [$candidate_email, $candidate_name, $candidate['source'] ?? 'unknown', parserCandidateDebugSummary($candidates)];
    }

    return [$from_email, $from_name, null, parserCandidateDebugSummary($candidates)];
}


function parserNormalizeEmailList(array $emails, array $exclude = [], ?string $bad_pattern = null): array {
    $exclude_map = [];
    foreach ($exclude as $email) {
        $email = parserNormalizeEmail($email);
        if ($email !== '') {
            $exclude_map[$email] = true;
        }
    }

    $out = [];
    foreach ($emails as $email) {
        if (is_array($email)) {
            $email = $email['email'] ?? $email['mail'] ?? '';
        } elseif (is_object($email)) {
            $email = $email->mail ?? '';
        }

        $email = parserNormalizeEmail((string)$email);
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            continue;
        }
        if (isset($exclude_map[$email])) {
            continue;
        }
        if ($bad_pattern && preg_match($bad_pattern, $email)) {
            continue;
        }
        if (parserIsAutomatedAddress($email)) {
            continue;
        }
        $out[$email] = true;
    }

    return array_keys($out);
}

function parserGetRawHeaderFirstValue(string $raw_headers, string $header_name): string {
    $values = parserGetRawHeaderValues($raw_headers, $header_name);
    return $values[0] ?? '';
}

function parserSanitizeMessageId(?string $value): string {
    $value = parserDecodeHeaderValue($value);
    if ($value === '') {
        return '';
    }

    if (preg_match('/<[^<>\s]+@[^<>\s]+>/', $value, $match)) {
        return $match[0];
    }

    return '';
}

function parserBuildThreadHeaders(string $raw_headers): array {
    $message_id = parserSanitizeMessageId(parserGetRawHeaderFirstValue($raw_headers, 'Message-ID'));
    $references_raw = parserDecodeHeaderValue(parserGetRawHeaderFirstValue($raw_headers, 'References'));
    $references = '';

    if ($references_raw !== '' && preg_match_all('/<[^<>\s]+@[^<>\s]+>/', $references_raw, $matches)) {
        $references = implode(' ', array_unique($matches[0]));
    }

    if ($message_id !== '') {
        if ($references === '') {
            $references = $message_id;
        } elseif (strpos($references, $message_id) === false) {
            $references .= ' ' . $message_id;
        }
    }

    return [
        'in_reply_to' => $message_id,
        'references' => $references,
    ];
}


function parserCleanMailQueueHeaderValue(?string $value): string {
    $value = trim((string)$value);
    // Prevent header injection if this metadata is ever malformed.
    $value = str_replace(["\r", "\n"], '', $value);
    return substr($value, 0, 998);
}

function parserEmbedMailQueueMeta(string $body, array $meta): string {
    $cc = [];
    if (!empty($meta['cc']) && is_array($meta['cc'])) {
        foreach ($meta['cc'] as $email) {
            $email = parserNormalizeEmail((string)$email);
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $cc[$email] = true;
            }
        }
    }

    $reply_to = parserNormalizeEmail((string)($meta['reply_to'] ?? ''));
    if (!filter_var($reply_to, FILTER_VALIDATE_EMAIL)) {
        $reply_to = '';
    }

    $payload = [
        'cc' => array_keys($cc),
        'reply_to' => $reply_to,
        'in_reply_to' => parserCleanMailQueueHeaderValue($meta['in_reply_to'] ?? ''),
        'references' => parserCleanMailQueueHeaderValue($meta['references'] ?? ''),
    ];

    $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return $body;
    }

    // Keep this compact and invisible. If mail_queue.php is not patched yet, the marker
    // remains an HTML comment and customers will not see it.
    $encoded = base64_encode($json);
    return "<!-- ITFLOW_MAIL_META:$encoded -->\n" . $body;
}


/** ------------------------------------------------------------------
 * Internal delegation / ignored unknown-thread helpers
 * ------------------------------------------------------------------ */
function parserConfiguredInternalDomains(): array {
    global $config_mail_internal_domains;

    $configured = (string)($config_mail_internal_domains ?? '');
    $domains = [];

    foreach (preg_split('/[\r\n,;]+/', $configured) as $domain) {
        $domain = strtolower(trim((string)$domain));
        $domain = ltrim($domain, '@');
        if ($domain !== '' && preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $domain)) {
            $domains[$domain] = true;
        }
    }

    return array_keys($domains);
}

function parserIsInternalEmail(?string $email): bool {
    $email = parserNormalizeEmail($email);
    if ($email === '' || strpos($email, '@') === false) {
        return false;
    }

    $domain = strtolower(substr(strrchr($email, '@'), 1));
    if ($domain === '') {
        return false;
    }

    foreach (parserConfiguredInternalDomains() as $internal_domain) {
        if ($domain === $internal_domain) {
            return true;
        }
    }

    return false;
}

function parserHasForceTicketToken(string $subject): bool {
    return (bool)preg_match('/\[(?:create|force)\s+ticket\]/i', $subject);
}

function parserStripForceTicketToken(string $subject): string {
    $subject = preg_replace('/\s*\[(?:create|force)\s+ticket\]\s*/i', ' ', $subject);
    return trim(preg_replace('/\s+/', ' ', $subject));
}

function parserExtractMessageIdsFromString(?string $value): array {
    $value = parserDecodeHeaderValue($value);
    if ($value === '') {
        return [];
    }

    if (!preg_match_all('/<[^<>\s]+@[^<>\s]+>/', $value, $matches)) {
        return [];
    }

    return array_values(array_unique($matches[0]));
}

function parserIgnoredThreadCachePath(): string {
    $dir = '../uploads/tmp';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    return $dir . '/itflow_ignored_email_threads.json';
}

function parserLoadIgnoredThreads(): array {
    $path = parserIgnoredThreadCachePath();
    if (!is_file($path)) {
        return [];
    }

    $raw = @file_get_contents($path);
    $data = json_decode((string)$raw, true);
    if (!is_array($data)) {
        return [];
    }

    // Keep cache bounded and prune entries older than 30 days.
    $cutoff = time() - (30 * 86400);
    $out = [];
    foreach ($data as $message_id => $row) {
        $message_id = trim((string)$message_id);
        $created = intval($row['created'] ?? 0);
        if ($message_id !== '' && $created >= $cutoff) {
            $out[$message_id] = $row;
        }
    }

    return $out;
}

function parserSaveIgnoredThreads(array $data): void {
    $path = parserIgnoredThreadCachePath();

    // Bound the cache so a long-running install does not grow this forever.
    if (count($data) > 1000) {
        uasort($data, function($a, $b) {
            return intval($b['created'] ?? 0) <=> intval($a['created'] ?? 0);
        });
        $data = array_slice($data, 0, 1000, true);
    }

    @file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function parserRecordIgnoredThread(string $message_id, string $from_email, string $subject): void {
    $message_id = parserSanitizeMessageId($message_id);
    if ($message_id === '') {
        return;
    }

    $data = parserLoadIgnoredThreads();
    $data[$message_id] = [
        'created' => time(),
        'from' => parserNormalizeEmail($from_email),
        'subject' => substr($subject, 0, 300),
    ];
    parserSaveIgnoredThreads($data);
}

function parserReferencesIgnoredThread(array $thread_headers): bool {
    $ids = [];
    foreach (['in_reply_to', 'references'] as $key) {
        foreach (parserExtractMessageIdsFromString($thread_headers[$key] ?? '') as $id) {
            $ids[] = $id;
        }
    }

    if (!$ids) {
        return false;
    }

    $ignored = parserLoadIgnoredThreads();
    foreach (array_unique($ids) as $id) {
        if (isset($ignored[$id])) {
            return true;
        }
    }

    return false;
}


function parserIsLikelySelfGeneratedInfrastructureMail(string $from_email, string $subject, string $raw_headers, array $local_inbound_addresses): bool {
    $from_email = parserNormalizeEmail($from_email);

    if ($from_email === '' || !in_array($from_email, $local_inbound_addresses, true)) {
        return false;
    }

    $subject = trim($subject);
    $raw_headers = (string)$raw_headers;

    // Ticket notifications generated by this ITFlow instance and then delivered back into
    // the parser mailbox through a Google Group / shared support address must be ignored.
    // Real Google Group customer mail should have X-Original-Sender / X-Original-From and
    // will be resolved before this check.
    if (
        preg_match('/\bTicket\s+(Created|Updated|update|created)\b/i', $subject)
        || preg_match('/\bNew\s+Ticket\b/i', $subject)
        || preg_match('/\bITFlow\b/i', $raw_headers)
        || preg_match('/Received:\s+from\s+ITFlow\b/i', $raw_headers)
        || preg_match('/Message-ID:\s*<[^>]+@ITFlow>/i', $raw_headers)
    ) {
        return true;
    }

    return false;
}



function parserIsForwardedMessage(string $subject, string $body, array $attachments = []): bool {
    if (preg_match('/^\s*(fw|fwd)\s*:/i', $subject)) {
        return true;
    }

    $plain = html_entity_decode(strip_tags($body), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    if (preg_match('/(-{2,}\s*Forwarded message\s*-{2,}|Begin forwarded message:|^From:\s.+\R(?:.*\R){0,8}?(?:Sent|Date|To|Subject):)/mi', $plain)) {
        return true;
    }

    foreach ($attachments as $attachment) {
        $name = strtolower((string)($attachment['name'] ?? ''));
        if (substr($name, -4) === '.eml') {
            return true;
        }
    }

    return false;
}

function parserExtractEmailAddressesFromString(?string $text): array {
    $text = html_entity_decode(strip_tags((string)$text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    if ($text === '') {
        return [];
    }

    if (!preg_match_all('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', $text, $matches)) {
        return [];
    }

    $out = [];
    foreach ($matches[0] as $email) {
        $email = parserNormalizeEmail($email);
        if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL) && !parserIsAutomatedAddress($email)) {
            $out[$email] = true;
        }
    }

    return array_keys($out);
}

function parserExtractForwardedFromEmails(string $body): array {
    $plain = html_entity_decode(strip_tags($body), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $out = [];

    if (preg_match_all('/^\s*From:\s*(.+)$/mi', $plain, $matches)) {
        foreach ($matches[1] as $from_line) {
            $candidate = parserExtractEmailCandidate($from_line, 'forwarded From');
            if ($candidate && !parserIsInternalEmail($candidate['email'])) {
                $out[] = $candidate;
            }
        }
    }

    return $out;
}

function parserGetKnownClientIdentityFromEmail(string $email, ?string $fallback_name = null, bool $create_contact_for_domain = true): ?array {
    global $mysqli;

    $email = parserNormalizeEmail($email);
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || parserIsAutomatedAddress($email)) {
        return null;
    }

    $email_esc = mysqli_real_escape_string($mysqli, $email);
    $contact_sql = mysqli_query(
        $mysqli,
        "SELECT contact_id, contact_name, contact_email, contact_client_id
         FROM contacts
         WHERE LOWER(contact_email) = '$email_esc' AND contact_archived_at IS NULL
         LIMIT 1"
    );

    if ($contact_sql && ($contact = mysqli_fetch_assoc($contact_sql))) {
        return [
            'contact_id' => intval($contact['contact_id']),
            'contact_name' => sanitizeInput($contact['contact_name']),
            'contact_email' => sanitizeInput($contact['contact_email']),
            'client_id' => intval($contact['contact_client_id']),
            'source' => 'known contact',
        ];
    }

    $domain = substr(strrchr($email, '@') ?: '', 1);
    $domain = parserNormalizeEmail($domain);
    if ($domain === '') {
        return null;
    }

    $domain_esc = mysqli_real_escape_string($mysqli, $domain);
    $domain_sql = mysqli_query(
        $mysqli,
        "SELECT domain_client_id
         FROM domains
         WHERE LOWER(domain_name) = '$domain_esc' AND domain_archived_at IS NULL
         LIMIT 1"
    );

    if ($domain_sql && ($domain_row = mysqli_fetch_assoc($domain_sql))) {
        $client_id = intval($domain_row['domain_client_id']);
        $name = trim((string)$fallback_name);
        if ($name === '') {
            $name = $email;
        }

        if ($create_contact_for_domain && $client_id > 0) {
            $name_esc = mysqli_real_escape_string($mysqli, sanitizeInput($name));
            mysqli_query(
                $mysqli,
                "INSERT INTO contacts SET
                    contact_name = '$name_esc',
                    contact_email = '$email_esc',
                    contact_notes = 'Added automatically via internal email delegation parsing.',
                    contact_client_id = $client_id"
            );
            $contact_id = mysqli_insert_id($mysqli);
            logAction("Contact", "Create", "Email parser: created contact $name_esc via internal delegation/domain match", $client_id, $contact_id);
            customAction('contact_create', $contact_id);
        } else {
            $contact_id = 0;
        }

        return [
            'contact_id' => intval($contact_id),
            'contact_name' => sanitizeInput($name),
            'contact_email' => $email,
            'client_id' => $client_id,
            'source' => 'known domain',
        ];
    }

    return null;
}

function parserFindBestClientIdentityInThread(
    string $from_email,
    string $from_name,
    string $raw_headers,
    string $body,
    array $ccs,
    array $local_addresses
): ?array {
    $local_map = [];
    foreach ($local_addresses as $email) {
        $email = parserNormalizeEmail($email);
        if ($email !== '') {
            $local_map[$email] = true;
        }
    }

    $candidate_records = [];

    // Forwarded From: is the strongest signal for internal forwarding.
    foreach (parserExtractForwardedFromEmails($body) as $candidate) {
        $candidate_records[] = $candidate;
    }

    // Reply-To / From / To / Cc headers are next.
    foreach (['Reply-To', 'From', 'To', 'Cc'] as $header_name) {
        foreach (parserGetRawHeaderValues($raw_headers, $header_name) as $value) {
            $candidate = parserExtractEmailCandidate($value, "raw $header_name");
            if ($candidate) {
                $candidate_records[] = $candidate;
            }
            foreach (parserExtractEmailAddressesFromString($value) as $email) {
                $candidate_records[] = ['email' => $email, 'name' => null, 'source' => "raw $header_name"];
            }
        }
    }

    // Parsed CCs from Webklex.
    foreach ($ccs as $email) {
        $candidate_records[] = ['email' => $email, 'name' => null, 'source' => 'parsed Cc'];
    }

    // Body/quoted thread addresses are weaker but useful when an internal person originated the chain.
    foreach (parserExtractEmailAddressesFromString($body) as $email) {
        $candidate_records[] = ['email' => $email, 'name' => null, 'source' => 'message body'];
    }

    foreach ($candidate_records as $candidate) {
        $email = parserNormalizeEmail($candidate['email'] ?? '');
        if ($email === '' || isset($local_map[$email]) || parserIsInternalEmail($email)) {
            continue;
        }

        $identity = parserGetKnownClientIdentityFromEmail($email, $candidate['name'] ?? null, true);
        if ($identity) {
            $identity['matched_email'] = $email;
            $identity['matched_source'] = $candidate['source'] ?? 'unknown';
            return $identity;
        }
    }

    return null;
}

function parserBuildInternalDelegationBody(string $body, string $from_name, string $from_email, ?array $identity): string {
    $from_label = trim($from_name) !== '' ? "$from_name <$from_email>" : $from_email;
    $match = '';
    if ($identity) {
        $match = "<br>Matched client/contact using {$identity['matched_source']}: {$identity['matched_email']}";
    }

    return "<div style='border-left:3px solid #0ea5e9;padding-left:10px;margin-bottom:12px;color:#334155;'>"
        . "<b>Internal delegation</b><br>"
        . "Forwarded/CC'd to support by: " . htmlspecialchars($from_label, ENT_QUOTES | ENT_HTML5, 'UTF-8')
        . $match
        . "</div>"
        . $body;
}

/** ------------------------------------------------------------------
 * OAuth helpers + provider guard
 * ------------------------------------------------------------------ */

// returns true if expires_at ('Y-m-d H:i:s') is in the past (or missing)
function tokenExpired(?string $expires_at): bool {
    if (empty($expires_at)) return true;
    $ts = strtotime($expires_at);
    if ($ts === false) return true;
    // refresh a little early (60s) to avoid race
    return ($ts - 60) <= time();
}

// very small form-encoded POST helper using curl
function httpFormPost(string $url, array $fields): array {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($fields, '', '&'));
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ['ok' => ($raw !== false && $code >= 200 && $code < 300), 'body' => $raw, 'code' => $code, 'err' => $err];
}

/**
 * Get a valid access token for Google Workspace IMAP via refresh token if needed.
 * Uses settings: config_mail_oauth_client_id / _client_secret / _refresh_token / _access_token / _access_token_expires_at
 * Updates globals if refreshed (so later logging can reflect it if you want to persist).
 */
function getGoogleAccessToken(string $username): ?string {
    // pull from global settings variables you already load
    global $mysqli,
           $config_mail_oauth_client_id,
           $config_mail_oauth_client_secret,
           $config_mail_oauth_refresh_token,
           $config_mail_oauth_access_token,
           $config_mail_oauth_access_token_expires_at;

    // If we have a not-expired token, use it
    if (!empty($config_mail_oauth_access_token) && !tokenExpired($config_mail_oauth_access_token_expires_at)) {
        return $config_mail_oauth_access_token;
    }

    // Need to refresh?
    if (empty($config_mail_oauth_client_id) || empty($config_mail_oauth_client_secret) || empty($config_mail_oauth_refresh_token)) {
        // Nothing we can do
        return null;
    }

    $resp = httpFormPost(
        'https://oauth2.googleapis.com/token',
        [
            'client_id'     => $config_mail_oauth_client_id,
            'client_secret' => $config_mail_oauth_client_secret,
            'refresh_token' => $config_mail_oauth_refresh_token,
            'grant_type'    => 'refresh_token',
        ]
    );

    if (!$resp['ok']) return null;

    $json = json_decode($resp['body'], true);
    if (!is_array($json) || empty($json['access_token'])) return null;

    // Calculate new expiry
    $expires_at = date('Y-m-d H:i:s', time() + (int)($json['expires_in'] ?? 3600));

    // Update in-memory globals (and persist to DB)
    $config_mail_oauth_access_token = $json['access_token'];
    $config_mail_oauth_access_token_expires_at = $expires_at;

    $at_esc  = mysqli_real_escape_string($mysqli, $config_mail_oauth_access_token);
    $exp_esc = mysqli_real_escape_string($mysqli, $config_mail_oauth_access_token_expires_at);
    mysqli_query($mysqli, "UPDATE settings SET
        config_mail_oauth_access_token = '{$at_esc}',
        config_mail_oauth_access_token_expires_at = '{$exp_esc}'
        WHERE company_id = 1
    ");

    return $config_mail_oauth_access_token;
}

/**
 * Get a valid access token for Microsoft 365 IMAP via refresh token if needed.
 * Uses settings: config_mail_oauth_client_id / _client_secret / _tenant_id / _refresh_token / _access_token / _access_token_expires_at
 */
function getMicrosoftAccessToken(string $username): ?string {
    global $mysqli,
           $config_mail_oauth_client_id,
           $config_mail_oauth_client_secret,
           $config_mail_oauth_tenant_id,
           $config_mail_oauth_refresh_token,
           $config_mail_oauth_access_token,
           $config_mail_oauth_access_token_expires_at;

    if (!empty($config_mail_oauth_access_token) && !tokenExpired($config_mail_oauth_access_token_expires_at)) {
        return $config_mail_oauth_access_token;
    }

    if (empty($config_mail_oauth_client_id) || empty($config_mail_oauth_client_secret) || empty($config_mail_oauth_refresh_token) || empty($config_mail_oauth_tenant_id)) {
        return null;
    }

    $url = "https://login.microsoftonline.com/".rawurlencode($config_mail_oauth_tenant_id)."/oauth2/v2.0/token";

    $resp = httpFormPost($url, [
        'client_id'     => $config_mail_oauth_client_id,
        'client_secret' => $config_mail_oauth_client_secret,
        'refresh_token' => $config_mail_oauth_refresh_token,
        'grant_type'    => 'refresh_token',
        // IMAP/SMTP scopes typically included at initial consent; not needed for refresh
    ]);

    if (!$resp['ok']) return null;

    $json = json_decode($resp['body'], true);
    if (!is_array($json) || empty($json['access_token'])) return null;

    $expires_at = date('Y-m-d H:i:s', time() + (int)($json['expires_in'] ?? 3600));

    $config_mail_oauth_access_token = $json['access_token'];
    $config_mail_oauth_access_token_expires_at = $expires_at;

    $at_esc  = mysqli_real_escape_string($mysqli, $config_mail_oauth_access_token);
    $exp_esc = mysqli_real_escape_string($mysqli, $config_mail_oauth_access_token_expires_at);
    mysqli_query($mysqli, "UPDATE settings SET
        config_mail_oauth_access_token = '{$at_esc}',
        config_mail_oauth_access_token_expires_at = '{$exp_esc}'
        WHERE company_id = 1
    ");

    return $config_mail_oauth_access_token;
}

// Provider from settings (may be NULL/empty to disable IMAP polling)
$imap_provider = $config_imap_provider ?? '';
if ($imap_provider === null) $imap_provider = '';

if ($imap_provider === '') {
    // IMAP disabled by admin: exit cleanly
    logApp("Cron-Email-Parser", "info", "IMAP polling skipped: provider not configured.");
    @unlink($lock_file_path);
    exit(0);
}

/** ------------------------------------------------------------------
 * Webklex IMAP setup (supports Standard / Google OAuth / Microsoft OAuth)
 * ------------------------------------------------------------------ */
use Webklex\PHPIMAP\ClientManager;

$validate_cert = true;

// Defaults from settings (standard IMAP)
$host = $config_imap_host;
$port = (int)$config_imap_port;
$encr = !empty($config_imap_encryption) ? $config_imap_encryption : 'notls'; // 'ssl'|'tls'|'notls'
$user = $config_imap_username;
$pass = $config_imap_password;
$auth = null; // 'oauth' for OAuth providers

if ($imap_provider === 'google_oauth') {
    $host = 'imap.gmail.com';
    $port = 993;
    $encr = 'ssl';
    $auth = 'oauth';
    $pass = getGoogleAccessToken($user);
    if (empty($pass)) {
        logApp("Cron-Email-Parser", "error", "Google OAuth: no usable access token (check refresh token/client credentials).");
        @unlink($lock_file_path);
        exit(1);
    }
} elseif ($imap_provider === 'microsoft_oauth') {
    $host = 'outlook.office365.com';
    $port = 993;
    $encr = 'ssl';
    $auth = 'oauth';
    $pass = getMicrosoftAccessToken($user);
    if (empty($pass)) {
        logApp("Cron-Email-Parser", "error", "Microsoft OAuth: no usable access token (check refresh token/client credentials/tenant).");
        @unlink($lock_file_path);
        exit(1);
    }
} else {
    // standard_imap (username/password)
    if (empty($host) || empty($port) || empty($user)) {
        logApp("Cron-Email-Parser", "error", "Standard IMAP: missing host/port/username.");
        @unlink($lock_file_path);
        exit(1);
    }
}

$cm = new ClientManager();

$client = $cm->make(array_filter([
    'host'           => $host,
    'port'           => $port,
    'encryption'     => $encr,            // 'ssl' | 'tls' | null
    'validate_cert'  => (bool)$validate_cert,
    'username'       => $user,            // full mailbox address (OAuth uses user as principal)
    'password'       => $pass,            // access token when $auth === 'oauth'
    'authentication' => $auth,            // 'oauth' or null
    'protocol'       => 'imap',
]));

try {
    $client->connect();
} catch (\Throwable $e) {
    echo "Error connecting to IMAP server: " . $e->getMessage();
    @unlink($lock_file_path);
    exit(1);
}

$inbox = $client->getFolderByPath('INBOX');

$targetFolderPath = 'ITFlow';
try {
    $targetFolder = $client->getFolderByPath($targetFolderPath);
} catch (\Throwable $e) {
    $client->createFolder($targetFolderPath);
    $targetFolder = $client->getFolderByPath($targetFolderPath);
}

// Fetch unseen messages
$messages = $inbox->messages()->leaveUnread()->unseen()->get();

// Counters
$processed_count = 0;
$unprocessed_count = 0;

// Addresses that belong to ITFlow / mailing-list infrastructure, not customers.
// When a group/list rewrites From: to one of these, the resolver can safely recover the real sender.
$local_inbound_addresses = array_filter(array_unique(array_map('parserNormalizeEmail', array_merge([
    $user ?? '',
    $config_imap_username ?? '',
    $config_ticket_from_email ?? '',
    $config_smtp_username ?? '',
    $config_mail_from_email ?? '',
], function_exists('itflowConfiguredMailInfrastructureAddresses') ? itflowConfiguredMailInfrastructureAddresses() : []))));

// Process messages
foreach ($messages as $message) {
    $email_processed = false;

    // Save original message as .eml (getRawMessage() doesn't seem to work properly)
    mkdirMissing('../uploads/tmp/');
    $original_message_file = "processed-eml-" . randomString(200) . ".eml";
    $raw_message = (string)$message->getHeader()->raw . "\r\n\r\n" . ($message->getRawBody() ?? $message->getHTMLBody() ?? $message->getTextBody());
    file_put_contents("../uploads/tmp/{$original_message_file}", $raw_message);

    // From
    $from_col    = $message->getFrom();
    $from_first  = ($from_col && $from_col->count()) ? $from_col->first() : null;
    $from_email = sanitizeInput(parserNormalizeEmail($from_first->mail ?? 'itflow-guest@example.com'));
    $from_name  = sanitizeInput($from_first->personal ?? 'Unknown');

    $from_name = parserCleanEmailDisplayName((string)$from_name, (string)($from_email ?? ''));
    // Mailing lists can intermittently rewrite From: to a configured infrastructure address while preserving
    // the real sender in Reply-To / X-Original-* headers. Recover that sender before any
    // contact/domain/ticket matching happens.
    $raw_headers_for_sender_resolution = (string)$message->getHeader()->raw;
    $resolver_debug = 'resolver-disabled';
    if (intval($config_mail_group_sender_resolver ?? 1) === 1) {
        [$resolved_from_email, $resolved_from_name, $resolved_from_source, $resolver_debug] = parserResolveGroupRewrittenSender($message, $raw_headers_for_sender_resolution, $from_email, $from_name, $local_inbound_addresses);
        if ($resolved_from_source !== null && parserNormalizeEmail($resolved_from_email) !== parserNormalizeEmail($from_email)) {
            logApp("Cron-Email-Parser", "info", "Resolved group sender from $from_email to $resolved_from_email using $resolved_from_source. Candidates: $resolver_debug");
            $from_email = sanitizeInput(parserNormalizeEmail($resolved_from_email));
            $from_name = sanitizeInput($resolved_from_name ?: $from_name);
        } elseif (in_array(parserNormalizeEmail($from_email), $local_inbound_addresses, true)) {
            $unresolved_local_subject = (string)$message->getSubject();

            if (parserIsLikelySelfGeneratedInfrastructureMail($from_email, $unresolved_local_subject, $raw_headers_for_sender_resolution, $local_inbound_addresses)) {
                logApp("Cron-Email-Parser", "info", "Skipped self-generated infrastructure mail from $from_email after sender resolver found no external sender. Subject: $unresolved_local_subject");
                $email_processed = true;
            } else {
                logApp("Cron-Email-Parser", "warning", "Sender resolver could not override local sender $from_email. Candidates: $resolver_debug. Subject: " . $unresolved_local_subject);
            }
        }
    }

    $thread_headers = parserBuildThreadHeaders($raw_headers_for_sender_resolution);
    $mail_context = [
        'in_reply_to' => $thread_headers['in_reply_to'] ?? '',
        'references' => $thread_headers['references'] ?? '',
        'exclude_emails' => $local_inbound_addresses,
    ];

    $from_domain = explode("@", $from_email);
    $from_domain = sanitizeInput(end($from_domain));

    // Subject
    $subject = sanitizeInput((string)$message->getSubject() ?: 'No Subject');

    // CC
    $ccs = array();
    $cc_attr = $message->header->cc;
    $cc_list = $cc_attr->toArray();
    foreach ($cc_list as $cc_addr) {
        if ($cc_addr instanceof \Webklex\PHPIMAP\Address) {
            $ccs[] = $cc_addr->mail;
        }
    }

    // Date (string)
    $dateAttr = $message->getDate();                  // Attribute
    $dateRaw  = $dateAttr ? (string)$dateAttr : '';   // e.g. "Tue, 10 Sep 2025 13:22:05 +0000"
    $ts       = $dateRaw ? strtotime($dateRaw) : false;
    $date     = sanitizeInput($ts !== false ? date('Y-m-d H:i:s', $ts) : date('Y-m-d H:i:s'));

    // Body (prefer HTML)
    $message_body_html = $message->getHTMLBody();
    $message_body_text = $message->getTextBody();
    $message_body_raw  = $message->getRawBody();

    if (!empty($message_body_html)) {
        $message_body = $message_body_html;
    } elseif (!empty($message_body_text)) {
        $message_body = nl2br(htmlspecialchars($message_body_text));
    } else {
        // Final fallback
        $message_body = nl2br(htmlspecialchars($message_body_raw));
    }

    // Handle attachments (inline vs regular)
    $attachments = [];
    foreach ($message->getAttachments() as $att) {
        $attrs   = $att->getAttributes(); // v6.2: canonical source
        $dispo   = strtolower((string)($attrs['disposition'] ?? ''));
        $cid     = $attrs['id'] ?? null;            // Content-ID
        $content = $attrs['content'] ?? null;       // binary
        $mime    = $att->getMimeType();
        $name    = $att->getName() ?: 'attachment';

        $is_inline = false;
        if ($dispo === 'inline' && $cid && $content !== null) {
            $cid_trim  = trim($cid, '<>');
            $dataUri   = "data:$mime;base64,".base64_encode($content);
            $message_body = str_replace(["cid:$cid_trim", "cid:$cid"], $dataUri, $message_body);
            $is_inline = true;
        }

        if (!$is_inline && $content !== null) {
            $attachments[] = ['name' => $name, 'content' => $content];
        }
    }

    $force_ticket = parserHasForceTicketToken($subject);
    if ($force_ticket) {
        $subject = sanitizeInput(parserStripForceTicketToken($subject));
    }

    $is_internal_sender = parserIsInternalEmail($from_email);
    $is_forwarded_message = parserIsForwardedMessage($subject, $message_body, $attachments);
    $current_message_id = parserSanitizeMessageId(parserGetRawHeaderFirstValue($raw_headers_for_sender_resolution, 'Message-ID'));
    $inbound_relation_headers = [
        'in_reply_to' => parserDecodeHeaderValue(parserGetRawHeaderFirstValue($raw_headers_for_sender_resolution, 'In-Reply-To')),
        'references' => parserDecodeHeaderValue(parserGetRawHeaderFirstValue($raw_headers_for_sender_resolution, 'References')),
    ];

    // 1. Reply to existing ticket with the number in subject
    if (preg_match("/\[$config_ticket_prefix(\d+)\]/", $subject, $ticket_number_matches)) {
        $ticket_number = intval($ticket_number_matches[1]);
        $email_processed = addReply($from_email, $date, $subject, $ticket_number, $message_body, $attachments);
    }

    // 1b. Internal reply-all to an ignored unknown-sender thread should not create a new ticket.
    // Forwarded messages and explicit [create ticket]/[force ticket] overrides are always allowed.
    if (!$email_processed && $is_internal_sender && !$force_ticket && !$is_forwarded_message && parserReferencesIgnoredThread($inbound_relation_headers)) {
        logApp("Cron-Email-Parser", "info", "Skipped internal reply-all from $from_email because it references a previously ignored unknown-sender thread. Subject: $subject");
        $email_processed = true;
    }

    // 2. Fuzzy duplicate check using a known contact/domain and similar_text subject
    if (!$email_processed && strlen(trim($subject)) > 10) {
        $contact_id = 0;
        $client_id  = 0;

        // First: check if sender is a registered contact
        $from_email_esc = mysqli_real_escape_string($mysqli, $from_email);
        $contact_sql = mysqli_query($mysqli, "SELECT * FROM contacts WHERE contact_email = '$from_email_esc' AND contact_archived_at IS NULL LIMIT 1");
        $contact_row = mysqli_fetch_assoc($contact_sql);

        if ($contact_row) {
            $contact_id = intval($contact_row['contact_id']);
            $client_id  = intval($contact_row['contact_client_id']);
        } else {
            // Else: check if sender domain is registered
            $from_domain_esc = mysqli_real_escape_string($mysqli, $from_domain);
            $domain_sql = mysqli_query($mysqli, "SELECT * FROM domains WHERE domain_name = '$from_domain_esc' AND domain_archived_at IS NULL LIMIT 1");
            $domain_row = mysqli_fetch_assoc($domain_sql);

            if ($domain_row && $from_domain == $domain_row['domain_name']) {
                $client_id = intval($domain_row['domain_client_id']);
            }
        }

        // If we found either a contact or a domain, check recent tickets for a matching subject
        if ($client_id) {
            $recent_tickets_sql = mysqli_query($mysqli,
                "SELECT ticket_id, ticket_number, ticket_subject
                FROM tickets
                WHERE ticket_client_id = $client_id AND ticket_resolved_at IS NULL
                AND ticket_created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
            );

            while ($rowt = mysqli_fetch_assoc($recent_tickets_sql)) {
                $ticket_number = intval($rowt['ticket_number']);
                $existing_subject = $rowt['ticket_subject'];

                // Calculate similarity percentage
                similar_text(strtolower($subject), strtolower($existing_subject), $percent);

                if ($percent >= 95) {
                    // Treat as a reply/duplicate
                    $email_processed = addReply($from_email, $date, $subject, $ticket_number, $message_body, $attachments);
                    break;
                }
            }
        }
    }

    // 2b. Internal delegation: configured internal-domain users may forward or CC support to intentionally create a ticket.
    // Try to attach the ticket to a known client/contact found in the forwarded/quoted thread. If none is found,
    // create a Guest/Unknown ticket instead. Do not send the customer-facing ticket-created auto-reply for
    // internal delegation, because the customer may not have directly emailed support.
    if (!$email_processed && $is_internal_sender && intval($config_mail_internal_delegation_enable ?? 1) === 1) {
        $delegation_identity = parserFindBestClientIdentityInThread($from_email, $from_name, $raw_headers_for_sender_resolution, $message_body, $ccs, $local_inbound_addresses);
        $delegation_context = $mail_context;
        $delegation_context['suppress_customer_notification'] = true;

        $delegated_body = parserBuildInternalDelegationBody($message_body, $from_name, $from_email, $delegation_identity);

        if ($delegation_identity) {
            $email_processed = addTicket(
                intval($delegation_identity['contact_id']),
                $delegation_identity['contact_name'],
                $delegation_identity['contact_email'],
                intval($delegation_identity['client_id']),
                $date,
                $subject,
                $delegated_body,
                $attachments,
                $original_message_file,
                $ccs,
                $delegation_context
            );
        } else {
            $email_processed = addTicket(
                0,
                $from_name ?: $from_email,
                $from_email,
                0,
                $date,
                $subject,
                $delegated_body,
                $attachments,
                $original_message_file,
                $ccs,
                $delegation_context
            );
        }

        if ($email_processed) {
            logApp("Cron-Email-Parser", "info", "Created ticket from internal delegation by $from_email. Forwarded=" . ($is_forwarded_message ? 'yes' : 'no') . ". Subject: $subject");
        }
    }

    // 3. A known, registered contact?
    if (!$email_processed) {
        $from_email_esc = mysqli_real_escape_string($mysqli, $from_email);
        $any_contact_sql = mysqli_query($mysqli, "SELECT * FROM contacts WHERE contact_email = '$from_email_esc' AND contact_archived_at IS NULL LIMIT 1");
        $rowc = mysqli_fetch_assoc($any_contact_sql);

        if ($rowc) {
            $contact_name  = sanitizeInput($rowc['contact_name']);
            $contact_name = parserCleanEmailDisplayName((string)$contact_name, (string)($contact_email ?? ''));
            $contact_id    = intval($rowc['contact_id']);
            $contact_email = sanitizeInput($rowc['contact_email']);
            $client_id     = intval($rowc['contact_client_id']);

            $email_processed = addTicket($contact_id, $contact_name, $contact_email, $client_id, $date, $subject, $message_body, $attachments, $original_message_file, $ccs, $mail_context);
        }
    }

    // 4. A known domain?
    if (!$email_processed) {
        $from_domain_esc = mysqli_real_escape_string($mysqli, $from_domain);
        $domain_sql = mysqli_query($mysqli, "SELECT * FROM domains WHERE domain_name = '$from_domain_esc' AND domain_archived_at IS NULL LIMIT 1");
        $rowd = mysqli_fetch_assoc($domain_sql);

        if ($rowd && $from_domain == $rowd['domain_name']) {
            $client_id = intval($rowd['domain_client_id']);

            // Create a new contact
            $contact_name  = $from_name;
            $contact_email = $from_email;
            mysqli_query($mysqli, "INSERT INTO contacts SET contact_name = '".mysqli_real_escape_string($mysqli, $contact_name)."', contact_email = '".mysqli_real_escape_string($mysqli, $contact_email)."', contact_notes = 'Added automatically via email parsing.', contact_client_id = $client_id");
            $contact_id = mysqli_insert_id($mysqli);

            logAction("Contact", "Create", "Email parser: created contact " . mysqli_real_escape_string($mysqli, $contact_name), $client_id, $contact_id);
            customAction('contact_create', $contact_id);

            $email_processed = addTicket($contact_id, $contact_name, $contact_email, $client_id, $date, $subject, $message_body, $attachments, $original_message_file, $ccs, $mail_context);
        }
    }

    // 5. Unknown sender allowed?
    if (!$email_processed && $config_ticket_email_parse_unknown_senders) {

        $bad_from_pattern = "/daemon|postmaster|bounce|mta/i"; //  Stop NDRs with bad subjects raising new tickets
        if (!preg_match($bad_from_pattern, $from_email)) {
            $email_processed = addTicket(0, $from_name, $from_email, 0, $date, $subject, $message_body, $attachments, $original_message_file, $ccs, $mail_context);

        } else {

            // Probably an NDR message without a ticket ref in the subject

            $failed_recipient  = null;
            $diagnostic_code   = null;
            $status_code       = null;
            $original_subject  = null;
            $original_to       = null;

            // Webklex stores DSN info in attachments, not parts
            foreach ($message->getAttachments() as $attachment) {

                $ctype = strtolower($attachment->getContentType());
                $body  = $attachment->getContent() ?? '';

                // 1. Delivery status block
                if (strpos($ctype, 'delivery-status') !== false) {

                    if (preg_match('/Final-Recipient:\s*rfc822;\s*(.+)/i', $body, $m)) {
                        $failed_recipient = sanitizeInput(trim($m[1]));
                    }

                    if (preg_match('/Diagnostic-Code:\s*(.+)/i', $body, $m)) {
                        $diagnostic_code = sanitizeInput(trim($m[1]));
                    }

                    if (preg_match('/Status:\s*([0-9\.]+)/i', $body, $m)) {
                        $status_code = sanitizeInput(trim($m[1]));
                    }
                }

                // 2. Original message headers
                if (strpos($ctype, 'message/rfc822') !== false) {

                    if (preg_match('/^To:\s*(.+)$/mi', $body, $m)) {
                        $original_to = sanitizeInput(trim($m[1]));
                    }

                    if (preg_match('/^Subject:\s*(.+)$/mi', $body, $m)) {
                        $original_subject = sanitizeInput(trim($m[1]));
                    }
                }
            }

            // 3. Fallback: extract diagnostic from human-readable text/plain
            if (!$diagnostic_code) {
                $text = $message->getTextBody() ?? '';

                // Exim puts diagnostics on an indented line
                if (preg_match('/\n\s{2,}(.+)/', $text, $m)) {
                    $diagnostic_code = sanitizeInput(trim($m[1]));
                }
            }

            // Fallbacks
            $failed_recipient = $failed_recipient ?: 'unknown recipient';
            $diagnostic_code  = $diagnostic_code ?: 'unknown diagnostic code';
            $status_code      = $status_code ?: 'unknown status code';
            $original_subject = $original_subject ?: $subject;

            appNotify(
                "Ticket",
                "Email parser NDR: Message to $failed_recipient bounced. Subject: $original_subject Diagnostics: $status_code / $diagnostic_code - check ITFlow folder manually to see email",
                "",
                0
            );

            // If the original subject has a ticket, add the NDR there too
            if (preg_match("/\[$config_ticket_prefix(\d+)\]/", $original_subject, $ticket_number_matches)) {

                $ticket_number = intval($ticket_number_matches[1]);

                // Craft a clean bounce message
                $reply_body = "Email delivery failed.\n".
                    "Recipient: $failed_recipient\n".
                    "Status: $status_code\n".
                    "Diagnostic: $diagnostic_code\n";

                // No attachments
                addReply(
                    $from_email,
                    $date,
                    $original_subject,
                    $ticket_number,
                    $reply_body,
                    []
                );

            }

            $email_processed = true;
        }
    }


    // Flag/move based on processing result
    if ($email_processed) {
        $processed_count++; // increment first so a move failure doesn't hide the success
        try {
            $message->setFlag('Seen');
            // Move using the Folder object (top-level "ITFlow")
            $message->move($targetFolderPath);
            // optional: logApp("Cron-Email-Parser", "info", "Moved message to ITFlow");
        } catch (\Throwable $e) {
            // >>> Put the extra logging RIGHT HERE
            $subj = (string)$message->getSubject();
            $uid  = method_exists($message, 'getUid') ? $message->getUid() : 'n/a';
            $path = (is_object($targetFolder) && property_exists($targetFolder, 'path')) ? (string)$targetFolder->path : $targetFolderPath;
            logApp(
                "Cron-Email-Parser",
                "warning",
                "Move failed (subject=\"$subj\", uid=$uid) to [$path]: ".$e->getMessage()
            );
        }
    } else {
        $ignored_unknown_mode = (string)($config_mail_ignored_unknown_thread_mode ?? 'external_only');
        if (
            !$force_ticket
            && $current_message_id !== ''
            && (
                $ignored_unknown_mode === 'all'
                || ($ignored_unknown_mode === 'external_only' && !$is_internal_sender)
            )
        ) {
            parserRecordIgnoredThread($current_message_id, $from_email, $subject);
            logApp("Cron-Email-Parser", "info", "Recorded ignored unknown/unprocessed email thread $current_message_id from $from_email. Subject: $subject");
        }
        $unprocessed_count++;
        try {
            $message->setFlag('Flagged');
            $message->unsetFlag('Seen');
        } catch (\Throwable $e) {
            logApp("Cron-Email-Parser", "warning", "Flag update failed: ".$e->getMessage());
        }
    }

    // Cleanup temp .eml if still present (e.g., reply path)
    if (isset($original_message_file)) {
        $tmp_path = "../uploads/tmp/{$original_message_file}";
        if (file_exists($tmp_path)) { @unlink($tmp_path); }
    }
}

// Expunge & disconnect
try {
    $client->expunge();
} catch (\Throwable $e) {
    // ignore
}
$client->disconnect();

// Execution timing (optional)
$script_end_time = microtime(true);
$execution_time = $script_end_time - $script_start_time;
$execution_time_formatted = number_format($execution_time, 2);

$processed_info = "Processed: $processed_count email(s), Unprocessed: $unprocessed_count email(s)";
// logAction("Cron-Email-Parser", "Execution", "Cron Email Parser executed in $execution_time_formatted seconds. $processed_info");

// Remove the lock file
unlink($lock_file_path);

// DEBUG
echo "\nLock File Path: $lock_file_path\n";
if (file_exists($lock_file_path)) {
    echo "\nLock is present\n\n";
}
echo "Processed Emails: $processed_count\n";
echo "Unprocessed Emails: $unprocessed_count\n";
