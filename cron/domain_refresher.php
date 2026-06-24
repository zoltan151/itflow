<?php

// Set working directory to the directory this cron script lives at.
chdir(dirname(__FILE__));

// Ensure we're running from command line
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

require_once "../config.php";

// Set Timezone
require_once "../includes/inc_set_timezone.php";
require_once "../functions.php";

$sql_settings = mysqli_query($mysqli, "SELECT * FROM settings WHERE settings.company_id = 1");
$row = mysqli_fetch_assoc($sql_settings);

// Company Settings
$config_enable_cron = intval($row['config_enable_cron']);

// Check cron is enabled
if ($config_enable_cron == 0) {
    logApp("Cron-Domain-Refresher", "error", "Cron Domain Refresh unable to run - cron not enabled in admin settings.");
    exit("Cron: is not enabled -- Quitting..\n");
}

function refreshDomainMetadata($domain_id, $refresh_certificate = false) {
    global $mysqli;

    $domain_id = intval($domain_id);

    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT domain_id, domain_name, domain_expire, domain_registrar, domain_webhost, domain_dnshost, domain_mailhost, domain_auto_map, domain_client_id
        FROM domains
        LEFT JOIN clients ON client_id = domain_client_id
        WHERE domain_id = $domain_id
        AND domain_archived_at IS NULL
        AND (client_id IS NULL OR client_archived_at IS NULL)
        LIMIT 1"
    ));

    if (!$row) {
        return false;
    }

    $domain_name = sanitizeInput($row['domain_name']);
    $client_id = intval($row['domain_client_id']);
    $current_expire = sanitizeInput($row['domain_expire']);
    $domain_auto_map = intval($row['domain_auto_map'] ?? 1);
    $registrar = intval($row['domain_registrar']);
    $webhost = intval($row['domain_webhost']);
    $dnshost = intval($row['domain_dnshost']);
    $mailhost = intval($row['domain_mailhost']);

    // Touch the record before remote lookups so a slow/failed lookup will not be retried repeatedly.
    mysqli_query($mysqli, "UPDATE domains SET domain_updated_at = NOW() WHERE domain_id = $domain_id");

    $expire = getDomainExpirationDate($domain_name);
    $records = getDomainRecords($domain_name);
    $a = sanitizeInput($records['a']);
    $ns = sanitizeInput($records['ns']);
    $mx = sanitizeInput($records['mx']);
    $txt = sanitizeInput($records['txt']);
    $whois = sanitizeInput($records['whois']);

    if ($domain_auto_map == 1) {
        $vendor_map = getDomainVendorAutoMap($client_id, $domain_name, $records);
        if (!empty($vendor_map['registrar'])) {
            $registrar = intval($vendor_map['registrar']);
        }
        if (!empty($vendor_map['webhost'])) {
            $webhost = intval($vendor_map['webhost']);
        }
        if (!empty($vendor_map['dnshost'])) {
            $dnshost = intval($vendor_map['dnshost']);
        }
        if (!empty($vendor_map['mailhost'])) {
            $mailhost = intval($vendor_map['mailhost']);
        }
    }

    if (strtotime($expire)) {
        $expire = "'" . sanitizeInput($expire) . "'";
    } elseif (!strtotime($expire) && strtotime($current_expire)) {
        $expire = "'" . $current_expire . "'";
    } else {
        $expire = 'NULL';
    }

    $original_domain_info = mysqli_fetch_assoc(mysqli_query($mysqli,"
        SELECT
            domains.*,
            registrar.vendor_name AS registrar_name,
            dnshost.vendor_name AS dnshost_name,
            mailhost.vendor_name AS mailhost_name,
            webhost.vendor_name AS webhost_name
        FROM domains
        LEFT JOIN vendors AS registrar ON domains.domain_registrar = registrar.vendor_id
        LEFT JOIN vendors AS dnshost ON domains.domain_dnshost = dnshost.vendor_id
        LEFT JOIN vendors AS mailhost ON domains.domain_mailhost = mailhost.vendor_id
        LEFT JOIN vendors AS webhost ON domains.domain_webhost = webhost.vendor_id
        WHERE domain_id = $domain_id
    "));

    mysqli_query($mysqli, "UPDATE domains SET domain_registrar = $registrar, domain_webhost = $webhost, domain_dnshost = $dnshost, domain_mailhost = $mailhost, domain_expire = $expire, domain_ip = '$a', domain_name_servers = '$ns', domain_mail_servers = '$mx', domain_txt = '$txt', domain_raw_whois = '$whois', domain_updated_at = NOW(), domain_refresh_queued_at = NULL WHERE domain_id = $domain_id");

    $new_domain_info = mysqli_fetch_assoc(mysqli_query($mysqli,"
        SELECT
            domains.*,
            registrar.vendor_name AS registrar_name,
            dnshost.vendor_name AS dnshost_name,
            mailhost.vendor_name AS mailhost_name,
            webhost.vendor_name AS webhost_name
        FROM domains
        LEFT JOIN vendors AS registrar ON domains.domain_registrar = registrar.vendor_id
        LEFT JOIN vendors AS dnshost ON domains.domain_dnshost = dnshost.vendor_id
        LEFT JOIN vendors AS mailhost ON domains.domain_mailhost = mailhost.vendor_id
        LEFT JOIN vendors AS webhost ON domains.domain_webhost = webhost.vendor_id
        WHERE domain_id = $domain_id
    "));

    if ($original_domain_info && $new_domain_info) {
        $ignored_columns = ["domain_updated_at", "domain_accessed_at", "domain_refresh_queued_at", "domain_registrar", "domain_webhost", "domain_dnshost", "domain_mailhost"];
        foreach ($original_domain_info as $column => $old_value) {
            $new_value = $new_domain_info[$column] ?? null;
            if ($old_value != $new_value && !in_array($column, $ignored_columns)) {
                $column = sanitizeInput($column);
                $old_value = sanitizeInput($old_value);
                $new_value = sanitizeInput($new_value);
                mysqli_query($mysqli,"INSERT INTO domain_history SET domain_history_column = '$column', domain_history_old_value = '$old_value', domain_history_new_value = '$new_value', domain_history_domain_id = $domain_id");
            }
        }
    }

    if ($refresh_certificate) {
        $certificate = getSSL($domain_name);
        if ($certificate['success'] == "TRUE") {
            $cert_expire = sanitizeInput($certificate['expire']);
            $issued_by = sanitizeInput($certificate['issued_by']);
            $public_key = sanitizeInput($certificate['public_key']);

            $sql_certificate = mysqli_query($mysqli, "SELECT certificate_id FROM certificates WHERE certificate_domain_id = $domain_id LIMIT 1");
            if (mysqli_num_rows($sql_certificate) > 0) {
                $certificate_row = mysqli_fetch_assoc($sql_certificate);
                $certificate_id = intval($certificate_row['certificate_id']);
                mysqli_query($mysqli,"UPDATE certificates SET certificate_name = '$domain_name', certificate_domain = '$domain_name', certificate_issued_by = '$issued_by', certificate_expire = '$cert_expire', certificate_public_key = '$public_key', certificate_client_id = $client_id WHERE certificate_id = $certificate_id");
            } else {
                mysqli_query($mysqli,"INSERT INTO certificates SET certificate_name = '$domain_name', certificate_domain = '$domain_name', certificate_issued_by = '$issued_by', certificate_expire = '$cert_expire', certificate_public_key = '$public_key', certificate_domain_id = $domain_id, certificate_client_id = $client_id");
            }
        }
    }

    return $domain_name;
}

$target_domain_id = 0;
foreach ($argv as $arg) {
    if (strpos($arg, '--domain-id=') === 0) {
        $target_domain_id = intval(substr($arg, strlen('--domain-id=')));
    }
}

if ($target_domain_id > 0) {
    $domain_name = refreshDomainMetadata($target_domain_id, true);
    if ($domain_name) {
        echo "Refreshed queued domain $domain_name.\n";
    } else {
        echo "Queued domain not found or not active.\n";
    }
    exit;
}

/*
 * ###############################################################################################################
 *  REFRESH DATA
 * ###############################################################################################################
 */

$sql_count = mysqli_query(
    $mysqli,
    "SELECT COUNT(domain_id) AS total_domains
    FROM domains
    LEFT JOIN clients ON client_id = domain_client_id
    WHERE domain_archived_at IS NULL
    AND (client_id IS NULL OR client_archived_at IS NULL)"
);
$row_count = mysqli_fetch_assoc($sql_count);
$total_domains = intval($row_count['total_domains'] ?? 0);
$domains_per_run = max(1, (int)ceil($total_domains / 24));

if ($total_domains == 0) {
    echo "No active domains to refresh.\n";
    exit;
}

$sql_domains = mysqli_query(
    $mysqli,
    "SELECT domain_id
    FROM domains
    LEFT JOIN clients ON client_id = domain_client_id
    WHERE domain_archived_at IS NULL
    AND (client_id IS NULL OR client_archived_at IS NULL)
    AND (
        domain_refresh_queued_at IS NOT NULL
        OR domain_updated_at IS NULL
        OR DATE(domain_updated_at) < CURRENT_DATE
    )
    ORDER BY
        CASE WHEN domain_refresh_queued_at IS NOT NULL THEN 0 ELSE 1 END,
        domain_refresh_queued_at ASC,
        domain_updated_at ASC,
        domain_id ASC
    LIMIT $domains_per_run"
);

$refreshed_count = 0;

while ($row = mysqli_fetch_assoc($sql_domains)) {
    $domain_id = intval($row['domain_id']);
    $domain_name = refreshDomainMetadata($domain_id, false);
    if ($domain_name) {
        echo "Updated $domain_name.\n";
        $refreshed_count++;
    }
}

if ($refreshed_count == 0) {
    echo "No domains needed refresh. Total active domains: $total_domains. Batch size: $domains_per_run.\n";
} else {
    echo "Refreshed $refreshed_count domain(s). Total active domains: $total_domains. Batch size: $domains_per_run.\n";
}
