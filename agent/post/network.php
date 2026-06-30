<?php
// ITFLOW_NETWORK_DIAGRAM_PHASE2C

/*
 * ITFlow - GET/POST request handler for client networks
 */

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");


if (isset($_GET['generate_network_diagram'])) {

    validateCSRFToken($_GET['csrf_token']);

    enforceUserPermission('module_support', 2);

    $network_id = intval($_GET['generate_network_diagram']);

    $sql_network = mysqli_query(
        $mysqli,
        "SELECT networks.*,
            clients.client_name,
            locations.location_name
         FROM networks
         LEFT JOIN clients ON network_client_id = client_id
         LEFT JOIN locations ON network_location_id = location_id
         WHERE network_id = $network_id
         LIMIT 1"
    );

    if (!$sql_network || mysqli_num_rows($sql_network) == 0) {
        flash_alert("Network not found", 'error');
        redirect();
    }

    $row = mysqli_fetch_assoc($sql_network);

    $network_name = sanitizeInput($row['network_name']);
    $network_description = sanitizeInput($row['network_description'] ?? '');
    $network_cidr = sanitizeInput($row['network'] ?? '');
    $network_subnet = sanitizeInput($row['network_subnet'] ?? '');
    $network_gateway = sanitizeInput($row['network_gateway'] ?? '');
    $network_vlan = intval($row['network_vlan'] ?? 0);
    $network_location_id = intval($row['network_location_id']);
    $network_client_id = intval($row['network_client_id']);
    $client_id = $network_client_id;
    $client_name = sanitizeInput($row['client_name'] ?? '');
    $location_name = sanitizeInput($row['location_name'] ?? '');

    enforceClientAccess();

    if (!$network_name) {
        $network_name = "Network $network_id";
    }

    if (!$client_name) {
        $client_name = "Client $client_id";
    }

    $network_node = $network_name;

    if ($network_cidr) {
        $network_node .= " ($network_cidr)";
    }

    if ($network_vlan > 0) {
        $network_node .= " VLAN $network_vlan";
    }

    $diagram_lines = [];
    $diagram_lines[] = "# Generated from ITFlow network: $network_name";
    $diagram_lines[] = "$client_name -> $network_node";

    if ($location_name) {
        $diagram_lines[] = "$network_node -> $location_name";
    }

    if ($network_gateway) {
        $diagram_lines[] = "$network_node -> Gateway $network_gateway";
    }

    if ($network_subnet) {
        $diagram_lines[] = "$network_node -> Subnet $network_subnet";
    }

    $asset_count = 0;
    $interface_count = 0;

    $asset_interfaces_exists = false;
    $sql_table = mysqli_query($mysqli, "SHOW TABLES LIKE 'asset_interfaces'");
    if ($sql_table && mysqli_num_rows($sql_table) > 0) {
        $asset_interfaces_exists = true;
    }

    $interface_columns = [];
    if ($asset_interfaces_exists) {
        $sql_columns = mysqli_query($mysqli, "SHOW COLUMNS FROM asset_interfaces");
        while ($column = mysqli_fetch_assoc($sql_columns)) {
            $interface_columns[$column['Field']] = true;
        }
    }

    if (
        $asset_interfaces_exists
        && isset($interface_columns['interface_network_id'])
        && isset($interface_columns['interface_asset_id'])
    ) {
        $sql_assets = mysqli_query(
            $mysqli,
            "SELECT DISTINCT
                assets.asset_id,
                assets.asset_name,
                assets.asset_type,
                assets.asset_make,
                assets.asset_model,
                assets.asset_status,
                asset_interfaces.interface_name,
                asset_interfaces.interface_ip,
                asset_interfaces.interface_connected_asset_id,
                connected_assets.asset_name AS connected_asset_name
             FROM asset_interfaces
             LEFT JOIN assets ON interface_asset_id = assets.asset_id
             LEFT JOIN assets AS connected_assets ON interface_connected_asset_id = connected_assets.asset_id
             WHERE interface_network_id = $network_id
               AND assets.asset_archived_at IS NULL
             ORDER BY assets.asset_type ASC, assets.asset_name ASC, asset_interfaces.interface_name ASC
             LIMIT 250"
        );

        if ($sql_assets) {
            while ($asset = mysqli_fetch_assoc($sql_assets)) {
                $asset_id = intval($asset['asset_id']);
                $asset_name = sanitizeInput($asset['asset_name'] ?? '');
                $asset_type = sanitizeInput($asset['asset_type'] ?? '');
                $asset_make = sanitizeInput($asset['asset_make'] ?? '');
                $asset_model = sanitizeInput($asset['asset_model'] ?? '');
                $interface_name = sanitizeInput($asset['interface_name'] ?? '');
                $interface_ip = sanitizeInput($asset['interface_ip'] ?? '');
                $connected_asset_name = sanitizeInput($asset['connected_asset_name'] ?? '');

                if (!$asset_id || !$asset_name) {
                    continue;
                }

                $asset_label = $asset_name;

                if ($asset_type) {
                    $asset_label .= " [$asset_type]";
                }

                if ($interface_ip) {
                    $asset_label .= " ($interface_ip)";
                }

                $diagram_lines[] = "$network_node -> $asset_label";
                $asset_count++;
                $interface_count++;

                if ($connected_asset_name) {
                    $diagram_lines[] = "$asset_label -> $connected_asset_name";
                }
            }
        }
    }

    if ($asset_count == 0) {
        $asset_query = "SELECT asset_id, asset_name, asset_type, asset_make, asset_model, asset_status
            FROM assets
            WHERE asset_client_id = $client_id
              AND asset_archived_at IS NULL";

        if ($network_location_id > 0) {
            $asset_query .= " AND asset_location_id = $network_location_id";
        }

        $asset_query .= " ORDER BY asset_type ASC, asset_name ASC LIMIT 200";

        $sql_assets = mysqli_query($mysqli, $asset_query);

        if ($sql_assets) {
            while ($asset = mysqli_fetch_assoc($sql_assets)) {
                $asset_id = intval($asset['asset_id']);
                $asset_name = sanitizeInput($asset['asset_name'] ?? '');
                $asset_type = sanitizeInput($asset['asset_type'] ?? '');

                if (!$asset_id || !$asset_name) {
                    continue;
                }

                $asset_label = $asset_name;

                if ($asset_type) {
                    $asset_label .= " [$asset_type]";
                }

                $diagram_lines[] = "$network_node -> $asset_label";
                $asset_count++;
            }
        }
    }

    if ($asset_count == 0) {
        $diagram_lines[] = "$network_node -> No mapped assets found";
    }

    $document_name = sanitizeInput("Network Diagram - $network_name");
    $document_description = sanitizeInput("Generated from network $network_name");
    $document_type = "Network Diagram";
    $document_diagram_data = mysqli_real_escape_string($mysqli, implode("\n", $diagram_lines));
    $content_html = "<p>This network diagram was generated from ITFlow network data.</p>";
    $content_html .= "<ul>";
    $content_html .= "<li><strong>Network:</strong> " . htmlspecialchars($network_name, ENT_QUOTES, 'UTF-8') . "</li>";

    if ($network_cidr) {
        $content_html .= "<li><strong>Network/CIDR:</strong> " . htmlspecialchars($network_cidr, ENT_QUOTES, 'UTF-8') . "</li>";
    }

    if ($network_gateway) {
        $content_html .= "<li><strong>Gateway:</strong> " . htmlspecialchars($network_gateway, ENT_QUOTES, 'UTF-8') . "</li>";
    }

    if ($network_vlan > 0) {
        $content_html .= "<li><strong>VLAN:</strong> " . intval($network_vlan) . "</li>";
    }

    if ($location_name) {
        $content_html .= "<li><strong>Location:</strong> " . htmlspecialchars($location_name, ENT_QUOTES, 'UTF-8') . "</li>";
    }

    $content_html .= "<li><strong>Assets included:</strong> " . intval($asset_count) . "</li>";
    $content_html .= "<li><strong>Interfaces matched:</strong> " . intval($interface_count) . "</li>";
    $content_html .= "</ul>";
    $content_html .= "<p class='text-muted'>Edit the diagram source above if the generated layout needs cleanup.</p>";

    $document_content = mysqli_real_escape_string($mysqli, $content_html);
    $document_content_raw = mysqli_real_escape_string(
        $mysqli,
        sanitizeInput($document_name . " " . $document_description . " " . implode(" ", $diagram_lines))
    );

    mysqli_query(
        $mysqli,
        "INSERT INTO documents SET
            document_name = '$document_name',
            document_description = '$document_description',
            document_type = '$document_type',
            document_diagram_data = '$document_diagram_data',
            document_diagram_updated_at = NOW(),
            document_content = '$document_content',
            document_content_raw = '$document_content_raw',
            document_folder_id = 0,
            document_created_by = $session_user_id,
            document_updated_by = $session_user_id,
            document_client_id = $client_id"
    );

    $document_id = mysqli_insert_id($mysqli);

    logAction(
        "Document",
        "Create",
        "$session_name generated network diagram document $document_name from network $network_name",
        $client_id,
        $document_id
    );

    flash_alert("Network diagram document <strong>$document_name</strong> created");

    redirect("document_details.php?client_id=$client_id&document_id=$document_id");

}


if (isset($_POST['add_network'])) {

    validateCSRFToken($_POST['csrf_token']);

    enforceUserPermission('module_support', 2);

    require_once 'network_model.php';

    $client_id = intval($_POST['client_id']);

    enforceClientAccess();

    mysqli_query($mysqli,"INSERT INTO networks SET network_name = '$name', network_description = '$description', network_vlan = $vlan, network = '$network', network_subnet = '$subnet', network_gateway = '$gateway', network_primary_dns = '$primary_dns', network_secondary_dns = '$secondary_dns', network_dhcp_range = '$dhcp_range', network_notes = '$notes', network_location_id = $location_id, network_client_id = $client_id");

    $network_id = mysqli_insert_id($mysqli);

    logAction("Network", "Create", "$session_name created network $name", $client_id, $network_id);

    flash_alert("Network <strong>$name</strong> created");

    redirect();

}

if (isset($_POST['edit_network'])) {

    validateCSRFToken($_POST['csrf_token']);

    enforceUserPermission('module_support', 2);

    require_once 'network_model.php';

    $network_id = intval($_POST['network_id']);

    $client_id = intval(getFieldById('networks', $network_id, 'network_client_id'));

    enforceClientAccess();

    mysqli_query($mysqli,"UPDATE networks SET network_name = '$name', network_description = '$description', network_vlan = $vlan, network = '$network', network_gateway = '$gateway', network_primary_dns = '$primary_dns', network_secondary_dns = '$secondary_dns', network_dhcp_range = '$dhcp_range', network_notes = '$notes', network_location_id = $location_id WHERE network_id = $network_id");

    logAction("Network", "Edit", "$session_name edited network $name", $client_id, $network_id);

    flash_alert("Network <strong>$name</strong> updated");

    redirect();

}

if (isset($_GET['archive_network'])) {

    validateCSRFToken($_GET['csrf_token']);

    enforceUserPermission('module_support', 2);

    $network_id = intval($_GET['archive_network']);

    // Get Network Name and Client ID for logging and alert message
    $sql = mysqli_query($mysqli,"SELECT network_name, network_client_id FROM networks WHERE network_id = $network_id");
    $row = mysqli_fetch_assoc($sql);
    $network_name = sanitizeInput($row['network_name']);
    $client_id = intval($row['network_client_id']);

    enforceClientAccess();

    mysqli_query($mysqli,"UPDATE networks SET network_archived_at = NOW() WHERE network_id = $network_id");

    logAction("Network", "Archive", "$session_name archived network $network_name", $client_id, $network_id);

    flash_alert("Network <strong>$network_name</strong> archived", 'error');

    redirect();

}

if (isset($_GET['restore_network'])) {

    validateCSRFToken($_GET['csrf_token']);

    enforceUserPermission('module_support', 2);

    $network_id = intval($_GET['restore_network']);

    // Get Network Name and Client ID for logging and alert message
    $sql = mysqli_query($mysqli,"SELECT network_name, network_client_id FROM networks WHERE network_id = $network_id");
    $row = mysqli_fetch_assoc($sql);
    $network_name = sanitizeInput($row['network_name']);
    $client_id = intval($row['network_client_id']);

    enforceClientAccess();

    mysqli_query($mysqli,"UPDATE networks SET network_archived_at = NULL WHERE network_id = $network_id");

    logAction("Network", "Restore", "$session_name restored contact $contact_name", $client_id, $network_id);

    flash_alert("Network <strong>$network_name</strong> restored");

    redirect();

}

if (isset($_GET['delete_network'])) {

    validateCSRFToken($_GET['csrf_token']);

    enforceUserPermission('module_support', 3);

    $network_id = intval($_GET['delete_network']);

    // Get Network Name and Client ID for logging and alert message
    $sql = mysqli_query($mysqli,"SELECT network_name, network_client_id FROM networks WHERE network_id = $network_id");
    $row = mysqli_fetch_assoc($sql);
    $network_name = sanitizeInput($row['network_name']);
    $client_id = intval($row['network_client_id']);

    enforceClientAccess();

    mysqli_query($mysqli,"DELETE FROM networks WHERE network_id = $network_id");

    logAction("Network", "Delete", "$session_name deleted network $network_name", $client_id);

    flash_alert("Network <strong>$network_name</strong> deleted", 'error');

    redirect();

}

if (isset($_POST['bulk_delete_networks'])) {

    validateCSRFToken($_POST['csrf_token']);

    enforceUserPermission('module_support', 3);

    if (isset($_POST['network_ids'])) {

        // Get Selected Count
        $count = count($_POST['network_ids']);

        // Cycle through array and delete each network
        foreach ($_POST['network_ids'] as $network_id) {

            $network_id = intval($network_id);

            // Get Network Name and Client ID for logging and alert message
            $sql = mysqli_query($mysqli,"SELECT network_name, network_client_id FROM networks WHERE network_id = $network_id");
            $row = mysqli_fetch_assoc($sql);
            $network_name = sanitizeInput($row['network_name']);
            $client_id = intval($row['network_client_id']);

            enforceClientAccess();

            mysqli_query($mysqli, "DELETE FROM networks WHERE network_id = $network_id AND network_client_id = $client_id");

            logAction("Network", "Delete", "$session_name deleted network $network_name", $client_id);

        }

        logAction("Network", "Bulk Delete", "$session_name deleted $count network(s)", $client_id);

        flash_alert("Deleted <strong>$count</strong> network(s)", 'error');

    }

    redirect();

}

if (isset($_POST['export_networks_csv'])) {

    enforceUserPermission('module_support');

    if ($_POST['client_id']) {
        $client_id = intval($_POST['client_id']);
        $client_query = "AND network_client_id = $client_id";
        $client_name = getFieldById('clients', $client_id, 'client_name');
        $file_name_prepend = "$client_name-";
        enforceClientAccess();
    } else {
        $client_query = '';
        $client_id = 0;
        $file_name_prepend = "$session_company_name-";
    }

    $sql = mysqli_query($mysqli,"SELECT * FROM networks LEFT JOIN clients ON client_id = network_client_id WHERE network_archived_at IS NULL $client_query $access_permission_query ORDER BY network_name ASC");

    $num_rows = mysqli_num_rows($sql);

    if ($num_rows > 0) {
        $delimiter = ",";
        $enclosure = '"';
        $escape    = '\\';   // backslash
        $filename = sanitize_filename($file_name_prepend . "Networks-" . date('Y-m-d_H-i-s') . ".csv");

        //create a file pointer
        $f = fopen('php://memory', 'w');

        //set column headers
        $fields = array('Name', 'Description', 'VLAN', 'Network (CIDR)', 'Gateway', 'IP Range', 'Primary DNS', 'Secondary DNS');
        fputcsv($f, $fields, $delimiter, $enclosure, $escape);

        //output each row of the data, format line as csv and write to file pointer
        while ($row = $sql->fetch_assoc()) {
            $lineData = array($row['network_name'], $row['network_description'], $row['network_vlan'], $row['network'], $row['network_gateway'], $row['network_dhcp_range'], $row['network_primary_dns'], $row['network_secondary_dns']);
            fputcsv($f, $lineData, $delimiter, $enclosure, $escape);
        }

        //move back to beginning of file
        fseek($f, 0);

        //set headers to download file rather than displayed
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '";');

        //output all remaining data on a file pointer
        fpassthru($f);
    }

    logAction("Network", "Export", "$session_name deleted $num_rows network(s) to a CSV file", $client_id);

    exit;

}

// ============================================================
// Add these two blocks to agent/post/network.php
// Place them alongside the existing export_networks_csv block.
// ============================================================

// ----------------------------------------------------------
// CSV Template Download
// GET: post.php?download_networks_csv_template=<client_id>
// ----------------------------------------------------------
if (isset($_GET['download_networks_csv_template'])) {

    $delimiter = ",";
    $enclosure = '"';
    $escape    = '\\';
    $filename  = "Networks-Template.csv";

    $f = fopen('php://memory', 'w');

    $fields = array('Name', 'Description', 'VLAN', 'Network (CIDR)', 'Gateway', 'IP Range', 'Primary DNS', 'Secondary DNS');
    fputcsv($f, $fields, $delimiter, $enclosure, $escape);

    // One example row so the user can see expected formatting
    $example = array('Office LAN', 'Main office network', '10', '192.168.1.0/24', '192.168.1.1', '192.168.1.100-192.168.1.200', '8.8.8.8', '8.8.4.4');
    fputcsv($f, $example, $delimiter, $enclosure, $escape);

    fseek($f, 0);

    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '";');

    fpassthru($f);
    exit;

}

// ----------------------------------------------------------
// CSV Import
// POST: post.php  (name="import_networks_csv")
// ----------------------------------------------------------
if (isset($_POST['import_networks_csv'])) {

    validateCSRFToken($_POST['csrf_token']);

    enforceUserPermission('module_support', 2);

    $client_id = intval($_POST['client_id']);

    enforceClientAccess();

    $error = false;

    // File provided?
    if (!empty($_FILES['file']['tmp_name'])) {
        $file_name = $_FILES['file']['tmp_name'];
    } else {
        flash_alert("Please select a file to upload.", 'error');
        redirect();
    }

    // Check extension
    $file_extension = strtolower(end(explode('.', $_FILES['file']['name'])));
    if ($file_extension !== 'csv') {
        $error = true;
        flash_alert("Bad file extension — only .csv files are accepted.", 'error');
    }

    // Check not empty
    elseif ($_FILES['file']['size'] < 1) {
        $error = true;
        flash_alert("Bad file size (empty file?).", 'error');
    }

    // Check column count matches the 8-column export/template format
    else {
        $f = fopen($file_name, 'r');
        $f_columns = fgetcsv($f, 1000, ',');
        fclose($f);

        if (count($f_columns) !== 8) {
            $error = true;
            flash_alert("Bad column count — expected 8 columns: Name, Description, VLAN, Network (CIDR), Gateway, IP Range, Primary DNS, Secondary DNS.", 'error');
        }
    }

    // Parse and insert
    if (!$error) {
        $file = fopen($file_name, 'r');
        fgetcsv($file, 1000, ','); // Skip header row

        $row_count       = 0;
        $duplicate_count = 0;

        while (($column = fgetcsv($file, 1000, ',')) !== false) {

            $duplicate_detect = 0;

            $name         = isset($column[0]) ? sanitizeInput($column[0]) : '';
            $description  = isset($column[1]) ? sanitizeInput($column[1]) : '';
            $vlan         = isset($column[2]) ? intval($column[2])         : 0;
            $network      = isset($column[3]) ? sanitizeInput($column[3]) : '';
            $gateway      = isset($column[4]) ? sanitizeInput($column[4]) : '';
            $dhcp_range   = isset($column[5]) ? sanitizeInput($column[5]) : '';
            $primary_dns  = isset($column[6]) ? sanitizeInput($column[6]) : '';
            $secondary_dns = isset($column[7]) ? sanitizeInput($column[7]) : '';

            // Skip rows with no name
            if ($name === '') {
                continue;
            }

            // Duplicate check — same name + network address for this client
            $dup_check = mysqli_query($mysqli,
                "SELECT network_id FROM networks
                 WHERE network_name = '$name'
                   AND network = '$network'
                   AND network_client_id = $client_id
                   AND network_archived_at IS NULL
                 LIMIT 1"
            );

            if (mysqli_num_rows($dup_check) > 0) {
                $duplicate_detect = 1;
            }

            if ($duplicate_detect === 0) {
                mysqli_query($mysqli,
                    "INSERT INTO networks SET
                        network_name         = '$name',
                        network_description  = '$description',
                        network_vlan         = $vlan,
                        network              = '$network',
                        network_gateway      = '$gateway',
                        network_dhcp_range   = '$dhcp_range',
                        network_primary_dns  = '$primary_dns',
                        network_secondary_dns = '$secondary_dns',
                        network_client_id    = $client_id"
                );
                $row_count++;
            } else {
                $duplicate_count++;
            }
        }

        fclose($file);

        logAction("Network", "Import", "$session_name imported $row_count network(s). $duplicate_count duplicate(s) found and not imported", $client_id);

        flash_alert("$row_count Network(s) imported, $duplicate_count duplicate(s) detected and not imported");

        redirect();
    }

    if ($error) {
        redirect();
    }

}
