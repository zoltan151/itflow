<?php

// Default Column Sortby Filter
$sort = "ticket_number";
$order = "DESC";

// If client_id is in URI then show client Side Bar and client header
if (isset($_GET['client_id'])) {
    require_once "includes/inc_all_client.php";
    $client_query = "AND ticket_client_id = $client_id";
    $client_url = "client_id=$client_id&";
} else {
    require_once "includes/inc_all.php";
    $client_query = '';
    $client_url = '';
}

// Perms
enforceUserPermission('module_support');

// ITFLOW_TICKET_LIST_AUDIT_DEFAULTS
// A direct visit to Tickets should be an audit/review view: all statuses, all assignees.
// Explicit quick filters like Open, Closed, My Tickets, Unassigned, client_id, search, category, project, etc. still work.
$ticket_list_has_explicit_scope_filter = (
    (isset($_GET['status']) && ((is_array($_GET['status']) && count(array_filter(array_map('intval', $_GET['status']))) > 0) || (!is_array($_GET['status']) && $_GET['status'] !== '')))
    || (isset($_GET['assigned']) && count(array_filter((array)$_GET['assigned'], static function ($ticket_assigned_scope_value) {
        return $ticket_assigned_scope_value !== '' && $ticket_assigned_scope_value !== 'any' && $ticket_assigned_scope_value !== '__clear__';
    })) > 0)
    || isset($_GET['unassigned'])
    || isset($_GET['user'])
    || isset($_GET['view'])
    || isset($_GET['client_id'])
    || isset($_GET['q'])
    || isset($_GET['category'])
    || (isset($_GET['project']) && count(array_filter((array)$_GET['project'], static function ($ticket_project_scope_value) {
        return $ticket_project_scope_value !== '' && $ticket_project_scope_value !== 'any' && $ticket_project_scope_value !== '__clear__';
    })) > 0)
    || isset($_GET['billable'])
    || isset($_GET['unbilled'])
    || isset($_GET['dtf'])
    || isset($_GET['dtt'])
);

$ticket_list_audit_default = isset($_GET['all_tickets']) || !$ticket_list_has_explicit_scope_filter;

// Always show the full filter row so ticket review/auditing is not hidden behind the funnel button.
$_GET['filter'] = 1;

if (isset($_GET['all_tickets'])) {
    unset($_GET['assigned'], $_GET['unassigned'], $_GET['user']);
}



// ITFLOW_TICKET_STATUS_PLACEHOLDER_ANY_LOGIC
// Ticket status from GET. Empty multi-select / no status means Any, which means all statuses.
$ticket_status_filter_values = [];

if (isset($_GET['status']) && is_array($_GET['status'])) {
    $ticket_status_filter_values = array_values(array_unique(array_filter(array_map('intval', $_GET['status']), static function ($ticket_status_filter_value) {
        return $ticket_status_filter_value > 0;
    })));

    if (!empty($ticket_status_filter_values)) {
        $sanitizedStatuses = array_map(static function ($ticket_status_filter_value) {
            return "'" . intval($ticket_status_filter_value) . "'";
        }, $ticket_status_filter_values);

        $sanitizedStatusesString = implode(",", $sanitizedStatuses);
        $ticket_status_snippet = "ticket_status IN ($sanitizedStatusesString)";
        $_GET['status'] = $ticket_status_filter_values;
    } else {
        unset($_GET['status']);
        $status = 'All';
        $ticket_status_snippet = "1=1";
    }

} elseif (isset($_GET['status']) && $_GET['status'] == 'Closed') {
    // Explicit quick filter.
    $status = 'Closed';
    $ticket_status_snippet = "ticket_resolved_at IS NOT NULL";

} elseif (isset($_GET['status']) && $_GET['status'] == 'Open') {
    // Explicit quick filter.
    $status = 'Open';
    $ticket_status_snippet = "ticket_resolved_at IS NULL";

} elseif (isset($_GET['status']) && intval($_GET['status']) > 0) {
    // Backward-compatible single status ID URL.
    $ticket_status_filter_values = [intval($_GET['status'])];
    $ticket_status_snippet = "ticket_status = " . intval($_GET['status']);

} else {
    // Default / Any - Show all tickets regardless of status.
    unset($_GET['status']);
    $status = 'All';
    $ticket_status_snippet = "1=1";
}


if (isset($_GET['billable']) && ($_GET['billable']) == '1') {
    if (isset($_GET['unbilled'])) {
        $billable = 1;
        $ticket_billable_snippet = "AND ticket_billable = 1 AND ticket_invoice_id = 0";
        $ticket_status_snippet = '1 = 1';
    }
} else {
    $billable = 0;
    $ticket_billable_snippet = '';
}

// Category Filter
if (isset($_GET['category']) & !empty($_GET['category'])) {
    $category_query = 'AND (ticket_category = ' . intval($_GET['category']) . ')';
    $category_filter = intval($_GET['category']);
} else {
    // Default - any
    $category_query = '';
    $category_filter = '';
}

// ITFLOW_TICKET_ASSIGNED_PLACEHOLDER_ANY_LOGIC
// Ticket assignment filter. Empty multi-select / no assignee means Any.
$ticket_assigned_query = '';
$ticket_assigned_filter_values = [];

if (isset($_GET['assigned'])) {
    $assigned_filter_raw_values = is_array($_GET['assigned']) ? $_GET['assigned'] : [$_GET['assigned']];

    foreach ($assigned_filter_raw_values as $assigned_filter_raw_value) {
        if ($assigned_filter_raw_value === '' || $assigned_filter_raw_value === 'any' || $assigned_filter_raw_value === '__clear__') {
            continue;
        }

        if ($assigned_filter_raw_value === 'unassigned') {
            $ticket_assigned_filter_values[] = 'unassigned';
            continue;
        }

        $assigned_filter_user_id = intval($assigned_filter_raw_value);
        if ($assigned_filter_user_id > 0) {
            $ticket_assigned_filter_values[] = (string)$assigned_filter_user_id;
        }
    }

    $ticket_assigned_filter_values = array_values(array_unique($ticket_assigned_filter_values));

    if (!empty($ticket_assigned_filter_values)) {
        $ticket_assigned_filter_ids = [];
        foreach ($ticket_assigned_filter_values as $ticket_assigned_filter_value) {
            if ($ticket_assigned_filter_value === 'unassigned') {
                $ticket_assigned_filter_ids[] = 0;
            } else {
                $ticket_assigned_filter_ids[] = intval($ticket_assigned_filter_value);
            }
        }

        $ticket_assigned_filter_ids = array_values(array_unique(array_filter($ticket_assigned_filter_ids, static function ($ticket_assigned_filter_id) {
            return $ticket_assigned_filter_id >= 0;
        })));

        if (!empty($ticket_assigned_filter_ids)) {
            $ticket_assigned_query = 'AND ticket_assigned_to IN (' . implode(',', $ticket_assigned_filter_ids) . ')';
        }
    } else {
        unset($_GET['assigned']);
    }
}
// ITFLOW_TICKET_PROJECT_PLACEHOLDER_ANY_LOGIC
// Project filter. Empty multi-select / no project means Any.
$ticket_project_snippet = '';
$ticket_project_filter_values = [];

if (isset($_GET['project'])) {
    $project_filter_raw_values = is_array($_GET['project']) ? $_GET['project'] : [$_GET['project']];

    foreach ($project_filter_raw_values as $project_filter_raw_value) {
        if ($project_filter_raw_value === '' || $project_filter_raw_value === 'any' || $project_filter_raw_value === '__clear__') {
            continue;
        }

        $project_filter_id = intval($project_filter_raw_value);
        if ($project_filter_id > 0) {
            $ticket_project_filter_values[] = (string)$project_filter_id;
        }
    }

    $ticket_project_filter_values = array_values(array_unique($ticket_project_filter_values));

    if (!empty($ticket_project_filter_values)) {
        $ticket_project_filter_ids = array_values(array_unique(array_filter(array_map('intval', $ticket_project_filter_values), static function ($ticket_project_filter_id) {
            return $ticket_project_filter_id > 0;
        })));

        if (!empty($ticket_project_filter_ids)) {
            $ticket_project_snippet = 'AND ticket_project_id IN (' . implode(',', $ticket_project_filter_ids) . ')';
        }
    } else {
        unset($_GET['project']);
    }
}


// ITFLOW_TICKET_LIST_AUDIT_DEFAULTS_QUERY_OVERRIDE
if (!empty($ticket_list_audit_default)) {
    // Neutral audit view: do not restrict by status/resolved state or assignee.
    $status = 'All';
    $ticket_status_snippet = '1=1';
    unset($_GET['status']);
    $ticket_status_filter_values = [];
    $ticket_assigned_query = '';
    unset($_GET['assigned']);
    $ticket_assigned_filter_values = [];
    $ticket_assigned_filter_id = '';
    unset($_GET['project']);
    $ticket_project_filter_values = [];
}

// Ticket client access overide - This is the only way to show tickets without a client to agents with restricted client access
$access_permission_query_overide = '';
if ($client_access_string) {
    $access_permission_query_overide = "AND ticket_client_id IN (0,$client_access_string)";
}

// Main ticket query:
$query =
    "SELECT SQL_CALC_FOUND_ROWS * FROM tickets
    LEFT JOIN clients ON ticket_client_id = client_id
    LEFT JOIN contacts ON ticket_contact_id = contact_id
    LEFT JOIN users ON ticket_assigned_to = user_id
    LEFT JOIN assets ON ticket_asset_id = asset_id
    LEFT JOIN locations ON ticket_location_id = location_id
    LEFT JOIN vendors ON ticket_vendor_id = vendor_id
    LEFT JOIN ticket_statuses ON ticket_status = ticket_status_id
    LEFT JOIN categories ON ticket_category = category_id
    WHERE $ticket_status_snippet " . $ticket_assigned_query . "
    $category_query
    AND DATE(ticket_created_at) BETWEEN '$dtf' AND '$dtt'
    AND (CONCAT(ticket_prefix,ticket_number) LIKE '%$q%' OR client_name LIKE '%$q%' OR ticket_subject LIKE '%$q%' OR ticket_status_name LIKE '%$q%' OR ticket_priority LIKE '%$q%' OR user_name LIKE '%$q%' OR contact_name LIKE '%$q%' OR asset_name LIKE '%$q%' OR vendor_name LIKE '%$q%' OR ticket_vendor_ticket_number LIKE '%q%')
    $ticket_billable_snippet
    $ticket_project_snippet
    $access_permission_query_overide
    $client_query
    ORDER BY
        CASE
            WHEN '$sort' = 'ticket_priority' THEN
                CASE ticket_priority
                    WHEN 'High' THEN 1
                    WHEN 'Medium' THEN 2
                    WHEN 'Low' THEN 3
                    ELSE 4  -- Optional: for unexpected priority values
                END
            ELSE NULL
        END $order,
        $sort $order  -- Apply normal sorting by $sort and $order
    LIMIT $record_from, $record_to";

$sql = mysqli_query($mysqli,$query);

$num_rows = mysqli_fetch_row(mysqli_query($mysqli, "SELECT FOUND_ROWS()"));

//Get Total tickets open
$sql_total_tickets_open = mysqli_query($mysqli, "SELECT COUNT(ticket_id) AS total_tickets_open FROM tickets WHERE ticket_resolved_at IS NULL $client_query $access_permission_query_overide");
$row = mysqli_fetch_assoc($sql_total_tickets_open);
$total_tickets_open = intval($row['total_tickets_open']);

//Get Total tickets closed
$sql_total_tickets_closed = mysqli_query($mysqli, "SELECT COUNT(ticket_id) AS total_tickets_closed FROM tickets WHERE ticket_resolved_at IS NOT NULL $client_query $access_permission_query_overide");
$row = mysqli_fetch_assoc($sql_total_tickets_closed);
$total_tickets_closed = intval($row['total_tickets_closed']);

//Get Unassigned tickets
$sql_total_tickets_unassigned = mysqli_query($mysqli, "SELECT COUNT(ticket_id) AS total_tickets_unassigned FROM tickets WHERE ticket_assigned_to = '0' AND ticket_resolved_at IS NULL $client_query $access_permission_query_overide");
$row = mysqli_fetch_assoc($sql_total_tickets_unassigned);
$total_tickets_unassigned = intval($row['total_tickets_unassigned']);

//Get Total tickets assigned to me
$sql_total_tickets_assigned = mysqli_query($mysqli, "SELECT COUNT(ticket_id) AS total_tickets_assigned FROM tickets WHERE ticket_assigned_to = $session_user_id AND ticket_resolved_at IS NULL $client_query $access_permission_query_overide");
$row = mysqli_fetch_assoc($sql_total_tickets_assigned);
$user_active_assigned_tickets = intval($row['total_tickets_assigned']);

$sql_categories_filter = mysqli_query(
    $mysqli,
    "SELECT * FROM categories
    WHERE category_type = 'Ticket'
    AND category_archived_at IS NULL
    ORDER BY category_name"
);

?>
    <style>
        .popover {
            max-width: 600px;
        }
    </style>
    <div class="card card-dark">
        <div class="card-header py-2">
            <h3 class="card-title mt-2"><i class="fa fa-fw fa-life-ring mr-2"></i>Tickets
                <small class="ml-3">
                    <a href="?<?= $client_url ?>status=Open" class="badge badge-pill text-light p-1 <?php if($status == 'Open') { echo "badge-light text-dark"; } ?>"><strong><?= $total_tickets_open ?></strong> Open</a> |
                    <a href="?<?= $client_url ?>status=Closed" class="badge badge-pill text-light p-1 <?php if($status == 'Closed') { echo "badge-light text-dark"; } ?>"><strong><?= $total_tickets_closed ?></strong> Closed</a>
                </small>
            </h3>
            <?php if (lookupUserPermission("module_support") >= 2) { ?>
                <div class="card-tools">
                    <div class="btn-group">
                        <button type="button" class="btn btn-primary ajax-modal" data-modal-url="modals/ticket/ticket_add_v2.php?<?= $client_url ?>" data-modal-size="lg">
                            <i class="fas fa-plus"></i><span class="d-none d-lg-inline ml-2">New Ticket</span>
                        </button>
                        <?php if ($num_rows[0] > 0) { ?>
                        <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-toggle="dropdown"></button>
                        <div class="dropdown-menu">
                            <a class="dropdown-item text-dark ajax-modal" href="#"
                                data-modal-url="modals/ticket/ticket_export.php?<?= $client_url ?>">
                                <i class="fa fa-fw fa-download mr-2"></i>Export
                            </a>
                        </div>
                        <?php } ?>
                    </div>
                </div>
            <?php } ?>
        </div>
        <div class="card-body">
            <form autocomplete="off">
                <?php if ($client_url) { ?>
                    <input type="hidden" name="client_id" value="<?= $client_id ?>">
                <?php } ?>
                <input type="hidden" name="status" value="<?= $status ?>">
                <input type="hidden" name="view" value="<?= nullable_htmlentities($_GET['view'] ?? 'list') ?>">
                <div class="row">
                    <div class="col-sm-4">
                        <div class="input-group mb-3 mb-sm-0">
                            <input type="search" class="form-control" name="q" value="<?php if (isset($q)) { echo stripslashes(nullable_htmlentities($q)); } ?>" placeholder="Search Tickets">
                            <div class="input-group-append">
                                <button class="btn btn-secondary" type="button" data-itflow-marker="ITFLOW_TICKET_FILTER_TOGGLE_DISABLED"><i class="fas fa-filter"></i></button>
                                <button class="btn btn-primary"><i class="fa fa-search"></i></button>
                            </div>
                        </div>
                    </div>

                    <div class="col-sm-3">
                        <div class="form-group">
                            <select class="form-control select2" name="category" onchange="this.form.submit()">
                                <option value="">- All Categories -</option>

                                <?php
                                while ($row = mysqli_fetch_assoc($sql_categories_filter)) {
                                    $category_id = intval($row['category_id']);
                                    $category_name = nullable_htmlentities($row['category_name']);
                                ?>
                                    <option <?php if ($category_filter == $category_id) { echo "selected"; } ?> value="<?php echo $category_id; ?>"><?php echo $category_name; ?></option>
                                <?php
                                }
                                ?>

                            </select>
                        </div>
                    </div>
                    <div class="col-sm-5">
                        <div class="btn-group float-right">
                            <div class="btn-group">
                                <button class="btn btn-outline-dark dropdown-toggle" id="dropdownMenuButton" data-toggle="dropdown">
                                    <i class="fa fa-fw fa-eye"></i>
                                    <span class="d-none d-xl-inline ml-2">View</span>
                                </button>
                                <div class="dropdown-menu">
                                    <a class="dropdown-item" href="<?=htmlspecialchars('?' . http_build_query(array_merge($_GET, ['view' => 'list']))); ?>">List</a>
                                    <?php if ($status !== 'Closed') {?>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item " href="<?=htmlspecialchars('?' . http_build_query(array_merge($_GET, ['view' => 'kanban']))); ?>">Kanban</a>
                                    <?php } ?>
                                </div>
                            </div>
                            <div class="btn-group">
                                <button class="btn btn-outline-dark dropdown-toggle" id="categoriesDropdownMenuButton" data-toggle="dropdown">
                                    <i class="fa fa-fw fa-envelope"></i>
                                    <span class="d-none d-xl-inline ml-2">My Tickets</span>
                                </button>
                                <div class="dropdown-menu">
                                    <a class="dropdown-item" href="?<?php echo $client_url; ?>status=Open&assigned=<?php echo $session_user_id ?>">Active tickets (<?php echo $user_active_assigned_tickets ?>)</a>
                                    <div class="dropdown-divider"></div>
                                    <a class="dropdown-item " href="?<?php echo $client_url; ?>status=Closed&assigned=<?php echo $session_user_id ?>">Closed tickets</a>
                                </div>
                            </div>
                            <a href="?<?php echo $client_url; ?>assigned=unassigned" class="btn btn-outline-danger">
                                <i class="fa fa-fw fa-exclamation-triangle"></i>
                                <span class="d-none d-xl-inline ml-2">Unassigned</span> | <strong> <?php echo $total_tickets_unassigned; ?></strong>
                            </a>

                            <?php if (lookupUserPermission("module_support") >= 2) { ?>
                                <div class="dropdown ml-2" id="bulkActionButton" hidden>
                                    <button class="btn btn-secondary dropdown-toggle" type="button" data-toggle="dropdown">
                                        <i class="fas fa-fw fa-layer-group mr-2"></i>Bulk Action (<span id="selectedCount">0</span>)
                                    </button>
                                    <div class="dropdown-menu">
                                        <a class="dropdown-item ajax-modal" href="#"
                                            data-modal-url="modals/ticket/ticket_bulk_assign.php"
                                            data-bulk="true">
                                            <i class="fas fa-fw fa-user-check mr-2"></i>Assign Agent
                                        </a>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item ajax-modal" href="#"
                                            data-modal-url="modals/ticket/ticket_bulk_edit_category.php"
                                            data-bulk="true">
                                            <i class="fas fa-fw fa-layer-group mr-2"></i>Set Category
                                        </a>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item ajax-modal" href="#"
                                            data-modal-url="modals/ticket/ticket_bulk_edit_priority.php"
                                            data-bulk="true">
                                            <i class="fas fa-fw fa-thermometer-half mr-2"></i>Set Priority
                                        </a>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item ajax-modal" href="#"
                                            data-modal-url="modals/ticket/ticket_bulk_reply.php"
                                            data-modal-size="lg"
                                            data-bulk="true">
                                            <i class="fas fa-fw fa-paper-plane mr-2"></i>Update/Reply
                                        </a>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item ajax-modal" href="#"
                                            data-modal-url="modals/ticket/ticket_bulk_add_project.php"
                                            data-bulk="true">
                                            <i class="fas fa-fw fa-project-diagram mr-2"></i>Set Project
                                        </a>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item ajax-modal" href="#"
                                            data-modal-url="modals/ticket/ticket_bulk_merge.php"
                                            data-bulk="true">
                                            <i class="fas fa-fw fa-clone mr-2"></i>Merge
                                        </a>
                                        <div class="dropdown-divider"></div>
                                        <a class="dropdown-item ajax-modal" href="#"
                                            data-modal-url="modals/ticket/ticket_bulk_resolve.php"
                                            data-modal-size="lg"
                                            data-bulk="true">
                                            <i class="fas fa-fw fa-check mr-2"></i>Resolve
                                        </a>
                                        <?php if (lookupUserPermission("module_support") === 3) { ?>
                                        <div class="dropdown-divider"></div>
                                        <button class="dropdown-item text-danger text-bold confirm-link" type="submit" form="bulkActions" name="bulk_delete_tickets">
                                            <i class="fas fa-fw fa-trash mr-2"></i>Delete
                                        </button>
                                        <?php } ?>
                                    </div>
                                </div>
                            <?php } ?>

                        </div>

                    </div>
                </div>

                <!-- ITFLOW_TICKET_FILTERS_ALWAYS_VISIBLE -->
                  <div class="mt-3" id="advancedFilter">
                    <div class="row">
                        <div class="col-md-3">
                            <div class="form-group">
                                <label>Date range</label>
                                <input type="text" id="dateFilter" class="form-control" autocomplete="off">
                                <input type="hidden" name="canned_date" id="canned_date" value="<?php echo nullable_htmlentities($_GET['canned_date']) ?? ''; ?>">
                                <input type="hidden" name="dtf" id="dtf" value="<?php echo nullable_htmlentities($dtf ?? ''); ?>">
                                <input type="hidden" name="dtt" id="dtt" value="<?php echo nullable_htmlentities($dtt ?? ''); ?>">
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="form-group">
                                <label>Ticket Status</label>
                                <select onchange="this.form.submit()" class="form-control select2" name="status[]" data-placeholder="Any" multiple>
                                    <!-- ITFLOW_TICKET_STATUS_PLACEHOLDER_ANY_UI -->
                                        <!-- ITFLOW_TICKET_FILTER_ANY_CLEAR_ACTIONS_STATUS -->
                                    <option value="__clear__" data-itflow-clear-filter="status">Any</option>
                                    <?php $sql_ticket_status = mysqli_query($mysqli, "SELECT * FROM ticket_statuses WHERE ticket_status_active = 1 ORDER BY ticket_status_order");
                                        while ($row = mysqli_fetch_assoc($sql_ticket_status)) {
                                            $ticket_status_id = intval($row['ticket_status_id']);
                                            $ticket_status_name = nullable_htmlentities($row['ticket_status_name']); ?>

                                            <option value="<?php echo $ticket_status_id ?>" <?php if (!empty($ticket_status_filter_values) && in_array($ticket_status_id, $ticket_status_filter_values, true)) { echo 'selected'; } ?>> <?php echo $ticket_status_name ?> </option>

                                        <?php } ?>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="form-group">
                                <label>Assigned to</label>
                                <select onchange="this.form.submit()" class="form-control select2" name="assigned[]" data-placeholder="Any" multiple>
                                    <!-- ITFLOW_TICKET_ASSIGNED_PLACEHOLDER_ANY_UI -->
                                    <!-- ITFLOW_TICKET_ASSIGNED_ANY_UNASSIGNED_ORDER -->
                                    <!-- ITFLOW_TICKET_FILTER_ANY_CLEAR_ACTIONS_ASSIGNED -->
                                    <option value="__clear__" data-itflow-clear-filter="assigned">Any</option>
                                    <option value="unassigned" <?php if (!empty($ticket_assigned_filter_values) && in_array('unassigned', $ticket_assigned_filter_values, true)) { echo "selected"; } ?>>Unassigned</option>

                                    <?php
                                    $sql_assign_to = mysqli_query($mysqli, "SELECT * FROM users WHERE user_type = 1 AND user_archived_at IS NULL ORDER BY user_name ASC");
                                    while ($row = mysqli_fetch_assoc($sql_assign_to)) {
                                        $user_id = intval($row['user_id']);
                                        $user_name = nullable_htmlentities($row['user_name']);
                                        ?>
                                        <option <?php if (!empty($ticket_assigned_filter_values) && in_array((string)$user_id, $ticket_assigned_filter_values, true)) { echo "selected"; } ?> value="<?php echo $user_id; ?>"><?php echo $user_name; ?></option>
                                        <?php
                                    }
                                    ?>

                                </select>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="form-group">
                                <label>Project</label>
                                <select onchange="this.form.submit()" class="form-control select2" name="project[]" data-placeholder="Any" multiple>
                                    <!-- ITFLOW_TICKET_PROJECT_PLACEHOLDER_ANY_UI -->
                                    <!-- ITFLOW_TICKET_FILTER_ANY_CLEAR_ACTIONS_PROJECT -->
                                    <option value="__clear__" data-itflow-clear-filter="project">Any</option>
                                    <?php
                                    $sql_projects = mysqli_query($mysqli, "SELECT * FROM projects WHERE project_completed_at IS NULL and project_archived_at IS NULL ORDER BY project_name ASC");
                                    while ($row = mysqli_fetch_assoc($sql_projects)) {
                                        $project_id = intval($row['project_id']);
                                        $project_prefix = nullable_htmlentities($row['project_prefix']);
                                        $project_number = intval($row['project_number']);
                                        $project_name = nullable_htmlentities($row['project_name']);
                                        ?>
                                        <option <?php if (!empty($ticket_project_filter_values) && in_array((string)$project_id, $ticket_project_filter_values, true)) { echo "selected"; } ?> value="<?php echo $project_id; ?>"><?php echo $project_prefix . $project_number . " - " . $project_name; ?></option>
                                        <?php
                                    }
                                    ?>

                                </select>
                            </div>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>

<?php

if (isset($_GET["view"])) {
    if ($_GET["view"] == "list") {
        require_once "ticket_list.php";
    } elseif ($_GET["view"] == "kanban") {
        require_once "ticket_kanban.php";
    }
} else {
    // here we have to get default view setting
    if ($config_ticket_default_view === 0) {
        require_once "ticket_list.php";
    } elseif ($config_ticket_default_view === 2) {
        require_once "ticket_kanban.php";
    } else {
        require_once "ticket_list.php";
    }
}

?>



<script>
// ITFLOW_TICKET_FILTER_ANY_CLEAR_ACTIONS_JS
document.addEventListener('DOMContentLoaded', function () {
    var clearValue = '__clear__';
    var filterNames = ['status[]', 'assigned[]', 'project[]'];

    function arrayFromSelected(select) {
        return Array.prototype.map.call(select.selectedOptions, function (option) {
            return option.value;
        });
    }

    function clearAndSubmit(select) {
        Array.prototype.forEach.call(select.options, function (option) {
            option.selected = false;
        });

        if (window.jQuery && window.jQuery.fn && window.jQuery.fn.select2) {
            window.jQuery(select).val(null).trigger('change.select2');
        }

        if (select.form) {
            select.form.submit();
        }
    }

    filterNames.forEach(function (name) {
        var select = document.querySelector('select[name="' + name + '"]');
        if (!select) {
            return;
        }

        if (window.jQuery && window.jQuery.fn && window.jQuery.fn.select2) {
            window.jQuery(select).on('select2:select', function (event) {
                if (event.params && event.params.data && event.params.data.id === clearValue) {
                    clearAndSubmit(select);
                }
            });
        }

        select.addEventListener('change', function () {
            var values = arrayFromSelected(select);
            if (values.indexOf(clearValue) !== -1) {
                clearAndSubmit(select);
            }
        });
    });
});
</script>

<script src="../js/bulk_actions.js"></script>

<?php
require_once "../includes/footer.php";
