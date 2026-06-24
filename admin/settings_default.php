<?php
require_once "includes/inc_all_admin.php";

$start_page_select_array = array (
    'dashboard.php'=>'Dashboard',
    'clients.php'=> 'Client Management',
    'internal.php'=> 'Internal Workspace',
    'tickets.php'=> 'Support Tickets',
    'invoices.php' => 'Invoices'
);

$net_terms_array = array (
    '0'=>'On Receipt',
    '7'=>'7 Days',
    '10'=>'10 Days',
    '15'=>'15 Days',
    '30'=>'30 Days',
    '45'=>'45 Days',
    '60'=>'60 Days',
    '90'=>'90 Days'
);

$sql_internal_client_select = mysqli_query($mysqli, "SELECT client_id, client_name FROM clients WHERE client_archived_at IS NULL ORDER BY client_name ASC");

?>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-cogs mr-2"></i>Defaults</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <div class="form-group">
                <label>Start Page</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-home"></i></span>
                    </div>
                    <select class="form-control select2" name="start_page" data-tags="true" required>
                        <?php if (!in_array($config_start_page, array_keys($start_page_select_array))) { ?>
                            <option selected> <?php echo nullable_htmlentities($config_start_page); ?></option>
                        <?php } ?>
                        <?php foreach ($start_page_select_array as $start_page_value => $start_page_name) { ?>
                            <option <?php if ($start_page_value == $config_start_page) { echo "selected"; } ?>
                                value="<?php echo nullable_htmlentities($start_page_value); ?>">
                                <?php echo nullable_htmlentities($start_page_name); ?>
                            </option>
                        <?php }?>
                    </select>
                </div>
            </div>

            <hr>

            <h5 class="mb-3"><i class="fas fa-fw fa-building mr-2"></i>Internal Workspace</h5>

            <div class="card card-outline card-secondary mb-4">
                <div class="card-body">
                    <div class="form-group">
                        <div class="custom-control custom-switch">
                            <input type="checkbox" class="custom-control-input" name="internal_workspace_enable" value="1" id="internalWorkspaceSwitch" <?php if (($config_internal_workspace_enable ?? 0) == 1) { echo "checked"; } ?>>
                            <label class="custom-control-label text-bold" for="internalWorkspaceSwitch">Enable Internal Workspace</label>
                        </div>
                        <small class="text-secondary">Adds a dedicated Internal section to the agent sidebar. If no organization is selected yet, admins can configure or create it from the Internal page.</small>
                    </div>

                    <div class="form-group">
                        <label>Internal Menu Name</label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span>
                            </div>
                            <input type="text" class="form-control" name="internal_workspace_name" maxlength="100" value="<?php echo nullable_htmlentities($config_internal_workspace_name ?? 'Internal'); ?>" placeholder="Internal">
                        </div>
                    </div>

                    <?php $internal_workspace_record_mode = empty($config_internal_client_id ?? 0) ? 'create' : 'existing'; ?>
                    <div class="form-group">
                        <label>Internal Organization Setup</label>
                        <div class="btn-group btn-group-toggle d-flex" data-toggle="buttons">
                            <label class="btn btn-outline-secondary flex-fill <?php if ($internal_workspace_record_mode === 'existing') { echo 'active'; } ?>" for="internalWorkspaceModeExisting">
                                <input type="radio" name="internal_workspace_record_mode" id="internalWorkspaceModeExisting" value="existing" <?php if ($internal_workspace_record_mode === 'existing') { echo 'checked'; } ?>>
                                <i class="fas fa-fw fa-users mr-1"></i>Use Existing Organization
                            </label>
                            <label class="btn btn-outline-secondary flex-fill <?php if ($internal_workspace_record_mode === 'create') { echo 'active'; } ?>" for="internalWorkspaceModeCreate">
                                <input type="radio" name="internal_workspace_record_mode" id="internalWorkspaceModeCreate" value="create" <?php if ($internal_workspace_record_mode === 'create') { echo 'checked'; } ?>>
                                <i class="fas fa-fw fa-plus-circle mr-1"></i>Create New Internal Organization
                            </label>
                        </div>
                    </div>

                    <div class="form-group internal-workspace-mode-panel" id="internalWorkspaceExistingPanel">
                        <label>Internal Organization Record</label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fa fa-fw fa-users"></i></span>
                            </div>
                            <select class="form-control select2" name="internal_client_id">
                                <option value="0">- Select Existing Organization -</option>
                                <?php
                                mysqli_data_seek($sql_internal_client_select, 0);
                                while ($row = mysqli_fetch_assoc($sql_internal_client_select)) {
                                    $internal_client_id_select = intval($row['client_id']);
                                    $internal_client_name_select = nullable_htmlentities($row['client_name']);
                                ?>
                                    <option value="<?php echo $internal_client_id_select; ?>" <?php if (($config_internal_client_id ?? 0) == $internal_client_id_select) { echo "selected"; } ?>><?php echo $internal_client_name_select; ?></option>
                                <?php } ?>
                            </select>
                        </div>
                        <small class="text-secondary">Use an existing organization/client record. Existing docs, credentials, assets, domains, vendors, tickets, and related data stay attached to that record.</small>
                    </div>

                    <div class="form-group internal-workspace-mode-panel" id="internalWorkspaceCreatePanel">
                        <label>Create New Internal Organization</label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fa fa-fw fa-plus-circle"></i></span>
                            </div>
                            <input type="text" class="form-control" name="internal_create_client_name" maxlength="200" placeholder="Example: <?php echo nullable_htmlentities($company_name ?? 'Internal Organization'); ?> Internal">
                        </div>
                        <small class="text-secondary">Creates or reuses an active organization with this exact name, marks it Internal, enables the Internal Workspace, and uses it immediately.</small>
                    </div>

                    <div class="form-group mb-0">
                        <div class="custom-control custom-switch">
                            <input type="checkbox" class="custom-control-input" name="internal_hide_from_clients" value="1" id="internalHideFromClientsSwitch" <?php if (($config_internal_hide_from_clients ?? 1) == 1) { echo "checked"; } ?>>
                            <label class="custom-control-label text-bold" for="internalHideFromClientsSwitch">Hide Internal Workspace from Clients list</label>
                        </div>
                        <small class="text-secondary">Keeps the selected internal record out of normal client management views while preserving access through the Internal sidebar item.</small>
                    </div>
                </div>
            </div>

            <div class="form-group">
                <label>Calendar</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-calendar"></i></span>
                    </div>
                    <select class="form-control select2" name="calendar">
                        <option value="0">- None -</option>
                        <?php

                        $sql = mysqli_query($mysqli, "SELECT * FROM calendars ORDER BY calendar_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $calendar_id = intval($row['calendar_id']);
                            $calendar_name = nullable_htmlentities($row['calendar_name']); ?>
                            <option <?php if ($config_default_calendar == $calendar_id) {
                                        echo "selected";
                                    } ?> value="<?php echo $calendar_id; ?>"><?php echo $calendar_name; ?></option>
                        <?php } ?>

                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Transfer From Account</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-exchange-alt"></i></span>
                    </div>
                    <select class="form-control select2" name="transfer_from_account">
                        <option value="0">- None -</option>
                        <?php

                        $sql = mysqli_query($mysqli, "SELECT * FROM accounts WHERE account_archived_at IS NULL ORDER BY account_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $account_id = intval($row['account_id']);
                            $account_name = nullable_htmlentities($row['account_name']); ?>
                            <option <?php if ($config_default_transfer_from_account == $account_id) {
                                        echo "selected";
                                    } ?> value="<?php echo $account_id; ?>"><?php echo $account_name; ?></option>
                        <?php } ?>

                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Transfer To Account</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-exchange-alt"></i></span>
                    </div>
                    <select class="form-control select2" name="transfer_to_account">
                        <option value="0">- None -</option>
                        <?php

                        $sql = mysqli_query($mysqli, "SELECT * FROM accounts WHERE account_archived_at IS NULL ORDER BY account_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $account_id = intval($row['account_id']);
                            $account_name = nullable_htmlentities($row['account_name']); ?>
                            <option <?php if ($config_default_transfer_to_account == $account_id) {
                                        echo "selected";
                                    } ?> value="<?php echo $account_id; ?>"><?php echo $account_name; ?></option>
                        <?php } ?>

                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Payment Account</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-credit-card"></i></span>
                    </div>
                    <select class="form-control select2" name="payment_account">
                        <option value="0">- None -</option>
                        <?php

                        $sql = mysqli_query($mysqli, "SELECT * FROM accounts WHERE account_archived_at IS NULL ORDER BY account_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $account_id = intval($row['account_id']);
                            $account_name = nullable_htmlentities($row['account_name']); ?>
                            <option <?php if ($config_default_payment_account == $account_id) {
                                        echo "selected";
                                    } ?> value="<?php echo $account_id; ?>"><?php echo $account_name; ?></option>
                        <?php
                        }
                        ?>

                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Expense Account</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-shopping-cart"></i></span>
                    </div>
                    <select class="form-control select2" name="expense_account">
                        <option value="0">- None -</option>
                        <?php

                        $sql = mysqli_query($mysqli, "SELECT * FROM accounts WHERE account_archived_at IS NULL ORDER BY account_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $account_id = intval($row['account_id']);
                            $account_name = nullable_htmlentities($row['account_name']); ?>
                            <option <?php if ($config_default_expense_account == $account_id) {
                                        echo "selected";
                                    } ?> value="<?php echo $account_id; ?>"><?php echo $account_name; ?></option>
                        <?php } ?>

                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Payment Method</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-credit-card"></i></span>
                    </div>
                    <select class="form-control select2" name="payment_method">
                        <option value="">- None -</option>
                        <?php

                        $sql = mysqli_query($mysqli, "SELECT * FROM categories WHERE category_type = 'Payment Method' ORDER BY category_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $payment_method = nullable_htmlentities($row['category_name']); ?>
                            <option <?php if ($config_default_payment_method == $payment_method) {
                                        echo "selected";
                                    } ?>><?php echo $payment_method; ?></option>
                        <?php } ?>

                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Expense Payment Method</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-credit-card"></i></span>
                    </div>
                    <select class="form-control select2" name="expense_payment_method">
                        <option value="">- None -</option>
                        <?php

                        $sql = mysqli_query($mysqli, "SELECT * FROM categories WHERE category_type = 'Payment Method' ORDER BY category_name ASC");
                        while ($row = mysqli_fetch_assoc($sql)) {
                            $payment_method = nullable_htmlentities($row['category_name']); ?>
                            <option <?php if ($config_default_expense_payment_method == $payment_method) {
                                        echo "selected";
                                    } ?>><?php echo $payment_method; ?></option>
                        <?php } ?>

                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Net Terms</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-calendar"></i></span>
                    </div>
                    <select class="form-control select2" name="net_terms">
                        <?php foreach ($net_terms_array as $net_term_value => $net_term_name) { ?>
                            <option <?php if ($config_default_net_terms == $net_term_value) {
                                        echo "selected";
                                    } ?> value="<?php echo $net_term_value; ?>"><?php echo $net_term_name; ?></option>
                        <?php } ?>
                    </select>
                </div>
            </div>

            <div class="form-group">
                <label>Client Hourly Rate</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-clock"></i></span>
                    </div>
                    <input type="text" class="form-control" inputmode="decimal" pattern="[0-9]*\.?[0-9]{0,2}" name="hourly_rate" value="<?php echo number_format($config_default_hourly_rate, 2, '.', ''); ?>" placeholder="0.00" required>
                </div>
            </div>

            <hr>

            <button type="submit" name="edit_default_settings" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Save</button>

        </form>
    </div>
</div>

<?php
require_once "../includes/footer.php";
