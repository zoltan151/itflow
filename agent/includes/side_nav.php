<!-- Main Sidebar Container -->
<aside class="main-sidebar sidebar-dark-<?php echo nullable_htmlentities($config_theme); ?> d-print-none itflow-main-sidebar-branded">

    <?php
    $sidebar_brand_display = $config_sidebar_brand_display ?? 'text';
    if ($sidebar_brand_display == 'name') { $sidebar_brand_display = 'text'; }
    if ($sidebar_brand_display == 'logo_name') { $sidebar_brand_display = 'logo_text'; }
    if (!in_array($sidebar_brand_display, ['text', 'logo', 'logo_text'], true)) {
        $sidebar_brand_display = 'text';
    }

    $sidebar_company_logo = '';
    $sql_sidebar_company_logo = mysqli_query($mysqli, "SELECT company_logo FROM companies WHERE company_id = 1 LIMIT 1");
    if ($sql_sidebar_company_logo) {
        $row_sidebar_company_logo = mysqli_fetch_assoc($sql_sidebar_company_logo);
        $sidebar_company_logo = $row_sidebar_company_logo['company_logo'] ?? '';
    }

    $sidebar_logo_path = '';
    if (!empty($sidebar_company_logo) && file_exists($_SERVER['DOCUMENT_ROOT'] . '/uploads/settings/' . $sidebar_company_logo)) {
        $sidebar_logo_path = '/uploads/settings/' . rawurlencode($sidebar_company_logo);
    }

    if (($sidebar_brand_display === 'logo' || $sidebar_brand_display === 'logo_text') && empty($sidebar_logo_path)) {
        $sidebar_brand_display = 'text';
    }

    $sidebar_brand_text_source = $config_sidebar_brand_text_source ?? 'company';
    if (!in_array($sidebar_brand_text_source, ['company', 'custom'], true)) {
        $sidebar_brand_text_source = 'company';
    }
    $sidebar_brand_custom_text = trim($config_sidebar_brand_custom_text ?? '');
    $sidebar_brand_text = ($sidebar_brand_text_source === 'custom' && $sidebar_brand_custom_text !== '') ? $sidebar_brand_custom_text : $session_company_name;

    $sidebar_brand_background_mode = $config_sidebar_brand_background_mode ?? 'none';
    if (!in_array($sidebar_brand_background_mode, ['none', 'preset', 'custom'], true)) {
        $sidebar_brand_background_mode = 'none';
    }
    $sidebar_brand_background_color = $config_sidebar_brand_background_color ?? '#343a40';
    if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $sidebar_brand_background_color)) {
        $sidebar_brand_background_color = '#343a40';
    }
    $sidebar_brand_background_opacity = max(0, min(100, intval($config_sidebar_brand_background_opacity ?? 100)));
    $sidebar_brand_background_style = '';
    if ($sidebar_brand_background_mode !== 'none') {
        $hex = ltrim($sidebar_brand_background_color, '#');
        if (!preg_match('/^[0-9A-Fa-f]{6}$/', $hex)) {
            $hex = '343a40';
        }
        $r = hexdec(substr($hex, 0, 2));
        $g = hexdec(substr($hex, 2, 2));
        $b = hexdec(substr($hex, 4, 2));
        $a = $sidebar_brand_background_opacity / 100;
        $sidebar_brand_background_style = "background-color: rgba($r,$g,$b,$a) !important;";
    }


    $sidebar_brand_text_color_mode = $config_sidebar_brand_text_color_mode ?? 'default';
    if (!in_array($sidebar_brand_text_color_mode, ['default', 'preset', 'custom'], true)) {
        $sidebar_brand_text_color_mode = 'default';
    }
    $sidebar_brand_text_color = $config_sidebar_brand_text_color ?? '#ffffff';
    if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $sidebar_brand_text_color)) {
        $sidebar_brand_text_color = '#ffffff';
    }
    $sidebar_brand_text_color_opacity = max(0, min(100, intval($config_sidebar_brand_text_color_opacity ?? 100)));
    $sidebar_brand_text_color_style = '';
    if ($sidebar_brand_text_color_mode !== 'default') {
        $text_hex = ltrim($sidebar_brand_text_color, '#');
        if (!preg_match('/^[0-9A-Fa-f]{6}$/', $text_hex)) {
            $text_hex = 'ffffff';
        }
        $tr = hexdec(substr($text_hex, 0, 2));
        $tg = hexdec(substr($text_hex, 2, 2));
        $tb = hexdec(substr($text_hex, 4, 2));
        $ta = $sidebar_brand_text_color_opacity / 100;
        $sidebar_brand_text_color_style = "color: rgba($tr,$tg,$tb,$ta) !important;";
    }

    $sidebar_brand_layout = $config_sidebar_brand_layout ?? 'logo_left';
    if (!in_array($sidebar_brand_layout, ['logo_left', 'logo_right', 'logo_top', 'logo_bottom'], true)) {
        $sidebar_brand_layout = 'logo_left';
    }

    $sidebar_brand_logo_size = $config_sidebar_brand_logo_size ?? 'medium';
    if (!in_array($sidebar_brand_logo_size, ['tiny', 'small', 'medium', 'large', 'xlarge', 'huge'], true)) {
        $sidebar_brand_logo_size = 'medium';
    }

    $sidebar_brand_text_size = $config_sidebar_brand_text_size ?? ($config_sidebar_brand_name_size ?? 'medium');
    if (!in_array($sidebar_brand_text_size, ['tiny', 'small', 'medium', 'large', 'xlarge', 'huge'], true)) {
        $sidebar_brand_text_size = 'medium';
    }

    $sidebar_logo_sizes = [
        'tiny' => ['height' => 18, 'width' => 90],
        'small' => ['height' => 24, 'width' => 120],
        'medium' => ['height' => 34, 'width' => 165],
        'large' => ['height' => 44, 'width' => 195],
        'xlarge' => ['height' => 56, 'width' => 220],
        'huge' => ['height' => 68, 'width' => 235],
    ];
    $sidebar_text_sizes = [
        'tiny' => ['font' => '0.8rem', 'px' => 13],
        'small' => ['font' => '1rem', 'px' => 16],
        'medium' => ['font' => '1.25rem', 'px' => 20],
        'large' => ['font' => '1.5rem', 'px' => 24],
        'xlarge' => ['font' => '1.75rem', 'px' => 28],
        'huge' => ['font' => '2rem', 'px' => 32],
    ];
    $sidebar_logo_height_px = $sidebar_logo_sizes[$sidebar_brand_logo_size]['height'];
    $sidebar_logo_width_px = $sidebar_logo_sizes[$sidebar_brand_logo_size]['width'];
    $sidebar_text_font_size = $sidebar_text_sizes[$sidebar_brand_text_size]['font'];
    $sidebar_text_height_px = $sidebar_text_sizes[$sidebar_brand_text_size]['px'];

    $sidebar_brand_direction = 'row';
    $sidebar_brand_height_px = 64;
    if ($sidebar_brand_display === 'logo') {
        $sidebar_brand_height_px = max(64, $sidebar_logo_height_px + 28);
    } elseif ($sidebar_brand_display === 'text') {
        $sidebar_brand_height_px = max(57, $sidebar_text_height_px + 28);
    } elseif ($sidebar_brand_display === 'logo_text') {
        if ($sidebar_brand_layout === 'logo_top' || $sidebar_brand_layout === 'logo_bottom') {
            $sidebar_brand_direction = 'column';
            $sidebar_brand_height_px = max(82, $sidebar_logo_height_px + $sidebar_text_height_px + 38);
        } else {
            $sidebar_brand_height_px = max(64, max($sidebar_logo_height_px, $sidebar_text_height_px) + 30);
        }
    }
    $sidebar_brand_height = $sidebar_brand_height_px . 'px';
    $sidebar_logo_order = ($sidebar_brand_layout === 'logo_right' || $sidebar_brand_layout === 'logo_bottom') ? 2 : 1;
    $sidebar_text_order = ($sidebar_brand_layout === 'logo_right' || $sidebar_brand_layout === 'logo_bottom') ? 1 : 2;
    ?>
<style>
    .itflow-main-sidebar-branded {
        display: flex !important;
        flex-direction: column !important;
        height: 100vh !important;
        max-height: 100vh !important;
        overflow: hidden !important;
        border-right: 1px solid rgba(0, 0, 0, .22) !important;
        box-shadow: 2px 0 4px rgba(0, 0, 0, .06);
        box-sizing: border-box;
    }
    .brand-link.itflow-sidebar-brand-link {
        position: relative !important;
        top: auto !important;
        left: auto !important;
        right: auto !important;
        z-index: 20;
        flex: 0 0 auto;
        width: 100%;
        min-height: <?php echo $sidebar_brand_height; ?> !important;
        display: flex !important;
        flex-direction: <?php echo $sidebar_brand_direction; ?>;
        align-items: center;
        justify-content: center;
        gap: .35rem;
        overflow: hidden;
        text-align: center;
        padding: .85rem .8rem !important;
        margin: 0 !important;
        border-radius: 0 !important;
        border-bottom: 1px solid rgba(255,255,255,.12);
        box-sizing: border-box;
        background-clip: border-box;
        <?php echo $sidebar_brand_background_style; ?>
    }
    .itflow-sidebar-brand-logo-wrap {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: 0 1 auto;
        order: <?php echo $sidebar_logo_order; ?>;
        min-width: 0;
    }
    .itflow-sidebar-brand-logo {
        display: block;
        max-height: <?php echo $sidebar_logo_height_px; ?>px;
        max-width: <?php echo $sidebar_logo_width_px; ?>px;
        width: auto;
        height: auto;
        object-fit: contain;
        flex: 0 1 auto;
    }
    .itflow-sidebar-brand-text {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        min-width: 0;
        max-width: 100%;
        order: <?php echo $sidebar_text_order; ?>;
        font-size: <?php echo $sidebar_text_font_size; ?> !important;
        line-height: 1.1;
        margin: 0;
        <?php echo $sidebar_brand_text_color_style; ?>
    }
    .itflow-main-sidebar-branded > .sidebar {
        flex: 1 1 auto !important;
        min-height: 0 !important;
        margin-top: 0 !important;
        padding-top: .75rem !important;
        height: auto !important;
        max-height: none !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
        clear: both;
        box-sizing: border-box;
    }
    .itflow-main-sidebar-branded > .sidebar > nav > .nav-sidebar {
        margin-top: 0 !important;
    }
    html, body {
        min-height: 100%;
    }
    .wrapper {
        overflow-x: hidden;
    }
    .content-wrapper {
        overflow-x: hidden;
    }

    body.sidebar-collapse .brand-link.itflow-sidebar-brand-link {
        min-height: 57px !important;
        height: 57px !important;
        max-height: 57px !important;
        padding: .45rem .25rem !important;
        flex-direction: column !important;
        gap: 0 !important;
        justify-content: center !important;
    }
    body.sidebar-collapse .itflow-sidebar-brand-logo {
        max-height: 36px !important;
        max-width: 42px !important;
        object-fit: contain;
    }
    body.sidebar-collapse .itflow-sidebar-brand-text {
        display: none !important;
    }
    body.sidebar-collapse .itflow-main-sidebar-branded > .sidebar {
        margin-top: 0 !important;
        padding-top: .5rem !important;
        height: auto !important;
        max-height: none !important;
    }
</style>

<a class="brand-link itflow-sidebar-brand-link" href="/agent/dashboard.php" style="<?php echo nullable_htmlentities($sidebar_brand_background_style); ?>">
        <?php if (($sidebar_brand_display === 'logo' || $sidebar_brand_display === 'logo_text') && !empty($sidebar_logo_path)) { ?>
            <span class="itflow-sidebar-brand-logo-wrap">
                <img src="<?php echo nullable_htmlentities($sidebar_logo_path); ?>" alt="<?php echo nullable_htmlentities($session_company_name); ?>" class="itflow-sidebar-brand-logo">
            </span>
        <?php } ?>
        <?php if ($sidebar_brand_display === 'text' || $sidebar_brand_display === 'logo_text') { ?>
            <span class="brand-text itflow-sidebar-brand-text"><?php echo nullable_htmlentities($sidebar_brand_text); ?></span>
        <?php } ?>
    </a>
<!-- Sidebar -->
    <div class="sidebar">

        <!-- Sidebar Menu -->
        <nav>
            <ul class="nav nav-pills nav-sidebar flex-column" data-widget="treeview" data-accordion="false">
                <li class="nav-item">
                    <a href="/agent/dashboard.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "dashboard.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-tachometer-alt"></i>
                        <p>Dashboard</p>
                    </a>
                </li>

                <?php if (lookupUserPermission("module_client") >= 1 && !empty($config_internal_workspace_enable)) { ?>
                    <li class="nav-item">
                        <a href="/agent/internal.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "internal.php" || (basename($_SERVER["PHP_SELF"]) == "client_overview.php" && isset($_GET['client_id']) && intval($_GET['client_id']) == intval($config_internal_client_id ?? 0))) { echo "active"; } ?>">
                            <i class="nav-icon fas fa-home"></i>
                            <p><?php echo nullable_htmlentities($config_internal_workspace_name ?: 'Internal'); ?></p>
                        </a>
                    </li>
                <?php } ?>

                <?php if (lookupUserPermission("module_client") >= 1) { ?>
                    <li class="nav-item">
                        <a href="/agent/clients.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "clients.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-users"></i>
                            <p>
                                Clients
                                <?php if ($num_active_clients) { ?>
                                    <span class="right badge text-light" data-toggle="tooltip" title="Active Clients"><?php echo $num_active_clients; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                <?php } ?>

                <?php if (lookupUserPermission("module_support") >= 1) { ?>
                    <?php if ($config_module_enable_ticketing == 1) { ?>
                        <li class="nav-header mt-3">SUPPORT</li>
                        <li class="nav-item">
                            <a href="/agent/tickets.php?all_tickets=1" data-itflow-marker="ITFLOW_TICKET_NAV_ALL_TICKETS_DEFAULT" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "tickets.php" || basename($_SERVER["PHP_SELF"]) == "ticket.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-life-ring"></i>
                                <p>
                                    Tickets
                                    <?php if ($num_active_tickets) { ?>
                                        <span class="right badge text-light" data-toggle="tooltip" title="Open Tickets"><?php echo $num_active_tickets; ?></span>
                                    <?php } ?>
                                </p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="/agent/recurring_tickets.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "recurring_tickets.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-redo-alt"></i>
                                <p>
                                    Recurring Tickets
                                    <?php if ($num_recurring_tickets) { ?>
                                        <span class="right badge text-light" data-toggle="tooltip" title="Active Recurring Tickets"><?php echo $num_recurring_tickets; ?></span>
                                    <?php } ?>
                                </p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="/agent/projects.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "projects.php" || basename($_SERVER["PHP_SELF"]) == "project_details.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-project-diagram"></i>
                                <p>
                                    Projects
                                    <?php if ($num_active_projects) { ?>
                                        <span class="right badge text-light" data-toggle="tooltip" title="Open Projects"><?php echo $num_active_projects; ?></span>
                                    <?php } ?>
                                </p>
                            </a>
                        </li>
                    <?php } ?>
                <?php } ?>

                <li class="nav-item">
                    <a href="/agent/calendar.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "calendar.php") { echo "active"; } ?>">
                        <i class="nav-icon fas fa-calendar-alt"></i>
                        <p>Calendar</p>
                    </a>
                </li>
                <?php if ($config_module_enable_accounting == 1 && lookupUserPermission("module_sales") >= 1) { ?>
                    <li class="nav-header mt-3">BILLING</li>
                    <li class="nav-item">
                        <a href="/agent/quotes.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "quotes.php" || basename($_SERVER["PHP_SELF"]) == "quote.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-comment-dollar"></i>
                            <p>
                                Quotes
                                <?php if ($num_open_quotes) { ?>
                                    <span class="right badge text-light" data-toggle="tooltip" title="Active Quotes"><?php echo $num_open_quotes; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="/agent/invoices.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "invoices.php" || basename($_SERVER["PHP_SELF"]) == "invoice.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-file-invoice"></i>
                            <p>
                                Invoices
                                <?php if ($num_open_invoices) { ?>
                                    <span class="right badge text-light" data-toggle="tooltip" title="Open Invoices"><?php echo $num_open_invoices; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="/agent/recurring_invoices.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "recurring_invoices.php" || basename($_SERVER["PHP_SELF"]) == "recurring_invoice.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-redo-alt"></i>
                            <p>
                                Recurring Invoices
                                <?php if ($num_recurring_invoices) { ?>
                                    <span class="right badge text-light" data-toggle="tooltip" title="Active Recurring Invoices"><?php echo $num_recurring_invoices; ?></span>
                                <?php } ?>
                            </p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="/agent/revenues.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "revenues.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-hand-holding-usd"></i>
                            <p>Revenues</p>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a href="/agent/products.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "products.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-box-open"></i>
                            <p>Products</p>
                        </a>
                    </li>
                <?php } ?>

                <?php if ($config_module_enable_accounting == 1) { ?>
                    <li class="nav-header mt-3">FINANCE</li>
                    <?php if (lookupUserPermission("module_financial") >= 1) { ?>
                        <li class="nav-item">
                            <a href="/agent/payments.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "payments.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-credit-card"></i>
                                <p>Payments</p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="/agent/vendors.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "vendors.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-building"></i>
                                <p>Vendors</p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="/agent/expenses.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "expenses.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-shopping-cart"></i>
                                <p>Expenses</p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="/agent/recurring_expenses.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "recurring_expenses.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-redo-alt"></i>
                                <p>
                                    Recurring Expenses
                                    <?php if ($num_recurring_expenses) { ?>
                                        <span class="right badge text-light" data-toggle="tooltip" title="Recurring Expenses"><?php echo $num_recurring_expenses; ?></span>
                                    <?php } ?>
                                </p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="/agent/accounts.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "accounts.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-piggy-bank"></i>
                                <p>Accounts</p>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="/agent/transfers.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "transfers.php") { echo "active"; } ?>">
                                <i class="nav-icon fas fa-exchange-alt"></i>
                                <p>Transfers</p>
                            </a>
                        </li>
                    <?php } ?>
                    <li class="nav-item">
                        <a href="/agent/trips.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "trips.php") { echo "active"; } ?>">
                            <i class="nav-icon fas fa-route"></i>
                            <p>Trips</p>
                        </a>
                    </li>
                <?php } ?>

                <?php if (lookupUserPermission("module_client") >= 1) { ?>
                <li class="nav-item mt-3">
                    <a href="/agent/contacts.php" class="nav-link">
                        <i class="fas fa-users nav-icon"></i>
                        <p>Client Overview</p>
                        <i class="fas fa-angle-right nav-icon float-right"></i>
                    </a>
                </li>
                <?php } ?>

                <?php if (lookupUserPermission("module_reporting") >= 1) { ?>
                    <li class="nav-item mt-3">
                        <a href="/agent/reports/" class="nav-link">
                            <i class="fas fa-chart-line nav-icon"></i>
                            <p>Reports</p>
                            <i class="fas fa-angle-right nav-icon float-right"></i>
                        </a>
                    </li>
                <?php } ?>

                <?php
                $sql_custom_links = mysqli_query($mysqli, "SELECT * FROM custom_links WHERE custom_link_location = 1 AND custom_link_archived_at IS NULL
                    ORDER BY custom_link_order ASC, custom_link_name ASC"
                );

                while ($row = mysqli_fetch_assoc($sql_custom_links)) {
                    $custom_link_name = nullable_htmlentities($row['custom_link_name']);
                    $custom_link_uri = sanitize_url($row['custom_link_uri']);
                    $custom_link_icon = nullable_htmlentities($row['custom_link_icon']);
                    $custom_link_new_tab = intval($row['custom_link_new_tab']);
                    if ($custom_link_new_tab == 1) {
                        $target = "target='_blank' rel='noopener noreferrer'";
                    } else {
                        $target = "";
                    }

                    ?>

                <li class="nav-item">
                    <a href="<?php echo $custom_link_uri; ?>" <?php echo $target; ?> class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == basename($custom_link_uri)) { echo "active"; } ?>">
                        <i class="fas fa-<?php echo $custom_link_icon; ?> nav-icon"></i>
                        <p><?php echo $custom_link_name; ?></p>
                        <i class="fas fa-angle-right nav-icon float-right"></i>
                    </a>
                </li>

                <?php } ?>
<!-- ITFLOW_PLATFORM_ROADMAP_SIDEBAR_LINK -->
<li class="nav-header">PLATFORM</li>

<li class="nav-item">
    <a href="roadmap.php" class="nav-link <?php if (basename($_SERVER["PHP_SELF"]) == "roadmap.php") { echo "active"; } ?>">
        <i class="nav-icon fas fa-map-signs"></i>
        <p>Roadmap</p>
    </a>
</li>



            </ul>
        </nav>
        <!-- /.sidebar-menu -->

        <div class="mb-3"></div>

    </div>
    <!-- /.sidebar -->

</aside>
