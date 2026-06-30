<!-- Navbar -->
<nav class="main-header navbar navbar-expand navbar-<?php if (isset($_GET['client_id'])) { echo "gray"; } else { echo nullable_htmlentities($config_theme); } ?> navbar-dark">

    <!-- Left navbar links -->
    <ul class="navbar-nav">
        <li class="nav-item">
            <a class="nav-link" data-widget="pushmenu" data-enable-remember="TRUE" href="#"><i class="fas fa-bars"></i></a>
        </li>
    </ul>

    <!-- Center navbar links -->
    <ul class="navbar-nav ml-auto">

        <!-- SEARCH FORM -->
<!-- ITFLOW_GLOBAL_QUICK_ADD_MENU -->
<style>
/* ITFLOW_GLOBAL_QUICK_ADD_MENU_POLISHED */
#itflowGlobalQuickAdd {
    display: flex;
    align-items: center;
}

/* ITFLOW_GLOBAL_QUICK_ADD_SEARCH_SPACING */
/* Give the global action a little breathing room before Search everywhere. */
#itflowGlobalQuickAdd {
    margin-right: 1.5rem !important;
}

/* ITFLOW_GLOBAL_SEARCH_LEFT_SPACING */
/* Keep Search everywhere visually separated from Quick Add. */
#itflowGlobalQuickAdd + form.form-inline {
    margin-left: 0.35rem;
}

#itflowGlobalQuickAddDropdown {
    height: 31px;
    line-height: 1.2;
    display: inline-flex;
    align-items: center;
    border-radius: 0.2rem;
    box-shadow: none;
}

/* ITFLOW_GLOBAL_QUICK_ADD_BUTTON_POP */
/* Make the global creation action obvious against the dark navbar. */
#itflowGlobalQuickAddDropdown.btn-success {
    background-color: #28a745;
    border-color: #34ce57;
    color: #fff !important;
    font-weight: 700;
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.18);
}

#itflowGlobalQuickAddDropdown.btn-success:hover,
#itflowGlobalQuickAddDropdown.btn-success:focus {
    background-color: #218838;
    border-color: #34ce57;
    color: #fff !important;
}

#itflowGlobalQuickAddDropdown.btn-success i {
    color: #fff !important;
}

#itflowGlobalQuickAdd .dropdown-menu {
    min-width: 14rem;
}

#itflowGlobalQuickAdd .dropdown-header {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.03em;
    text-transform: uppercase;
}

/* ITFLOW_QUICK_ADD_ICON_CONTENT_STYLE */
/* Treat the plus as an icon with real spacing, not cramped text. */
.itflow-quick-add-content {
    display: inline-flex;
    align-items: center;
    gap: 0.55rem;
    font-weight: 700;
}

.itflow-quick-add-plus-icon {
    font-size: 0.95rem;
    line-height: 1;
    font-weight: 900;
    -webkit-text-stroke: 0.45px currentColor;
    transform: translateY(-0.02em);
}

.itflow-quick-add-label {
    line-height: 1;
}

/* ITFLOW_QUICK_ADD_HEADER_STYLE */
/* Make QUICK ADD read like a title/header, not a clickable menu option. */
.itflow-quick-add-header {
    margin: 0 0 0.35rem 0;
    padding: 0.45rem 0.9rem;
    background: #f1f3f5;
    color: #6c757d;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    border-bottom: 1px solid #dee2e6;
    cursor: default;
    pointer-events: none;
    user-select: none;
}
</style>

<li class="nav-item dropdown" id="itflowGlobalQuickAdd">
    <a class="nav-link btn btn-success btn-sm px-3 py-1 dropdown-toggle" href="#" id="itflowGlobalQuickAddDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" title="Quick Add">
        <span class="itflow-quick-add-content" data-itflow-marker="ITFLOW_QUICK_ADD_ICON_CONTENT"><i class="fas fa-plus itflow-quick-add-plus-icon" aria-hidden="true"></i><span class="itflow-quick-add-label d-none d-md-inline">New</span></span>
    </a>
    <div class="dropdown-menu dropdown-menu-left shadow" aria-labelledby="itflowGlobalQuickAddDropdown">
        <h6 class="dropdown-header itflow-quick-add-header" data-itflow-marker="ITFLOW_QUICK_ADD_HEADER">QUICK ADD</h6>

        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/ticket/ticket_add_v2.php" data-modal-size="lg">
            <i class="fas fa-life-ring fa-fw mr-2"></i>New Ticket
        </a>

        <div class="dropdown-divider"></div>

        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/client/client_add.php" data-modal-size="lg">
            <i class="fas fa-building fa-fw mr-2"></i>New Client Organization
        </a>
        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/contact/contact_add.php">
            <i class="fas fa-user fa-fw mr-2"></i>New Contact
        </a>

        <div class="dropdown-divider"></div>

        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/asset/asset_add.php">
            <i class="fas fa-desktop fa-fw mr-2"></i>New Asset
        </a>
        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/project/project_add.php" data-modal-size="lg">
            <i class="fas fa-project-diagram fa-fw mr-2"></i>New Project
        </a>
        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/vendor/vendor_add.php" data-modal-size="lg">
            <i class="fas fa-handshake fa-fw mr-2"></i>New Vendor
        </a>
        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/credential/credential_add.php" data-modal-size="lg">
            <i class="fas fa-key fa-fw mr-2"></i>New Credential
        </a>
        <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/document/document_add_global.php" data-modal-size="lg">
            <i class="fas fa-file-alt fa-fw mr-2"></i>New Document
        </a>
    </div>
</li>
<!-- /ITFLOW_GLOBAL_QUICK_ADD_MENU -->
<!-- ITFLOW_PLATFORM_ROADMAP_PHASE3B -->
<li class="nav-item mr-2">
        <i class="fas fa-map-signs mr-1"></i><span class="d-none d-md-inline">Roadmap</span>
    </a>
</li>



        <form class="form-inline" action="/agent/global_search.php">
            <div class="input-group input-group-sm">
                <input class="form-control form-control-navbar" type="search" placeholder="Search everywhere" name="query"
                    value="<?php if (isset($_GET['query'])) { echo nullable_htmlentities($_GET['query']); } ?>">
                <div class="input-group-append">
                    <button class="btn btn-navbar" type="submit">
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </div>
        </form>
    </ul>

    <!-- Right navbar links -->
    <ul class="navbar-nav ml-auto">

        <!--Custom Nav Link -->
        <?php
        $sql_custom_links = mysqli_query($mysqli, "SELECT * FROM custom_links WHERE custom_link_location = 2 AND custom_link_archived_at IS NULL
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

        <li class="nav-item" title="<?php echo $custom_link_name; ?>">
            <a href="<?php echo $custom_link_uri; ?>" <?php echo $target; ?> class="nav-link">
                <i class="fas fa-<?php echo $custom_link_icon; ?> nav-icon"></i>
            </a>
        </li>

        <?php } ?>
        <!-- End Custom Nav Links -->

        <!-- New Notifications Dropdown -->
        <?php
        $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT COUNT('notification_id') AS num FROM notifications WHERE notification_user_id = $session_user_id AND notification_dismissed_at IS NULL"));
        $num_notifications = $row['num'];

        ?>

        <li class="nav-item">
            <a class="nav-link ajax-modal" href="#" data-modal-url="/modals/notifications.php">
                <i class="fas fa-bell"></i>
                <?php if ($num_notifications) { ?>
                <span class="badge badge-light badge-pill navbar-badge position-absolute" style="top: 1px; right: 3px;">
                    <?php echo $num_notifications; ?>
                </span>
                <?php } ?>
            </a>
        </li>

        <li class="nav-item dropdown user-menu">
            <a href="#" class="nav-link" data-toggle="dropdown">
                <?php if (empty($session_avatar)) { ?>
                <i class="fas fa-user-circle mr-1"></i>
                <?php }else{ ?>
                <img src="<?php echo "/uploads/users/$session_user_id/$session_avatar"; ?>"
                    class="user-image img-circle">
                <?php } ?>
                <span
                    class="d-none d-md-inline dropdown-toggle"><?php echo stripslashes(nullable_htmlentities($session_name)); ?></span>
            </a>
            <ul class="dropdown-menu dropdown-menu-lg dropdown-menu-right">
                <!-- User image -->
                <li class="user-header bg-gray-dark">
                    <?php if (empty($session_avatar)) { ?>
                    <i class="fas fa-user-circle fa-6x"></i>
                    <?php }else{ ?>

                    <img src="<?php echo "/uploads/users/$session_user_id/$session_avatar"; ?>" class="img-circle">
                    <?php } ?>
                    <p>
                        <?php echo stripslashes(nullable_htmlentities($session_name)); ?>
                        <small><?php echo nullable_htmlentities($session_user_role_display); ?></small>
                    </p>
                </li>
                <!-- Menu Footer-->
                <li class="user-footer">
                    <?php if ($session_is_admin) { ?>
                        <a href="/admin" class="btn btn-default btn-block btn-flat mb-2"><i class="fas fa-user-shield mr-2"></i>Administration</a>
                    <?php } ?>
                    <a href="/agent/user/user_details.php" class="btn btn-default btn-flat"><i class="fas fa-user-cog mr-2"></i>Account</a>
                    <a href="/agent/post.php?logout" class="btn btn-default btn-flat float-right"><i class="fas fa-sign-out-alt mr-2"></i>Logout</a>
                </li>
            </ul>
        </li>

    </ul>
</nav>
<!-- /.navbar -->

