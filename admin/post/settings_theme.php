<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_theme_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $theme = preg_replace("/[^0-9a-zA-Z-]/", "", sanitizeInput($_POST['edit_theme_settings']));

    mysqli_query($mysqli,"UPDATE settings SET config_theme = '$theme' WHERE company_id = 1");

    logAction("Settings", "Edit", "$session_name edited theme settings");

    flash_alert("Changed theme to <strong>$theme</strong>");

    redirect();

}

if (isset($_POST['edit_sidebar_brand_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $sidebar_brand_display = sanitizeInput($_POST['config_sidebar_brand_display'] ?? 'name');
    if ($sidebar_brand_display == 'name') { $sidebar_brand_display = 'text'; }
    if ($sidebar_brand_display == 'logo_name') { $sidebar_brand_display = 'logo_text'; }
    if (!in_array($sidebar_brand_display, ['text', 'logo', 'logo_text'], true)) {
        $sidebar_brand_display = 'text';
    }

    $sidebar_brand_background_mode = sanitizeInput($_POST['config_sidebar_brand_background_mode'] ?? 'none');
    if (!in_array($sidebar_brand_background_mode, ['none', 'preset', 'custom'], true)) {
        $sidebar_brand_background_mode = 'none';
    }

    $sidebar_brand_background_color = $sidebar_brand_background_mode === 'preset'
        ? sanitizeInput($_POST['config_sidebar_brand_background_preset'] ?? '#343a40')
        : sanitizeInput($_POST['config_sidebar_brand_background_color'] ?? '#343a40');

    if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $sidebar_brand_background_color)) {
        $sidebar_brand_background_color = '#343a40';
    }

    $sidebar_brand_background_opacity = max(0, min(100, intval($_POST['config_sidebar_brand_background_opacity'] ?? 100)));


    $sidebar_brand_text_color_mode = sanitizeInput($_POST['config_sidebar_brand_text_color_mode'] ?? 'default');
    if (!in_array($sidebar_brand_text_color_mode, ['default', 'preset', 'custom'], true)) {
        $sidebar_brand_text_color_mode = 'default';
    }

    $sidebar_brand_text_color = $sidebar_brand_text_color_mode === 'preset'
        ? sanitizeInput($_POST['config_sidebar_brand_text_color_preset'] ?? '#ffffff')
        : sanitizeInput($_POST['config_sidebar_brand_text_color'] ?? '#ffffff');

    if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $sidebar_brand_text_color)) {
        $sidebar_brand_text_color = '#ffffff';
    }

    $sidebar_brand_text_color_opacity = max(0, min(100, intval($_POST['config_sidebar_brand_text_color_opacity'] ?? 100)));

    $sidebar_brand_layout = sanitizeInput($_POST['config_sidebar_brand_layout'] ?? 'logo_left');
    if (!in_array($sidebar_brand_layout, ['logo_left', 'logo_right', 'logo_top', 'logo_bottom'], true)) {
        $sidebar_brand_layout = 'logo_left';
    }

    $sidebar_brand_logo_size = sanitizeInput($_POST['config_sidebar_brand_logo_size'] ?? 'medium');
    if (!in_array($sidebar_brand_logo_size, ['tiny', 'small', 'medium', 'large', 'xlarge', 'huge'], true)) {
        $sidebar_brand_logo_size = 'medium';
    }

    $sidebar_brand_text_size = sanitizeInput($_POST['config_sidebar_brand_text_size'] ?? ($_POST['config_sidebar_brand_name_size'] ?? 'medium'));
    if (!in_array($sidebar_brand_text_size, ['tiny', 'small', 'medium', 'large', 'xlarge', 'huge'], true)) {
        $sidebar_brand_text_size = 'medium';
    }

    $sidebar_brand_text_source = sanitizeInput($_POST['config_sidebar_brand_text_source'] ?? 'company');
    if (!in_array($sidebar_brand_text_source, ['company', 'custom'], true)) {
        $sidebar_brand_text_source = 'company';
    }

    $sidebar_brand_custom_text = sanitizeInput($_POST['config_sidebar_brand_custom_text'] ?? '');
    $sidebar_brand_custom_text = substr($sidebar_brand_custom_text, 0, 200);
    $sidebar_brand_custom_text_sql = mysqli_real_escape_string($mysqli, $sidebar_brand_custom_text);

    mysqli_query($mysqli,"UPDATE settings SET
        config_sidebar_brand_display = '$sidebar_brand_display',
        config_sidebar_brand_background_mode = '$sidebar_brand_background_mode',
        config_sidebar_brand_background_color = '$sidebar_brand_background_color',
        config_sidebar_brand_background_opacity = $sidebar_brand_background_opacity,
        config_sidebar_brand_text_color_mode = '$sidebar_brand_text_color_mode',
        config_sidebar_brand_text_color = '$sidebar_brand_text_color',
        config_sidebar_brand_text_color_opacity = $sidebar_brand_text_color_opacity,
        config_sidebar_brand_layout = '$sidebar_brand_layout',
        config_sidebar_brand_logo_size = '$sidebar_brand_logo_size',
        config_sidebar_brand_name_size = '$sidebar_brand_text_size',
        config_sidebar_brand_text_size = '$sidebar_brand_text_size',
        config_sidebar_brand_text_source = '$sidebar_brand_text_source',
        config_sidebar_brand_custom_text = '$sidebar_brand_custom_text_sql'
        WHERE company_id = 1");

    logAction("Settings", "Edit", "$session_name edited sidebar brand display settings");

    flash_alert("Sidebar branding updated");

    redirect();

}

if (isset($_POST['edit_favicon_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    // Check to see if a file is attached
    if (isset($_FILES['file']['tmp_name'])) {
        if ($new_file_name = checkFileUpload($_FILES['file'], array('ico'))) {
            $file_tmp_path = $_FILES['file']['tmp_name'];

            // Delete old file
            if(file_exists("../uploads/favicon.ico")) {
                unlink("../uploads/favicon.ico");
            }

            // directory in which the uploaded file will be moved
            $upload_file_dir = "../uploads/";
            //Force File Name
            $new_file_name = "favicon.ico";
            $dest_path = $upload_file_dir . $new_file_name;

            move_uploaded_file($file_tmp_path, $dest_path);
        }
    }

    logAction("Settings", "Edit", "$session_name changed the favicon");

    flash_alert("Favicon Updated");

    redirect();

}

if (isset($_GET['reset_favicon'])) {

    validateCSRFToken($_GET['csrf_token']);

    if (file_exists("../uploads/favicon.ico")) {
        unlink("../uploads/favicon.ico");
    }

    logAction("Settings", "Edit", "$session_name reset Favicon");

    flash_alert("Favicon reset", 'error');

    redirect();

}
