<?php
require_once "includes/inc_all_admin.php";

$theme_colors_array = array (
    'lightblue',
    'blue',
    'cyan',
    'green',
    'olive',
    'teal',
    'red',
    'maroon',
    'pink',
    'purple',
    'indigo',
    'fuchsia',
    'yellow',
    'orange',
    'black',
    'navy',
    'gray'
);

$sql_company_brand = mysqli_query($mysqli, "SELECT company_name, company_logo FROM companies WHERE company_id = 1 LIMIT 1");
$row_company_brand = mysqli_fetch_assoc($sql_company_brand);
$theme_company_name_raw = $row_company_brand['company_name'] ?? $session_company_name;
$theme_company_name = nullable_htmlentities($theme_company_name_raw);
$theme_company_logo = nullable_htmlentities($row_company_brand['company_logo'] ?? '');
$theme_company_logo_exists = !empty($theme_company_logo) && file_exists("../uploads/settings/$theme_company_logo");

$brand_display = $config_sidebar_brand_display ?? 'text';
if ($brand_display == 'name') { $brand_display = 'text'; }
if ($brand_display == 'logo_name') { $brand_display = 'logo_text'; }
if (!in_array($brand_display, ['text', 'logo', 'logo_text'], true)) {
    $brand_display = 'text';
}
if (($brand_display == 'logo' || $brand_display == 'logo_text') && !$theme_company_logo_exists) {
    $brand_display = 'text';
}

$brand_text_source = $config_sidebar_brand_text_source ?? 'company';
if (!in_array($brand_text_source, ['company', 'custom'], true)) {
    $brand_text_source = 'company';
}
$brand_custom_text = nullable_htmlentities($config_sidebar_brand_custom_text ?? '');
$brand_preview_text = ($brand_text_source == 'custom' && !empty($brand_custom_text)) ? $brand_custom_text : $theme_company_name;

$brand_background_mode = $config_sidebar_brand_background_mode ?? 'none';
if (!in_array($brand_background_mode, ['none', 'preset', 'custom'], true)) {
    $brand_background_mode = 'none';
}

$brand_background_color = $config_sidebar_brand_background_color ?? '#343a40';
if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $brand_background_color)) {
    $brand_background_color = '#343a40';
}

$brand_background_opacity = intval($config_sidebar_brand_background_opacity ?? 100);
$brand_background_opacity = max(0, min(100, $brand_background_opacity));

$brand_text_color_mode = $config_sidebar_brand_text_color_mode ?? 'default';
if (!in_array($brand_text_color_mode, ['default', 'preset', 'custom'], true)) {
    $brand_text_color_mode = 'default';
}

$brand_text_color = $config_sidebar_brand_text_color ?? '#ffffff';
if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $brand_text_color)) {
    $brand_text_color = '#ffffff';
}

$brand_text_color_opacity = intval($config_sidebar_brand_text_color_opacity ?? 100);
$brand_text_color_opacity = max(0, min(100, $brand_text_color_opacity));

$brand_layout = $config_sidebar_brand_layout ?? 'logo_left';
if (!in_array($brand_layout, ['logo_left', 'logo_right', 'logo_top', 'logo_bottom'], true)) {
    $brand_layout = 'logo_left';
}

$brand_logo_size = $config_sidebar_brand_logo_size ?? 'medium';
if (!in_array($brand_logo_size, ['tiny', 'small', 'medium', 'large', 'xlarge', 'huge'], true)) {
    $brand_logo_size = 'medium';
}

$brand_text_size = $config_sidebar_brand_text_size ?? ($config_sidebar_brand_name_size ?? 'medium');
if (!in_array($brand_text_size, ['tiny', 'small', 'medium', 'large', 'xlarge', 'huge'], true)) {
    $brand_text_size = 'medium';
}

$sidebar_brand_preset_colors = [
    'lightblue' => '#3c8dbc',
    'blue' => '#007bff',
    'cyan' => '#17a2b8',
    'green' => '#28a745',
    'olive' => '#3d9970',
    'teal' => '#20c997',
    'red' => '#dc3545',
    'maroon' => '#d81b60',
    'pink' => '#e83e8c',
    'purple' => '#6f42c1',
    'indigo' => '#6610f2',
    'fuchsia' => '#f012be',
    'yellow' => '#ffc107',
    'orange' => '#fd7e14',
    'black' => '#343a40',
    'navy' => '#001f3f',
    'gray' => '#6c757d'
];
$brand_background_preset = 'black';
foreach ($sidebar_brand_preset_colors as $preset_name => $preset_hex) {
    if (strtolower($preset_hex) === strtolower($brand_background_color)) {
        $brand_background_preset = $preset_name;
        break;
    }
}

$brand_text_color_preset = 'gray';
foreach ($sidebar_brand_preset_colors as $preset_name => $preset_hex) {
    if (strtolower($preset_hex) === strtolower($brand_text_color)) {
        $brand_text_color_preset = $preset_name;
        break;
    }
}

?>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-paint-brush mr-2"></i>Theme</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <label>Select a Theme</label>
            <div class="form-row">

                <?php foreach ($theme_colors_array as $theme_color) { ?>
                    <div class="col-4 text-center mb-3">
                        <div class="form-group">
                            <div class="custom-control custom-radio">
                                <input class="custom-control-input" type="radio" onchange="this.form.submit()" id="customRadio<?php echo $theme_color; ?>" name="edit_theme_settings" value="<?php echo $theme_color; ?>" <?php if ($config_theme == $theme_color) { echo "checked"; } ?>>
                                <label for="customRadio<?php echo $theme_color; ?>" class="custom-control-label">
                                    <i class="fa fa-fw fa-6x fa-circle text-<?php echo $theme_color; ?>"></i>
                                    <br>
                                    <?php echo $theme_color; ?>
                                </label>
                            </div>
                        </div>
                    </div>
                <?php } ?>

            </div>

        </form>
    </div>
</div>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-id-card mr-2"></i>Sidebar Branding</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <div class="form-row">
                <div class="form-group col-md-4">
                    <label>Sidebar Brand Display</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fas fa-fw fa-id-badge"></i></span>
                        </div>
                        <select class="form-control select2" name="config_sidebar_brand_display" id="sidebarBrandDisplaySelect">
                            <option value="text" <?php if ($brand_display == 'text') { echo 'selected'; } ?>>Text Only</option>
                            <option value="logo" <?php if ($brand_display == 'logo') { echo 'selected'; } ?> <?php if (!$theme_company_logo_exists) { echo 'disabled'; } ?>>Logo Only<?php if (!$theme_company_logo_exists) { echo ' - upload a logo first'; } ?></option>
                            <option value="logo_text" <?php if ($brand_display == 'logo_text') { echo 'selected'; } ?> <?php if (!$theme_company_logo_exists) { echo 'disabled'; } ?>>Logo + Text<?php if (!$theme_company_logo_exists) { echo ' - upload a logo first'; } ?></option>
                        </select>
                    </div>
                    <small class="text-secondary">Company logo is managed under Administration &gt; Company Details. Use the live preview before saving.</small>
                </div>

                <div class="form-group col-md-4" id="sidebarBrandTextSourceGroup">
                    <label>Brand Text Source</label>
                    <select class="form-control" name="config_sidebar_brand_text_source" id="sidebarBrandTextSource">
                        <option value="company" <?php if ($brand_text_source == 'company') { echo 'selected'; } ?>>Company Name</option>
                        <option value="custom" <?php if ($brand_text_source == 'custom') { echo 'selected'; } ?>>Custom Text</option>
                    </select>
                </div>

                <div class="form-group col-md-4" id="sidebarBrandCustomTextGroup">
                    <label>Custom Brand Text</label>
                    <input type="text" class="form-control" name="config_sidebar_brand_custom_text" id="sidebarBrandCustomText" maxlength="200" value="<?php echo $brand_custom_text; ?>" placeholder="Example: Helpdesk Portal">
                </div>
            </div>

            <div class="form-row">
                <div class="form-group col-md-4" id="sidebarBrandArrangementGroup">
                    <label>Logo + Text Arrangement</label>
                    <select class="form-control" name="config_sidebar_brand_layout" id="sidebarBrandLayout">
                        <option value="logo_left" <?php if ($brand_layout == 'logo_left') { echo 'selected'; } ?>>Logo Left / Text Right</option>
                        <option value="logo_right" <?php if ($brand_layout == 'logo_right') { echo 'selected'; } ?>>Text Left / Logo Right</option>
                        <option value="logo_top" <?php if ($brand_layout == 'logo_top') { echo 'selected'; } ?>>Logo Above / Text Below</option>
                        <option value="logo_bottom" <?php if ($brand_layout == 'logo_bottom') { echo 'selected'; } ?>>Text Above / Logo Below</option>
                    </select>
                </div>

                <div class="form-group col-md-4" id="sidebarBrandLogoSizeGroup">
                    <label>Logo Size</label>
                    <select class="form-control" name="config_sidebar_brand_logo_size" id="sidebarBrandLogoSize">
                        <option value="tiny" <?php if ($brand_logo_size == 'tiny') { echo 'selected'; } ?>>Tiny</option>
                        <option value="small" <?php if ($brand_logo_size == 'small') { echo 'selected'; } ?>>Small</option>
                        <option value="medium" <?php if ($brand_logo_size == 'medium') { echo 'selected'; } ?>>Medium</option>
                        <option value="large" <?php if ($brand_logo_size == 'large') { echo 'selected'; } ?>>Large</option>
                        <option value="xlarge" <?php if ($brand_logo_size == 'xlarge') { echo 'selected'; } ?>>Extra Large</option>
                        <option value="huge" <?php if ($brand_logo_size == 'huge') { echo 'selected'; } ?>>Huge</option>
                    </select>
                </div>

                <div class="form-group col-md-4" id="sidebarBrandTextSizeGroup">
                    <label>Brand Text Size</label>
                    <select class="form-control" name="config_sidebar_brand_text_size" id="sidebarBrandTextSize">
                        <option value="tiny" <?php if ($brand_text_size == 'tiny') { echo 'selected'; } ?>>Tiny</option>
                        <option value="small" <?php if ($brand_text_size == 'small') { echo 'selected'; } ?>>Small</option>
                        <option value="medium" <?php if ($brand_text_size == 'medium') { echo 'selected'; } ?>>Medium</option>
                        <option value="large" <?php if ($brand_text_size == 'large') { echo 'selected'; } ?>>Large</option>
                        <option value="xlarge" <?php if ($brand_text_size == 'xlarge') { echo 'selected'; } ?>>Extra Large</option>
                        <option value="huge" <?php if ($brand_text_size == 'huge') { echo 'selected'; } ?>>Huge</option>
                    </select>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group col-md-4">
                    <label>Brand Background</label>
                    <select class="form-control" name="config_sidebar_brand_background_mode" id="sidebarBrandBackgroundMode">
                        <option value="none" <?php if ($brand_background_mode == 'none') { echo 'selected'; } ?>>No Background</option>
                        <option value="preset" <?php if ($brand_background_mode == 'preset') { echo 'selected'; } ?>>Theme Preset Color</option>
                        <option value="custom" <?php if ($brand_background_mode == 'custom') { echo 'selected'; } ?>>Custom Color</option>
                    </select>
                </div>

                <div class="form-group col-md-4" id="sidebarBrandPresetGroup">
                    <label>Preset Color</label>
                    <select class="form-control" id="sidebarBrandPresetColor">
                        <?php foreach ($theme_colors_array as $theme_color) { ?>
                            <option value="<?php echo nullable_htmlentities($theme_color); ?>" <?php if ($brand_background_preset == $theme_color) { echo 'selected'; } ?>><?php echo nullable_htmlentities(ucfirst($theme_color)); ?></option>
                        <?php } ?>
                    </select>
                    <input type="hidden" name="config_sidebar_brand_background_preset" id="sidebarBrandPresetHidden" value="<?php echo nullable_htmlentities($brand_background_color); ?>">
                </div>

                <div class="form-group col-md-4" id="sidebarBrandCustomGroup">
                    <label>Custom Color</label>
                    <div class="input-group">
                        <input type="color" class="form-control" id="sidebarBrandCustomColorPicker" value="<?php echo nullable_htmlentities($brand_background_color); ?>" style="max-width: 80px; padding: 3px;">
                        <input type="text" class="form-control" name="config_sidebar_brand_background_color" id="sidebarBrandCustomColorHex" value="<?php echo nullable_htmlentities($brand_background_color); ?>" maxlength="7" placeholder="#343a40">
                    </div>
                </div>
            </div>

            <div class="form-group" id="sidebarBrandOpacityGroup">
                <label>Background Opacity: <span id="sidebarBrandOpacityValue"><?php echo $brand_background_opacity; ?></span>%</label>
                <input type="range" class="custom-range" name="config_sidebar_brand_background_opacity" id="sidebarBrandOpacity" min="0" max="100" value="<?php echo $brand_background_opacity; ?>">
            </div>


            <div class="form-row" id="sidebarBrandTextColorControls">
                <div class="form-group col-md-4">
                    <label>Brand Text Color</label>
                    <select class="form-control" name="config_sidebar_brand_text_color_mode" id="sidebarBrandTextColorMode">
                        <option value="default" <?php if ($brand_text_color_mode == 'default') { echo 'selected'; } ?>>Default</option>
                        <option value="preset" <?php if ($brand_text_color_mode == 'preset') { echo 'selected'; } ?>>Theme Preset Color</option>
                        <option value="custom" <?php if ($brand_text_color_mode == 'custom') { echo 'selected'; } ?>>Custom Color</option>
                    </select>
                </div>

                <div class="form-group col-md-4" id="sidebarBrandTextPresetGroup">
                    <label>Text Preset Color</label>
                    <select class="form-control" id="sidebarBrandTextPresetColor">
                        <?php foreach ($theme_colors_array as $theme_color) { ?>
                            <option value="<?php echo nullable_htmlentities($theme_color); ?>" <?php if ($brand_text_color_preset == $theme_color) { echo 'selected'; } ?>><?php echo nullable_htmlentities(ucfirst($theme_color)); ?></option>
                        <?php } ?>
                    </select>
                    <input type="hidden" name="config_sidebar_brand_text_color_preset" id="sidebarBrandTextPresetHidden" value="<?php echo nullable_htmlentities($brand_text_color); ?>">
                </div>

                <div class="form-group col-md-4" id="sidebarBrandTextCustomGroup">
                    <label>Text Custom Color</label>
                    <div class="input-group">
                        <input type="color" class="form-control" id="sidebarBrandTextCustomColorPicker" value="<?php echo nullable_htmlentities($brand_text_color); ?>" style="max-width: 80px; padding: 3px;">
                        <input type="text" class="form-control" name="config_sidebar_brand_text_color" id="sidebarBrandTextCustomColorHex" value="<?php echo nullable_htmlentities($brand_text_color); ?>" maxlength="7" placeholder="#ffffff">
                    </div>
                </div>
            </div>

            <div class="form-group" id="sidebarBrandTextOpacityGroup">
                <label>Brand Text Opacity: <span id="sidebarBrandTextOpacityValue"><?php echo $brand_text_color_opacity; ?></span>%</label>
                <input type="range" class="custom-range" name="config_sidebar_brand_text_color_opacity" id="sidebarBrandTextOpacity" min="0" max="100" value="<?php echo $brand_text_color_opacity; ?>">
            </div>

            <style>
                .itflow-brand-preview-frame {
                    max-width: 260px;
                    width: 260px;
                    background-color: #343a40;
                    border: 1px solid rgba(0,0,0,.15);
                    overflow: hidden;
                }
                .itflow-brand-preview-shell {
                    width: 100%;
                    min-height: 64px;
                    overflow: hidden;
                    border-radius: 0;
                    box-sizing: border-box;
                }
            </style>
            <div class="border rounded p-3 mb-3 bg-light">
                <div class="text-bold mb-2">Live Brand Preview</div>
                <div class="itflow-brand-preview-frame">
                    <div id="sidebarBrandPreviewShell" class="itflow-brand-preview-shell d-flex align-items-center px-3 py-2">
                        <?php if ($theme_company_logo_exists) { ?>
                            <span id="sidebarBrandLogoPreviewWrap" class="d-inline-flex align-items-center justify-content-center">
                                <img id="sidebarBrandLogoPreview" src="../uploads/settings/<?php echo $theme_company_logo; ?>" alt="<?php echo $theme_company_name; ?>" style="max-height: 34px; max-width: 165px; width: auto; height: auto; object-fit: contain;">
                            </span>
                        <?php } ?>
                        <span id="sidebarBrandTextPreview" class="mb-0 text-truncate"><?php echo $brand_preview_text; ?></span>
                    </div>
                </div>
                <small class="text-secondary d-block mt-2">Preview uses the same full-width brand surface as the live sidebar. No Background means transparent over the sidebar color.</small>
            </div>

            <button type="submit" name="edit_sidebar_brand_settings" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Save Sidebar Branding</button>
        </form>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    var hasLogo = <?php echo $theme_company_logo_exists ? 'true' : 'false'; ?>;
    var companyName = <?php echo json_encode($theme_company_name_raw); ?>;
    var displaySelect = document.getElementById('sidebarBrandDisplaySelect');
    var textSource = document.getElementById('sidebarBrandTextSource');
    var customText = document.getElementById('sidebarBrandCustomText');
    var textSourceGroup = document.getElementById('sidebarBrandTextSourceGroup');
    var customTextGroup = document.getElementById('sidebarBrandCustomTextGroup');
    var modeSelect = document.getElementById('sidebarBrandBackgroundMode');
    var presetGroup = document.getElementById('sidebarBrandPresetGroup');
    var presetSelect = document.getElementById('sidebarBrandPresetColor');
    var presetHidden = document.getElementById('sidebarBrandPresetHidden');
    var customGroup = document.getElementById('sidebarBrandCustomGroup');
    var colorPicker = document.getElementById('sidebarBrandCustomColorPicker');
    var colorHex = document.getElementById('sidebarBrandCustomColorHex');
    var opacityGroup = document.getElementById('sidebarBrandOpacityGroup');
    var opacity = document.getElementById('sidebarBrandOpacity');
    var opacityValue = document.getElementById('sidebarBrandOpacityValue');
    var logoWrap = document.getElementById('sidebarBrandLogoPreviewWrap');
    var logo = document.getElementById('sidebarBrandLogoPreview');
    var brandText = document.getElementById('sidebarBrandTextPreview');
    var previewShell = document.getElementById('sidebarBrandPreviewShell');
    var arrangementGroup = document.getElementById('sidebarBrandArrangementGroup');
    var layoutSelect = document.getElementById('sidebarBrandLayout');
    var logoSizeGroup = document.getElementById('sidebarBrandLogoSizeGroup');
    var logoSizeSelect = document.getElementById('sidebarBrandLogoSize');
    var textSizeGroup = document.getElementById('sidebarBrandTextSizeGroup');
    var textSizeSelect = document.getElementById('sidebarBrandTextSize');
    var textColorMode = document.getElementById('sidebarBrandTextColorMode');
    var textPresetGroup = document.getElementById('sidebarBrandTextPresetGroup');
    var textPresetSelect = document.getElementById('sidebarBrandTextPresetColor');
    var textPresetHidden = document.getElementById('sidebarBrandTextPresetHidden');
    var textCustomGroup = document.getElementById('sidebarBrandTextCustomGroup');
    var textColorPicker = document.getElementById('sidebarBrandTextCustomColorPicker');
    var textColorHex = document.getElementById('sidebarBrandTextCustomColorHex');
    var textOpacityGroup = document.getElementById('sidebarBrandTextOpacityGroup');
    var textOpacity = document.getElementById('sidebarBrandTextOpacity');
    var textOpacityValue = document.getElementById('sidebarBrandTextOpacityValue');

    var presetColors = {
        lightblue: '#3c8dbc', blue: '#007bff', cyan: '#17a2b8', green: '#28a745', olive: '#3d9970', teal: '#20c997',
        red: '#dc3545', maroon: '#d81b60', pink: '#e83e8c', purple: '#6f42c1', indigo: '#6610f2', fuchsia: '#f012be',
        yellow: '#ffc107', orange: '#fd7e14', black: '#343a40', navy: '#001f3f', gray: '#6c757d'
    };
    var logoSizes = {
        tiny: {height: '18px', width: '90px'}, small: {height: '24px', width: '120px'}, medium: {height: '34px', width: '165px'},
        large: {height: '44px', width: '195px'}, xlarge: {height: '56px', width: '220px'}, huge: {height: '68px', width: '235px'}
    };
    var textSizes = {tiny: '0.8rem', small: '1rem', medium: '1.25rem', large: '1.5rem', xlarge: '1.75rem', huge: '2rem'};

    function normalizeDisplay(value) {
        if (value === 'name') { return 'text'; }
        if (value === 'logo_name') { return 'logo_text'; }
        return ['text', 'logo', 'logo_text'].indexOf(value) >= 0 ? value : 'text';
    }

    function hexToRgba(hex, alphaPercent) {
        var clean = (hex || '#343a40').replace('#', '');
        if (!/^[0-9A-Fa-f]{6}$/.test(clean)) { clean = '343a40'; }
        var r = parseInt(clean.substring(0, 2), 16);
        var g = parseInt(clean.substring(2, 4), 16);
        var b = parseInt(clean.substring(4, 6), 16);
        var a = Math.max(0, Math.min(100, parseInt(alphaPercent || 100, 10))) / 100;
        return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
    }

    function selectedBackground(mode, preset, custom, alpha) {
        if (mode === 'preset') { return hexToRgba(presetColors[preset] || '#343a40', alpha); }
        if (mode === 'custom') { return hexToRgba(custom, alpha); }
        return 'transparent';
    }


    function selectedTextColor(mode, preset, custom, alpha) {
        if (mode === 'preset') { return hexToRgba(presetColors[preset] || '#ffffff', alpha); }
        if (mode === 'custom') { return hexToRgba(custom, alpha); }
        return '#ffffff';
    }

    function updatePreview() {
        var display = normalizeDisplay(displaySelect ? displaySelect.value : 'text');
        var usesLogo = hasLogo && (display === 'logo' || display === 'logo_text');
        var usesText = (display === 'text' || display === 'logo_text' || !hasLogo);
        var mode = modeSelect ? modeSelect.value : 'none';
        if (['none', 'preset', 'custom'].indexOf(mode) < 0) { mode = 'none'; }
        var preset = presetSelect ? presetSelect.value : 'black';
        var custom = colorHex ? colorHex.value : '#343a40';
        var alpha = opacity ? opacity.value : 100;
        var layout = layoutSelect ? layoutSelect.value : 'logo_left';
        var logoSize = logoSizeSelect ? logoSizeSelect.value : 'medium';
        var textSize = textSizeSelect ? textSizeSelect.value : 'medium';
        var txtMode = textColorMode ? textColorMode.value : 'default';
        if (['default', 'preset', 'custom'].indexOf(txtMode) < 0) { txtMode = 'default'; }
        var txtPreset = textPresetSelect ? textPresetSelect.value : 'gray';
        var txtCustom = textColorHex ? textColorHex.value : '#ffffff';
        var txtAlpha = textOpacity ? textOpacity.value : 100;
        var source = textSource ? textSource.value : 'company';
        var finalText = source === 'custom' && customText && customText.value.trim() !== '' ? customText.value.trim() : companyName;

        if (opacityValue) { opacityValue.textContent = alpha; }
        if (textOpacityValue) { textOpacityValue.textContent = txtAlpha; }
        if (brandText) { brandText.textContent = finalText; }
        if (presetHidden) { presetHidden.value = presetColors[preset] || '#343a40'; }
        if (textPresetHidden) { textPresetHidden.value = presetColors[txtPreset] || '#ffffff'; }

        if (logoWrap) { logoWrap.style.display = usesLogo ? 'inline-flex' : 'none'; }
        if (brandText) { brandText.style.display = usesText ? '' : 'none'; }

        if (textSourceGroup) { textSourceGroup.style.display = usesText ? '' : 'none'; }
        if (customTextGroup) { customTextGroup.style.display = usesText && source === 'custom' ? '' : 'none'; }
        if (arrangementGroup) { arrangementGroup.style.display = display === 'logo_text' && hasLogo ? '' : 'none'; }
        if (logoSizeGroup) { logoSizeGroup.style.display = usesLogo ? '' : 'none'; }
        if (textSizeGroup) { textSizeGroup.style.display = usesText ? '' : 'none'; }
        if (textColorMode) { textColorMode.closest('.form-row').style.display = usesText ? '' : 'none'; }
        if (textPresetGroup) { textPresetGroup.style.display = usesText && txtMode === 'preset' ? '' : 'none'; }
        if (textCustomGroup) { textCustomGroup.style.display = usesText && txtMode === 'custom' ? '' : 'none'; }
        if (textOpacityGroup) { textOpacityGroup.style.display = usesText && txtMode !== 'default' ? '' : 'none'; }
        if (presetGroup) { presetGroup.style.display = mode === 'preset' ? '' : 'none'; }
        if (customGroup) { customGroup.style.display = mode === 'custom' ? '' : 'none'; }
        if (opacityGroup) { opacityGroup.style.display = mode === 'none' ? 'none' : ''; }

        if (previewShell) {
            previewShell.style.setProperty('background-color', selectedBackground(mode, preset, custom, alpha), 'important');
            previewShell.style.borderRadius = '0';
            previewShell.style.gap = '.35rem';
            previewShell.style.textAlign = 'center';
            previewShell.style.justifyContent = 'center';
            previewShell.style.flexDirection = (display === 'logo_text' && (layout === 'logo_top' || layout === 'logo_bottom')) ? 'column' : 'row';
            previewShell.style.minHeight = (display === 'logo_text' && (layout === 'logo_top' || layout === 'logo_bottom')) ? ((logoSize === 'xlarge' || logoSize === 'huge') ? '120px' : '96px') : ((display === 'logo' && (logoSize === 'xlarge' || logoSize === 'huge')) ? '88px' : '64px');
        }
        if (logoWrap) { logoWrap.style.order = (layout === 'logo_right' || layout === 'logo_bottom') ? '2' : '1'; }
        if (brandText) {
            brandText.style.order = (layout === 'logo_right' || layout === 'logo_bottom') ? '1' : '2';
            brandText.style.fontSize = textSizes[textSize] || textSizes.medium;
            brandText.style.lineHeight = '1.1';
            brandText.style.color = selectedTextColor(txtMode, txtPreset, txtCustom, txtAlpha);
        }
        if (logo && logoSizes[logoSize]) {
            logo.style.maxHeight = logoSizes[logoSize].height;
            logo.style.maxWidth = logoSizes[logoSize].width;
        }
    }

    function syncPickerFromHex() {
        if (colorHex && colorPicker && /^#[0-9A-Fa-f]{6}$/.test(colorHex.value)) { colorPicker.value = colorHex.value; }
        updatePreview();
    }

    function syncHexFromPicker() {
        if (colorHex && colorPicker) { colorHex.value = colorPicker.value; }
        updatePreview();
    }

    [displaySelect, textSource, customText, modeSelect, presetSelect, opacity, layoutSelect, logoSizeSelect, textSizeSelect].forEach(function (el) {
        if (el) { el.addEventListener('change', updatePreview); el.addEventListener('input', updatePreview); }
    });
    function syncTextPickerFromHex() {
        if (textColorHex && textColorPicker && /^#[0-9A-Fa-f]{6}$/.test(textColorHex.value)) { textColorPicker.value = textColorHex.value; }
        updatePreview();
    }

    function syncTextHexFromPicker() {
        if (textColorHex && textColorPicker) { textColorHex.value = textColorPicker.value; }
        updatePreview();
    }

    if (colorHex) { colorHex.addEventListener('input', syncPickerFromHex); colorHex.addEventListener('change', syncPickerFromHex); }
    if (colorPicker) { colorPicker.addEventListener('input', syncHexFromPicker); colorPicker.addEventListener('change', syncHexFromPicker); }
    [textColorMode, textPresetSelect, textOpacity].forEach(function (el) {
        if (el) { el.addEventListener('change', updatePreview); el.addEventListener('input', updatePreview); }
    });
    if (textColorHex) { textColorHex.addEventListener('input', syncTextPickerFromHex); textColorHex.addEventListener('change', syncTextPickerFromHex); }
    if (textColorPicker) { textColorPicker.addEventListener('input', syncTextHexFromPicker); textColorPicker.addEventListener('change', syncTextHexFromPicker); }
    if (window.jQuery && displaySelect) { window.jQuery(displaySelect).on('change select2:select', updatePreview); }

    updatePreview();
});
</script>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-image mr-2"></i>Favicon</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" enctype="multipart/form-data" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

            <img class="mb-3" src="<?php if(file_exists("../uploads/favicon.ico")) { echo "../uploads/favicon.ico"; } else { echo "../favicon.ico"; } ?>">

            <div class="form-group">
                <input type="file" class="form-control-file" name="file" accept=".ico">
            </div>

            <hr>

            <button type="submit" name="edit_favicon_settings" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Upload Icon</button>
            <?php if(file_exists("../uploads/favicon.ico")) { ?>
            <a href="post.php?reset_favicon&csrf_token=<?= $_SESSION['csrf_token'] ?>" class="btn btn-outline-danger"><i class="fas fa-redo-alt mr-2"></i>Reset Favicon</a>
            <?php } ?>
        </form>
    </div>
</div>

<?php
require_once "../includes/footer.php";
