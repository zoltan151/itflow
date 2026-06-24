<?php
/*
 * ITFlow 3rd Party Integrations landing page.
 * First-pass route for Administration -> Settings -> 3rd Party Integrations.
 */

$root = __DIR__;
foreach ([
    "$root/inc_all_settings.php",
    "$root/inc_all_admin.php",
    "$root/inc_all.php",
    "$root/config.php"
] as $include_file) {
    if (file_exists($include_file)) {
        require_once $include_file;
        break;
    }
}

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}
?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>3rd Party Integrations</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 24px; color: #222; background: #f7f7f7; }
        .wrap { max-width: 1200px; margin: 0 auto; }
        .card { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 18px; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
        h1, h2 { margin-top: 0; }
        a.button { display: inline-block; padding: 10px 14px; border-radius: 5px; border: 1px solid #1f6feb; background: #1f6feb; color: #fff; text-decoration: none; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border-bottom: 1px solid #e5e5e5; padding: 10px; text-align: left; }
        th { background: #f2f4f7; }
        .small { color: #666; font-size: 12px; }
        .ok { color: #067647; font-weight: bold; }
    </style>
</head>
<body>
<div class="wrap">
    <h1>Administration → Settings → 3rd Party Integrations</h1>
    <div class="card">
        <h2>Available Integrations</h2>
        <table>
            <thead>
            <tr>
                <th>Category</th>
                <th>Provider</th>
                <th>Status</th>
                <th>Description</th>
                <th>Open</th>
            </tr>
            </thead>
            <tbody>
            <tr>
                <td>RMM</td>
                <td>TacticalRMM</td>
                <td><span class="ok">Configured</span></td>
                <td>Sync TacticalRMM clients and agents/devices into ITFlow organizations and assets.</td>
                <td><a class="button" href="/admin_settings_rmm.php">Open RMM Settings</a></td>
            </tr>
            </tbody>
        </table>
        <p class="small">Future providers can be added here later, such as NinjaOne, Syncro, N-able, ConnectWise RMM, and others.</p>
    </div>
</div>
</body>
</html>
