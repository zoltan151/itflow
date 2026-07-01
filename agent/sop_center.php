
<?php
require_once "includes/inc_all.php";

function itflow_vops_e($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function itflow_vops_table_exists($table)
{
    global $mysqli;
    $table = mysqli_real_escape_string($mysqli, $table);
    $sql = mysqli_query($mysqli, "SHOW TABLES LIKE '$table'");
    return $sql && mysqli_num_rows($sql) > 0;
}

function itflow_vops_column_exists($table, $column)
{
    global $mysqli;
    $table = mysqli_real_escape_string($mysqli, $table);
    $column = mysqli_real_escape_string($mysqli, $column);
    $sql = mysqli_query($mysqli, "SHOW COLUMNS FROM `$table` LIKE '$column'");
    return $sql && mysqli_num_rows($sql) > 0;
}

function itflow_vops_contains($haystack, $needle)
{
    return strpos(strtolower((string)$haystack), strtolower((string)$needle)) !== false;
}

function itflow_vops_short_text($value, $length = 1200)
{
    $value = strip_tags((string)$value);
    return function_exists('mb_substr') ? mb_substr($value, 0, $length) : substr($value, 0, $length);
}

$has_docs = itflow_vops_table_exists('documents');
$has_type = $has_docs && itflow_vops_column_exists('documents', 'document_type');
$has_archived = $has_docs && itflow_vops_column_exists('documents', 'document_archived_at');
$has_updated = $has_docs && itflow_vops_column_exists('documents', 'document_updated_at');
$has_visible = $has_docs && itflow_vops_column_exists('documents', 'document_client_visible');
$has_content = $has_docs && itflow_vops_column_exists('documents', 'document_content');
$has_desc = $has_docs && itflow_vops_column_exists('documents', 'document_description');

$total = 0; $client = 0; $review = 0; $docs = [];
$type_condition = $has_type ? "document_type IN ('SOP','Client SOP','Runbook','Onboarding','Offboarding','Internal KB')" : "1=1";
$archive_condition = $has_archived ? "document_archived_at IS NULL AND" : "";

if ($has_docs) {
    $r = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM documents WHERE $archive_condition $type_condition");
    if ($r) $total = intval(mysqli_fetch_assoc($r)['count']);

    if ($has_type) {
        $r = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM documents WHERE $archive_condition document_type = 'Client SOP'");
        if ($r) $client = intval(mysqli_fetch_assoc($r)['count']);
    }

    if ($has_updated) {
        $r = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM documents WHERE $archive_condition $type_condition AND (document_updated_at IS NULL OR document_updated_at < DATE_SUB(NOW(), INTERVAL 90 DAY))");
        if ($r) $review = intval(mysqli_fetch_assoc($r)['count']);
    }

    $type_select = $has_type ? "d.document_type" : "'Document' AS document_type";
    $updated_select = $has_updated ? "d.document_updated_at" : "NULL AS document_updated_at";
    $visible_select = $has_visible ? "d.document_client_visible" : "0 AS document_client_visible";
    $content_select = $has_content ? "d.document_content" : "'' AS document_content";
    $desc_select = $has_desc ? "d.document_description" : "'' AS document_description";
    $order_by = $has_updated ? "COALESCE(d.document_updated_at, d.document_created_at) DESC" : "d.document_created_at DESC";

    $sql = mysqli_query($mysqli, "SELECT d.document_id, d.document_name, d.document_created_at, d.document_client_id, $type_select, $updated_select, $visible_select, $content_select, $desc_select, c.client_name FROM documents d LEFT JOIN clients c ON c.client_id = d.document_client_id WHERE $archive_condition $type_condition ORDER BY $order_by LIMIT 100");
    if ($sql) while ($row = mysqli_fetch_assoc($sql)) $docs[] = $row;
}

$selected = $docs[0] ?? null;
?>

<style>
.itflow-sop-card{background:#fff;border:1px solid #dee2e6;border-radius:.35rem;padding:1rem;margin-bottom:1rem}
.itflow-sop-item{padding:.75rem;border-bottom:1px solid #edf0f3}
.itflow-sop-item.active{background:#e8f2ff;border-left:4px solid #007bff}
.itflow-sop-list{background:#fff;border:1px solid #dee2e6;border-radius:.35rem;overflow:hidden}
</style>

<div class="d-flex justify-content-between align-items-center mb-3">
    <div>
        <h3 class="mb-0">SOP / Runbook Center</h3>
        <div class="text-muted">Client-specific SOPs, global runbooks, and Flexis handoff documentation</div>
    </div>
    <a href="files.php" class="btn btn-primary">New SOP</a>
</div>

<?php if (!$has_docs) { ?><div class="alert alert-warning">Documents table is not available.</div><?php } ?>

<div class="row">
    <div class="col-md-3"><div class="itflow-sop-card"><div class="text-muted">Total SOPs</div><h2><?= intval($total) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-sop-card"><div class="text-muted">Client-Specific SOPs</div><h2><?= intval($client) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-sop-card"><div class="text-muted">Needs Review</div><h2><?= intval($review) ?></h2></div></div>
    <div class="col-md-3"><div class="itflow-sop-card"><div class="text-muted">Flexis-Ready</div><h2><?= intval($client) ?></h2></div></div>
</div>

<div class="row">
    <div class="col-xl-4">
        <div class="itflow-sop-list">
            <?php if (!$docs) { ?><div class="p-4 text-center text-muted">No SOP or runbook documents yet.</div><?php } ?>
            <?php foreach ($docs as $i => $doc) { ?>
                <div class="itflow-sop-item <?= $i === 0 ? 'active' : '' ?>">
                    <strong><?= itflow_vops_e($doc['document_name'] ?? '') ?></strong><br>
                    <small class="text-muted"><?= itflow_vops_e($doc['client_name'] ?: 'Global') ?> · <?= itflow_vops_e($doc['document_type'] ?? 'Document') ?></small><br>
                    <span class="badge badge-success">Approved</span>
                    <?php if (($doc['document_type'] ?? '') === 'Client SOP') { ?><span class="badge badge-primary">Client-Specific</span><?php } ?>
                </div>
            <?php } ?>
        </div>
    </div>

    <div class="col-xl-8">
        <div class="itflow-sop-card">
            <?php if ($selected) { ?>
                <h4><?= itflow_vops_e($selected['document_name'] ?? '') ?></h4>
                <span class="badge badge-info"><?= itflow_vops_e($selected['document_type'] ?? 'Document') ?></span>
                <span class="badge badge-secondary"><?= intval($selected['document_client_visible'] ?? 0) ? 'Client Visible' : 'Internal' ?></span>
                <hr>
                <p><?= nl2br(itflow_vops_e($selected['document_description'] ?: 'No summary has been added yet.')) ?></p>
                <div class="border rounded p-3 bg-light"><?= nl2br(itflow_vops_e(itflow_vops_short_text($selected['document_content'] ?? '', 1200))) ?></div>
                <a href="document_details.php?document_id=<?= intval($selected['document_id']) ?>" class="btn btn-outline-primary mt-3">View Full SOP</a>
            <?php } else { ?>
                <h4>Select an SOP</h4>
                <p class="text-muted">Create SOP documents using document type SOP, Client SOP, or Runbook and they will appear here.</p>
            <?php } ?>
        </div>
    </div>
</div>

<?php require_once "includes/footer.php"; ?>
