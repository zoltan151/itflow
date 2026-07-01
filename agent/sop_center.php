<?php
require_once "includes/inc_all_agent.php";

function itflow_vops_e($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

$doc_types = "'SOP','Client SOP','Runbook','Onboarding','Offboarding','Internal KB'";
$total_sops = 0;
$client_sops = 0;
$needs_review = 0;
$flexis_ready = 0;

$count_sql = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM documents WHERE document_archived_at IS NULL AND document_type IN ($doc_types)");
if ($count_sql) $total_sops = intval(mysqli_fetch_assoc($count_sql)['count']);

$client_sql = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM documents WHERE document_archived_at IS NULL AND document_type = 'Client SOP'");
if ($client_sql) $client_sops = intval(mysqli_fetch_assoc($client_sql)['count']);

$review_sql = mysqli_query($mysqli, "SELECT COUNT(*) AS count FROM documents WHERE document_archived_at IS NULL AND document_type IN ($doc_types) AND (document_updated_at IS NULL OR document_updated_at < DATE_SUB(NOW(), INTERVAL 90 DAY))");
if ($review_sql) $needs_review = intval(mysqli_fetch_assoc($review_sql)['count']);

$flexis_ready = $client_sops;

$docs = [];
$sql = mysqli_query($mysqli, "
    SELECT d.*, c.client_name
    FROM documents d
    LEFT JOIN clients c ON c.client_id = d.document_client_id
    WHERE d.document_archived_at IS NULL
    AND d.document_type IN ($doc_types)
    ORDER BY COALESCE(d.document_updated_at, d.document_created_at) DESC
    LIMIT 100
");
if ($sql) {
    while ($row = mysqli_fetch_assoc($sql)) {
        $docs[] = $row;
    }
}

$selected = $docs[0] ?? null;
?>

<style>
.itflow-sop-metric{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px}
.itflow-sop-list{background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden}
.itflow-sop-item{padding:14px;border-bottom:1px solid #edf0f3}
.itflow-sop-item.active{background:#e8f2ff;border-left:4px solid #0d6efd}
.itflow-sop-detail,.itflow-right-card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px;margin-bottom:16px}
</style>

<div class="itflow-sop-page">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h3 class="mb-0">SOP / Runbook Center <small class="text-muted"><i class="far fa-question-circle"></i></small></h3>
            <div class="text-muted">Create and organize client-specific SOPs, global runbooks, and Flexis handoff documentation</div>
        </div>
        <a href="files.php" class="btn btn-primary"><i class="fas fa-plus mr-1"></i> New SOP</a>
    </div>

    <div class="row mb-4">
        <div class="col-md-3"><div class="itflow-sop-metric"><small class="text-muted">Total SOPs</small><h2><?= intval($total_sops) ?></h2></div></div>
        <div class="col-md-3"><div class="itflow-sop-metric"><small class="text-muted">Client-Specific SOPs</small><h2><?= intval($client_sops) ?></h2></div></div>
        <div class="col-md-3"><div class="itflow-sop-metric"><small class="text-muted">Needs Review</small><h2><?= intval($needs_review) ?></h2></div></div>
        <div class="col-md-3"><div class="itflow-sop-metric"><small class="text-muted">Flexis-Ready</small><h2><?= intval($flexis_ready) ?></h2></div></div>
    </div>

    <div class="mb-3">
        <button class="btn btn-sm btn-primary">All SOPs</button>
        <button class="btn btn-sm btn-outline-secondary">Client SOPs</button>
        <button class="btn btn-sm btn-outline-secondary">Global SOPs</button>
        <button class="btn btn-sm btn-outline-secondary">Flexis Handoff</button>
        <button class="btn btn-sm btn-outline-secondary">Templates</button>
    </div>

    <div class="row">
        <div class="col-xl-4">
            <div class="itflow-sop-list">
                <?php if (empty($docs)) { ?>
                    <div class="p-4 text-center text-muted">No SOP or runbook documents yet.</div>
                <?php } ?>
                <?php foreach ($docs as $i => $doc) { ?>
                    <div class="itflow-sop-item <?= $i === 0 ? 'active' : '' ?>">
                        <strong><?= itflow_vops_e($doc['document_name']) ?></strong><br>
                        <small class="text-muted"><?= itflow_vops_e($doc['client_name'] ?: 'Global') ?> · <?= itflow_vops_e($doc['document_type']) ?></small><br>
                        <span class="badge badge-success">Approved</span>
                        <?php if ($doc['document_type'] === 'Client SOP') { ?><span class="badge badge-primary">Client-Specific</span><?php } ?>
                    </div>
                <?php } ?>
            </div>
        </div>

        <div class="col-xl-5">
            <div class="itflow-sop-detail">
                <?php if ($selected) { ?>
                    <h4><?= itflow_vops_e($selected['document_name']) ?></h4>
                    <div class="mb-3">
                        <span class="badge badge-success">Approved</span>
                        <span class="badge badge-info"><?= itflow_vops_e($selected['document_type']) ?></span>
                        <span class="badge badge-secondary"><?= intval($selected['document_client_visible'] ?? 0) ? 'Client Visible' : 'Internal' ?></span>
                    </div>

                    <div class="row mb-3">
                        <div class="col-md-4"><small class="text-muted">Client</small><br><?= itflow_vops_e($selected['client_name'] ?: 'Global') ?></div>
                        <div class="col-md-4"><small class="text-muted">Updated</small><br><?= itflow_vops_e($selected['document_updated_at'] ?: $selected['document_created_at']) ?></div>
                        <div class="col-md-4"><small class="text-muted">Linked Items</small><br>Future related items</div>
                    </div>

                    <h5>Summary</h5>
                    <p><?= nl2br(itflow_vops_e($selected['document_description'] ?: 'No summary has been added yet.')) ?></p>

                    <h5>SOP Preview</h5>
                    <div class="border rounded p-3 bg-light">
                        <?= nl2br(itflow_vops_e(mb_substr(strip_tags($selected['document_content'] ?? ''), 0, 1200))) ?>
                    </div>

                    <a href="document_details.php?document_id=<?= intval($selected['document_id']) ?>" class="btn btn-outline-primary mt-3">View Full SOP</a>
                <?php } else { ?>
                    <h4>Select an SOP</h4>
                    <p class="text-muted">Create SOP documents using document type SOP, Client SOP, or Runbook and they will appear here.</p>
                <?php } ?>
            </div>
        </div>

        <div class="col-xl-3">
            <div class="itflow-right-card">
                <h5>Related Documentation</h5>
                <div class="text-muted">Related docs and diagrams will appear here as relationship mapping is added.</div>
            </div>

            <div class="itflow-right-card">
                <h5>Linked Assets / Credentials / Contacts</h5>
                <div class="text-muted">Linked ITFlow records will appear here.</div>
            </div>

            <div class="itflow-right-card">
                <h5><i class="fas fa-magic text-purple mr-2"></i>AI Assist</h5>
                <button class="btn btn-outline-secondary btn-block" disabled>Summarize SOP</button>
                <button class="btn btn-outline-secondary btn-block" disabled>Clean Up Formatting</button>
                <button class="btn btn-outline-primary btn-block" disabled>Generate Flexis Handoff Notes</button>
            </div>
        </div>
    </div>
</div>

<?php require_once "includes/footer.php"; ?>
