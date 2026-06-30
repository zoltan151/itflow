<?php
// ITFLOW_DIAGRAM_WHITEBOARD_PHASE2B
// ITFLOW_DOCUMENT_DATE_NULL_FIX
// ITFLOW_DOCUMENT_TYPES_PHASE2A
// ITFLOW_RENAME_FILES_SECTION_TO_DOCUMENTATION

require_once "includes/inc_all_client.php";


//Initialize the HTML Purifier to prevent XSS
require "../plugins/htmlpurifier/HTMLPurifier.standalone.php";

$purifier_config = HTMLPurifier_Config::createDefault();
$purifier_config->set('Cache.DefinitionImpl', null); // Disable cache by setting a non-existent directory or an invalid one
$purifier_config->set('URI.AllowedSchemes', ['data' => true, 'src' => true, 'http' => true, 'https' => true]);
$purifier = new HTMLPurifier($purifier_config);

if (isset($_GET['document_id'])) {
    $document_id = intval($_GET['document_id']);
}

$folder_location = 0;

$sql_document = mysqli_query($mysqli, "SELECT * FROM documents
    LEFT JOIN folders ON document_folder_id = folder_id
    LEFT JOIN users ON document_created_by = user_id
    WHERE document_client_id = $client_id AND document_id = $document_id
    LIMIT 1"
);

if (mysqli_num_rows($sql_document) == 0) {
    echo "<center><h1 class='text-secondary mt-5'>Nothing to see here</h1><a class='btn btn-lg btn-secondary mt-3' href='javascript:history.back()'><i class='fa fa-fw fa-arrow-left'></i> Go Back</a></center>";
    require_once "../includes/footer.php";
    exit();
}

$row = mysqli_fetch_assoc($sql_document);

$folder_name = nullable_htmlentities($row['folder_name']);
$document_name = nullable_htmlentities($row['document_name']);
$document_description = nullable_htmlentities($row['document_description']);
$document_type = nullable_htmlentities($row['document_type'] ?? 'General');
$document_diagram_data = nullable_htmlentities($row['document_diagram_data'] ?? '');
$document_diagram_updated_at = nullable_htmlentities($row['document_diagram_updated_at'] ?? '');
$document_diagram_enabled = in_array($document_type, [
    'Diagram / Whiteboard',
    'Network Diagram',
    'Process Map',
    'Mind Map',
], true);
$document_content = $purifier->purify($row['document_content']);
$document_created_by_id = intval($row['document_created_by']);
$document_created_by_name = nullable_htmlentities($row['user_name']);
$document_created_at = nullable_htmlentities($row['document_created_at']);
$document_updated_at = nullable_htmlentities($row['document_updated_at']);
$document_display_date_raw = $row['document_updated_at'] ?: $row['document_created_at'];
$document_display_date = $document_display_date_raw ? date('Y-m-d', strtotime($document_display_date_raw)) : '';
$document_archived_at = nullable_htmlentities($row['document_archived_at']);
$document_folder_id = intval($row['document_folder_id']);
$document_client_visible = intval($row['document_client_visible']);

// Override Tab Title // No Sanitizing needed as this var will opnly be used in the tab title
$page_title = $row['document_name'];

?>

<ol class="breadcrumb d-print-none">
    <li class="breadcrumb-item">
        <a href="client_overview.php?client_id=<?= $client_id ?>"><?= $client_name ?></a>
    </li>
    <li class="breadcrumb-item">
        <a href="files.php?client_id=<?= $client_id ?>">Documentation</a>
    </li>
    <?php
    // Build the full folder path
    $folder_id = $document_folder_id;
    $folder_path = array();

    while ($folder_id > 0) {
        $sql_folder = mysqli_query($mysqli, "SELECT folder_name, parent_folder FROM folders WHERE folder_id = $folder_id");
        if ($row_folder = mysqli_fetch_assoc($sql_folder)) {
            $folder_name = nullable_htmlentities($row_folder['folder_name']);
            $parent_folder = intval($row_folder['parent_folder']);

            // Prepend the folder to the beginning of the array
            array_unshift($folder_path, array('folder_id' => $folder_id, 'folder_name' => $folder_name));

            // Move up to the parent folder
            $folder_id = $parent_folder;
        } else {
            // If the folder is not found, break the loop
            break;
        }
    }

    // Output breadcrumb items for each folder in the path
    foreach ($folder_path as $folder) {
        $bread_crumb_folder_id = $folder['folder_id']; // Sanitized before put in array
        $bread_crumb_folder_name = $folder['folder_name']; // Sanitized before put in array
        ?>
        <li class="breadcrumb-item">
            <a href="files.php?client_id=<?php echo $client_id; ?>&folder_id=<?php echo $bread_crumb_folder_id; ?>">
                <i class="fas fa-fw fa-folder-open mr-2"></i><?php echo $bread_crumb_folder_name; ?>
            </a>
        </li>
        <?php
    }
    ?>
    <li class="breadcrumb-item active">
        <i class="fas fa-file"></i> <?php echo $document_name; ?>
        <?php if (!empty($document_archived_at)) {
            echo "<span class='text-danger ml-2'>(ARCHIVED on $document_archived_at)</span>";
        } ?>
    </li>
</ol>

<div class="row">

    <div class="col-md-9">
        <div class="card">
            <div class="card-header bg-dark">
                <div class="row">
                    <div class="col">
                        <div class="h4 mb-0">
                            <?= $document_name ?>
                            <?php if (!empty($document_type) && $document_type !== 'General') { ?>
                                <span class="badge badge-info ml-2 align-middle" title="Document Type"><i class="fa fa-fw fa-tag mr-1"></i><?= $document_type ?></span><!-- ITFLOW_DOCUMENT_TYPE_BADGE_DETAILS -->
                            <?php } ?>
                        </div>
                        <?php if ($document_description) { ?>
                        <div class="text-light"><?= $document_description ?></div>
                        <?php } ?>
                    </div>
                    <div class="col">
                        <div class="float-right">
                            <div>
                                Date:
                                <strong><?= $document_display_date ?></strong>
                            </div>
                            <?php if($document_created_by_name) { ?>
                            <div>
                                Prepared By:
                                <strong><?= $document_created_by_name ?></strong>
                            </div>
                            <?php } ?>
                        </div>
                    </div>
                </div>
            </div>
            
                <?php if ($document_diagram_enabled) { ?>
            <div class="card-body border-bottom itflow-diagram-whiteboard" data-itflow-marker="ITFLOW_DIAGRAM_WHITEBOARD_PHASE2B">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <h5 class="mb-0"><i class="fas fa-project-diagram mr-2"></i>Diagram / Whiteboard</h5>
                            <small class="text-muted">
                                Enter one connection per line, for example:
                                <code>Internet -> Firewall -> Switch -> Server</code>
                            </small>
                            <?php if ($document_diagram_updated_at) { ?>
                                <div><small class="text-muted">Last diagram update: <?= $document_diagram_updated_at ?></small></div>
                            <?php } ?>
                        </div>
                        <div class="d-print-none">
                            <button type="button" class="btn btn-sm btn-secondary" id="itflowDiagramRenderButton">
                                <i class="fas fa-sync-alt mr-1"></i>Render
                            </button>
                        </div>
                    </div>

                    <form action="post.php" method="post" class="d-print-none mb-3">
                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                        <input type="hidden" name="document_id" value="<?= $document_id ?>">
                        <div class="form-group">
                            <label>Diagram Source</label>
                            <textarea class="form-control" id="itflowDiagramSource" name="document_diagram_data" rows="8" spellcheck="false" placeholder="Internet -> Firewall&#10;Firewall -> Switch&#10;Switch -> Server&#10;Switch -> Workstations"><?= $document_diagram_data ?></textarea>
                            <small class="form-text text-muted">
                                Supports chains using <code>-></code>. Blank lines and lines starting with <code>#</code> are ignored.
                            </small>
                        </div>
                        <button type="submit" name="save_document_diagram" class="btn btn-primary">
                            <i class="fas fa-save mr-1"></i>Save Diagram
                        </button>
                    </form>

                    <div class="border rounded bg-light p-2">
                        <div id="itflowDiagramPreview" style="min-height: 260px; overflow-x: auto;"></div>
                    </div>
            </div>
            <?php } ?>

            <div class="card-body prettyContent">
                <?= $document_content ?>
                <hr>
                <h4>Documentation Revision History</h4>

                <table class="table table-sm">
                    <thead class="thead-light">
                        <th>Version</th>
                        <th>Date</th>
                        <th>Name</th>
                        <th>Description</th>
                        <th>Author</th>
                    </thead>
                    <tbody>
                        <?php
                        $sql_document_versions = mysqli_query($mysqli, "SELECT * FROM document_versions
                            LEFT JOIN users ON document_version_created_by = user_id
                            WHERE document_version_document_id = $document_id
                            ORDER BY document_version_created_at ASC"
                        );

                        $document_version_count = 1; // Initialize the document version counter

                        while ($row = mysqli_fetch_assoc($sql_document_versions)) {
                            $document_version_id = intval($row['document_version_id']);
                            $document_version_name = nullable_htmlentities($row['document_version_name']);
                            $document_version_description = nullable_htmlentities($row['document_version_description']);
                            if ($document_version_description ) {
                                $document_version_description_display = $document_version_description;
                            } else {
                                $document_version_description_display = "-";
                            }
                            $document_version_author = nullable_htmlentities($row['user_name']);
                            $document_version_created_date = date('Y-m-d', strtotime($row['document_version_created_at']));

                        ?>
                        <tr>
                            <td><?= $document_version_count ?></td>
                            <td><?= $document_version_created_date ?></td>
                            <td><?= $document_version_name ?></td>
                            <td><?= $document_version_description_display ?></td>
                            <td><?= $document_version_author ?></td>
                        </tr>
                        <?php
                        $document_version_count++; // Increment the counter
                        }
                        ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="col-md-3 d-print-none">
        <div class="row">
            <div class="col-12 mb-3">
                <button type="button" class="btn btn-primary ajax-modal mr-1"
                    data-modal-size="lg"
                    data-modal-url="modals/document/document_edit.php?id=<?= $document_id ?>">
                    <i class="fas fa-fw fa-edit" title="Edit"></i>
                </button>
                <button type="button" class="btn btn-secondary mr-1" data-toggle="modal" data-target="#shareModal"
                    onclick="populateShareModal(<?= "$client_id, 'Document', $document_id"; ?>)">
                    <i class="fas fa-fw fa-share" title="Share"></i>
                </button>
                <a class="btn btn-success mr-1" href="post.php?export_document=<?= $document_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>"><i class='fas fa-fw fa-file-pdf' title="PDF Export"></i></a>
                <button type="button" class="btn btn-secondary mr-4" onclick="window.print();"><i class="fas fa-fw fa-print" title="Print"></i></button>
                <a class="btn btn-warning mr-1 confirm-link" href="post.php?archive_document=<?= $document_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>" title="Archive"><i class='fas fa-fw fa-archive'></i></a>
                <a class="btn btn-danger confirm-link" href="post.php?delete_document=<?= $document_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>&from=document_details" title="Delete"><i class='fas fa-fw fa-trash-alt'></i></a>
            </div>
        </div>
        <div class="card card-body bg-light">
            <h5 class="mb-3"><i class="fas fa-tags mr-2"></i>Related Items</h5>
            <h6>
                <i class="fas fa-fw fa-paperclip text-secondary mr-2"></i>Files
                <button type="button" class="btn btn-link btn-sm ajax-modal"
                    data-modal-url="modals/document/document_link_file.php?document_id=<?= $document_id ?>">
                    <i class="fas fa-fw fa-plus"></i>
                </button>
            </h6>
            <?php
            $sql_files = mysqli_query($mysqli, "SELECT * FROM files, document_files
                WHERE document_files.file_id = files.file_id
                AND document_files.document_id = $document_id
                ORDER BY file_name ASC"
            );

            $linked_files = array();

            while ($row = mysqli_fetch_assoc($sql_files)) {
                $file_id = intval($row['file_id']);
                $folder_id = intval($row['file_folder_id']);
                $file_name = nullable_htmlentities($row['file_name']);

                $linked_files[] = $file_id;

                ?>
                <div class="ml-2">
                    <a href="files.php?client_id=<?= $client_id ?>&folder_id=<?= $folder_id ?>&q=<?= $file_name ?>" target="_blank"><?= $file_name ?></a>
                    <a class="confirm-link" href="post.php?unlink_file_from_document&file_id=<?= $file_id ?>&document_id=<?= $document_id ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                        <i class="fas fa-fw fa-unlink text-secondary float-right" title="Unlink File"></i>
                    </a>
                </div>
                <?php
                }
                ?>
            <h6>
                <i class="fas fa-fw fa-users text-secondary mt-3 mr-2"></i>Contacts
                <button type="button" class="btn btn-link btn-sm ajax-modal"
                    data-modal-url="modals/document/document_link_contact.php?document_id=<?= $document_id ?>">
                    <i class="fas fa-fw fa-plus"></i>
                </button>
            </h6>
            <?php
            $sql_contacts = mysqli_query($mysqli, "SELECT contacts.contact_id, contact_name FROM contacts, contact_documents
                WHERE contacts.contact_id = contact_documents.contact_id
                AND contact_documents.document_id = $document_id
                ORDER BY contact_name ASC"
            );

            $linked_contacts = array();

            while ($row = mysqli_fetch_assoc($sql_contacts)) {
                $contact_id = intval($row['contact_id']);
                $contact_name = nullable_htmlentities($row['contact_name']);

                $linked_contacts[] = $contact_id;

                ?>
                <div class="ml-2">
                    <a class="ajax-modal" href="#"
                        data-modal-size="lg"
                        data-modal-url="modals/contact/contact_details.php?id=<?= $contact_id ?>">
                        <?php echo $contact_name; ?></a>
                    <a class="confirm-link float-right" href="post.php?unlink_contact_from_document&contact_id=<?php echo $contact_id; ?>&document_id=<?php echo $document_id; ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                        <i class="fas fa-fw fa-unlink text-secondary" title="Unlink Contact"></i>
                    </a>
                </div>
                <?php
                }
                ?>
            <h6>
                <i class="fas fa-fw fa-laptop text-secondary mr-2 mt-3"></i>Assets
                <button type="button" class="btn btn-link btn-sm ajax-modal" data-modal-url="modals/document/document_link_asset.php?document_id=<?= $document_id ?>">
                    <i class="fas fa-fw fa-plus"></i>
                </button>
            </h6>
            <?php
            $sql_assets = mysqli_query($mysqli, "SELECT assets.asset_id, asset_name FROM assets, asset_documents
                WHERE assets.asset_id = asset_documents.asset_id
                AND asset_documents.document_id = $document_id
                ORDER BY asset_name ASC"
            );

            $linked_assets = array();

            while ($row = mysqli_fetch_assoc($sql_assets)) {
                $asset_id = intval($row['asset_id']);
                $asset_name = nullable_htmlentities($row['asset_name']);

                $linked_assets[] = $asset_id;

                ?>
                <div class="ml-2">
                    <a class="ajax-modal" href="#"
                        data-modal-size="lg"
                        data-modal-url="modals/asset/asset_details.php?id=<?= $asset_id ?>">
                        <?php echo $asset_name; ?>
                    </a>
                    <a class="confirm-link float-right" href="post.php?unlink_asset_from_document&asset_id=<?php echo $asset_id; ?>&document_id=<?php echo $document_id; ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                        <i class="fas fa-fw fa-unlink text-secondary" title="Unlink Asset"></i>
                    </a>
                </div>
            <?php
            }
            ?>
            <h6>
                <i class="fas fa-fw fa-cube text-secondary mr-2 mt-3"></i>Licenses
                <button type="button" class="btn btn-link btn-sm ajax-modal"
                    data-modal-url="modals/document/document_link_software.php?document_id=<?= $document_id ?>">
                    <i class="fas fa-fw fa-plus"></i>
                </button>
            </h6>
            <?php
            $sql_software = mysqli_query($mysqli, "SELECT software.software_id, software_name FROM software, software_documents
                WHERE software.software_id = software_documents.software_id
                AND software_documents.document_id = $document_id
                ORDER BY software_name ASC"
            );

            $linked_software = array();

            while ($row = mysqli_fetch_assoc($sql_software)) {
                $software_id = intval($row['software_id']);
                $software_name = nullable_htmlentities($row['software_name']);

                $linked_software[] = $software_id;

                ?>
                <div class="ml-2">
                    <a href="software.php?client_id=<?php echo $client_id; ?>&q=<?php echo $software_name; ?>" target="_blank"><?php echo $software_name; ?></a>
                    <a class="confirm-link float-right" href="post.php?unlink_software_from_document&software_id=<?php echo $software_id; ?>&document_id=<?php echo $document_id; ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                        <i class="fas fa-fw fa-unlink text-secondary" title="Unlink License"></i>
                    </a>
                </div>
                <?php
                }
                ?>
            <h6>
                <i class="fas fa-fw fa-building text-secondary mr-2 mt-3"></i>Vendors
                <button type="button" class="btn btn-link btn-sm ajax-modal"
                    data-modal-url="modals/document/document_link_vendor.php?document_id=<?= $document_id ?>">
                    <i class="fas fa-fw fa-plus"></i>
                </button>
            </h6>
            <?php
            $sql_vendors = mysqli_query($mysqli, "SELECT vendors.vendor_id, vendor_name FROM vendors, vendor_documents
                WHERE vendors.vendor_id = vendor_documents.vendor_id
                AND vendor_documents.document_id = $document_id
                ORDER BY vendor_name ASC"
            );

            $associated_vendors = array();

            while ($row = mysqli_fetch_assoc($sql_vendors)) {
                $vendor_id = intval($row['vendor_id']);
                $vendor_name = nullable_htmlentities($row['vendor_name']);

                $associated_vendors[] = $vendor_id;

                ?>
                <div class="ml-2">
                    <a class="ajax-modal" href="#" data-modal-url="modals/vendor/vendor_details.php?id=<?= $vendor_id ?>">
                        <?php echo $vendor_name; ?>
                    </a>
                    <a class="confirm-link float-right" href="post.php?unlink_vendor_from_document&vendor_id=<?php echo $vendor_id; ?>&document_id=<?php echo $document_id; ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                        <i class="fas fa-fw fa-unlink text-secondary" title="Unlink Vendor"></i>
                    </a>
                </div>
            <?php
            }
            ?>
        </div>

        <?php if ($config_client_portal_enable) { ?>
            <div class="card card-body bg-light">
                <h6><i class="fas fa-handshake mr-2"></i>Portal Collaboration</h6>
                <div class="mt-1">
                    <i class="fa fa-fw fa-eye<?php if (!$document_client_visible) { echo '-slash'; } ?> text-secondary mr-2"></i>Document is
                    <a class="ajax-modal" href="#"
                        data-modal-url="modals/document/document_edit_visibility.php?document_id=<?= $document_id ?>">
                        <?php
                        if ($document_client_visible) {
                            echo "<span class='text-bold text-dark'>visible</span>";
                        } else {
                            echo "<span class='text-muted'>not visible</span>";
                        }
                        ?>
                    </a>
                </div>
            </div>
        <?php } ?>

        <div class="card card-body bg-light">
            <h6><i class="fas fa-history mr-2"></i>Revisions</h6>
            <?php

            $sql_document_versions = mysqli_query($mysqli, "SELECT * FROM document_versions
                LEFT JOIN users ON document_version_created_by = user_id
                WHERE document_version_document_id = $document_id
                ORDER BY document_version_created_at DESC"
            );

            while ($row = mysqli_fetch_assoc($sql_document_versions)) {
                $document_version_id = intval($row['document_version_id']);
                $document_version_name = nullable_htmlentities($row['document_version_name']);
                $document_version_description = nullable_htmlentities($row['document_version_description']);
                $document_version_author = nullable_htmlentities($row['user_name']);
                $document_version_created_date = nullable_htmlentities($row['document_version_created_at']);

                ?>
                <div class="mt-1 <?php if($document_id === $document_version_id){ echo "text-bold"; } ?>">
                    <i class="fas fa-fw fa-history text-secondary mr-2"></i>
                    <a class="ajax-modal" href="#"
                        data-modal-size="lg"
                        data-modal-url="modals/document/document_version_view.php?id=<?= $document_version_id ?>">
                        <?php echo "$document_version_created_date | $document_version_author"; ?>
                    </a>
                    <a class="confirm-link float-right" href="post.php?delete_document_version=<?php echo $document_version_id; ?>&csrf_token=<?= $_SESSION['csrf_token'] ?>">
                        <i class="fas fa-fw fa-trash-alt text-secondary"></i>
                    </a>
                </div>
                <?php
                }
                ?>
        </div>

    </div>

</div>


<?php if ($document_diagram_enabled) { ?>
<script>
(function () {
    function svgEl(name) {
        return document.createElementNS('http://www.w3.org/2000/svg', name);
    }

    function addText(svg, text, x, y, maxChars) {
        var words = String(text || '').split(/\s+/);
        var line = '';
        var lines = [];

        words.forEach(function (word) {
            var candidate = line ? line + ' ' + word : word;
            if (candidate.length > maxChars && line) {
                lines.push(line);
                line = word;
            } else {
                line = candidate;
            }
        });

        if (line) {
            lines.push(line);
        }

        if (!lines.length) {
            lines = [''];
        }

        lines.slice(0, 3).forEach(function (part, index) {
            var t = svgEl('text');
            t.setAttribute('x', x);
            t.setAttribute('y', y + (index * 16));
            t.setAttribute('text-anchor', 'middle');
            t.setAttribute('font-size', '12');
            t.setAttribute('font-family', 'Arial, sans-serif');
            t.setAttribute('fill', '#212529');
            t.textContent = part;
            svg.appendChild(t);
        });
    }

    function parseDiagram(source) {
        var nodes = [];
        var nodeSeen = {};
        var edges = [];

        function addNode(name) {
            name = String(name || '').trim();
            if (!name) {
                return null;
            }

            if (!nodeSeen[name]) {
                nodeSeen[name] = true;
                nodes.push(name);
            }

            return name;
        }

        String(source || '').split(/\r?\n/).forEach(function (line) {
            line = line.trim();

            if (!line || line.charAt(0) === '#') {
                return;
            }

            var parts = line.split(/\s*(?:->|=>)\s*/).map(function (part) {
                return part.trim();
            }).filter(Boolean);

            if (parts.length === 1) {
                addNode(parts[0]);
                return;
            }

            for (var i = 0; i < parts.length; i++) {
                addNode(parts[i]);
            }

            for (var j = 0; j < parts.length - 1; j++) {
                edges.push({ from: parts[j], to: parts[j + 1] });
            }
        });

        return { nodes: nodes, edges: edges };
    }

    function renderDiagram() {
        var source = document.getElementById('itflowDiagramSource');
        var preview = document.getElementById('itflowDiagramPreview');

        if (!source || !preview) {
            return;
        }

        var diagram = parseDiagram(source.value);
        preview.innerHTML = '';

        if (!diagram.nodes.length) {
            preview.innerHTML = '<div class="text-muted p-4 text-center">No diagram data yet. Add connections above and click Render.</div>';
            return;
        }

        var levels = {};
        diagram.nodes.forEach(function (node) {
            levels[node] = 0;
        });

        for (var pass = 0; pass < diagram.nodes.length + 2; pass++) {
            diagram.edges.forEach(function (edge) {
                levels[edge.to] = Math.max(levels[edge.to] || 0, (levels[edge.from] || 0) + 1);
            });
        }

        var groups = {};
        var maxLevel = 0;

        diagram.nodes.forEach(function (node) {
            var level = levels[node] || 0;
            maxLevel = Math.max(maxLevel, level);
            if (!groups[level]) {
                groups[level] = [];
            }
            groups[level].push(node);
        });

        var positions = {};
        var nodeWidth = 170;
        var nodeHeight = 58;
        var xGap = 230;
        var yGap = 92;
        var margin = 40;
        var maxRows = 1;

        Object.keys(groups).forEach(function (levelKey) {
            maxRows = Math.max(maxRows, groups[levelKey].length);
            groups[levelKey].forEach(function (node, index) {
                positions[node] = {
                    x: margin + (parseInt(levelKey, 10) * xGap),
                    y: margin + (index * yGap)
                };
            });
        });

        var width = Math.max(520, margin * 2 + nodeWidth + maxLevel * xGap);
        var height = Math.max(260, margin * 2 + nodeHeight + (maxRows - 1) * yGap);

        var svg = svgEl('svg');
        svg.setAttribute('width', width);
        svg.setAttribute('height', height);
        svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', 'Document diagram');

        var defs = svgEl('defs');
        var marker = svgEl('marker');
        marker.setAttribute('id', 'itflowDiagramArrow');
        marker.setAttribute('markerWidth', '10');
        marker.setAttribute('markerHeight', '10');
        marker.setAttribute('refX', '9');
        marker.setAttribute('refY', '3');
        marker.setAttribute('orient', 'auto');
        marker.setAttribute('markerUnits', 'strokeWidth');

        var path = svgEl('path');
        path.setAttribute('d', 'M0,0 L0,6 L9,3 z');
        path.setAttribute('fill', '#495057');

        marker.appendChild(path);
        defs.appendChild(marker);
        svg.appendChild(defs);

        diagram.edges.forEach(function (edge) {
            var from = positions[edge.from];
            var to = positions[edge.to];

            if (!from || !to) {
                return;
            }

            var line = svgEl('line');
            line.setAttribute('x1', from.x + nodeWidth);
            line.setAttribute('y1', from.y + (nodeHeight / 2));
            line.setAttribute('x2', to.x);
            line.setAttribute('y2', to.y + (nodeHeight / 2));
            line.setAttribute('stroke', '#495057');
            line.setAttribute('stroke-width', '2');
            line.setAttribute('marker-end', 'url(#itflowDiagramArrow)');
            svg.appendChild(line);
        });

        diagram.nodes.forEach(function (node) {
            var pos = positions[node];

            var rect = svgEl('rect');
            rect.setAttribute('x', pos.x);
            rect.setAttribute('y', pos.y);
            rect.setAttribute('width', nodeWidth);
            rect.setAttribute('height', nodeHeight);
            rect.setAttribute('rx', '9');
            rect.setAttribute('fill', '#ffffff');
            rect.setAttribute('stroke', '#343a40');
            rect.setAttribute('stroke-width', '1.5');
            svg.appendChild(rect);

            addText(svg, node, pos.x + (nodeWidth / 2), pos.y + 25, 22);
        });

        preview.appendChild(svg);
    }

    document.addEventListener('DOMContentLoaded', function () {
        var button = document.getElementById('itflowDiagramRenderButton');
        if (button) {
            button.addEventListener('click', renderDiagram);
        }
        renderDiagram();
    });
})();
</script>
<?php } ?>

<script src="../js/pretty_content.js"></script>

<?php

require_once "modals/share_modal.php";
require_once "../includes/footer.php";
