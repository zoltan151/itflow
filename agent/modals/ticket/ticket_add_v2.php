<?php

require_once '../../../includes/modal_header.php';

$client_id = intval($_GET['client_id'] ?? 0);
$contact_id = intval($_GET['contact_id'] ?? 0);
$project_id = intval($_GET['project_id'] ?? 0);

ob_start();

?>
<div class="modal-header bg-dark">
    <h5 class="modal-title"><i class="fas fa-fw fa-life-ring mr-2"></i>New Ticket (v2)</h5>
    <button type="button" class="close text-white" data-dismiss="modal">
        <span>&times;</span>
    </button>
</div>
<form action="post.php" method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <!-- Hidden/System fields -->
    <?php if ($client_id) { ?>
        <input type="hidden" name="client_id" value="<?php echo $client_id; ?>">
    <?php } ?>
    <?php if ($project_id) { ?>
        <input type="hidden" name="project_id" value="<?php echo $project_id; ?>">
    <?php } ?>
    <input type="hidden" name="billable" value="0">

    <div class="modal-body">

        <!-- Nav -->
        <ul class="nav nav-pills nav-justified mb-3">
            <li class="nav-item">
                <a class="nav-link active" data-toggle="pill" href="#pills-add-details"><i class="fa fa-fw fa-life-ring mr-2"></i>Details</a>
            </li>
            <?php if (!$contact_id) { ?>
                <li class="nav-item">
                    <a class="nav-link" data-toggle="pill" href="#pills-add-contacts"><i class="fa fa-fw fa-users mr-2"></i>Contact</a>
                </li>
            <?php } ?>
            <li class="nav-item">
                <a class="nav-link" data-toggle="pill" href="#pills-add-relationships"><i class="fa fa-fw fa-desktop mr-2"></i>Assignment</a>
            </li>
        </ul>

        <!-- Content -->
        <div class="tab-content">

            <!-- Ticket details -->
            <div class="tab-pane fade show active" id="pills-add-details">

                <div class="form-group">
                    <label>Template</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-cube"></i></span>
                        </div>
                        <select class="form-control select2" id="ticket_template_select" name="ticket_template_id" required>
                            <option value="0">- Choose a Template -</option>
                            <?php
                            $sql_ticket_templates = mysqli_query($mysqli, "
                                    SELECT tt.ticket_template_id,
                                           tt.ticket_template_name,
                                           tt.ticket_template_subject,
                                           tt.ticket_template_details,
                                           COUNT(ttt.task_template_id) as task_count
                                    FROM ticket_templates tt
                                    LEFT JOIN task_templates ttt
                                        ON tt.ticket_template_id = ttt.task_template_ticket_template_id
                                    WHERE tt.ticket_template_archived_at IS NULL
                                    GROUP BY tt.ticket_template_id
                                    ORDER BY tt.ticket_template_name ASC
                                ");

                            while ($row = mysqli_fetch_assoc($sql_ticket_templates)) {
                                $ticket_template_id_select = intval($row['ticket_template_id']);
                                $ticket_template_name_select = nullable_htmlentities($row['ticket_template_name']);
                                $ticket_template_subject_select = nullable_htmlentities($row['ticket_template_subject']);
                                $ticket_template_details_select = nullable_htmlentities($row['ticket_template_details']);
                                $task_count = intval($row['task_count']);
                                ?>
                                <option value="<?php echo $ticket_template_id_select; ?>"
                                        data-subject="<?php echo $ticket_template_subject_select; ?>"
                                        data-details="<?php echo $ticket_template_details_select; ?>">
                                    <?php echo $ticket_template_name_select; ?> (<?php echo $task_count; ?> tasks)
                                </option>
                            <?php } ?>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label>Subject <strong class="text-danger">*</strong></label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span>
                        </div>
                        <input type="text" class="form-control" id="subjectInput" name="subject" placeholder="Subject" maxlength="500" required>
                    </div>
                </div>

                <div class="form-group">
                    <textarea class="form-control tinymceTicket" id="detailsInput" name="details"></textarea>
                </div>

                <div class="row">

                    <div class="col">
                        <div class="form-group">
                            <label>Priority <strong class="text-danger">*</strong></label>
                            <div class="input-group">
                                <div class="input-group-prepend">
                                    <span class="input-group-text"><i class="fa fa-fw fa-thermometer-half"></i></span>
                                </div>
                                <select class="form-control select2" name="priority" required>
                                    <option>Low</option>
                                    <option>Medium</option>
                                    <option>High</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <div class="col">
                        <div class="form-group">
                            <label>Category</label>
                            <div class="input-group">
                                <div class="input-group-prepend">
                                    <span class="input-group-text"><i class="fa fa-fw fa-layer-group"></i></span>
                                </div>
                                <select class="form-control select2" name="category_id">
                                    <option value="0">- Not Categorized -</option>
                                    <?php
                                    $sql_categories = mysqli_query($mysqli, "SELECT category_id, category_name FROM categories WHERE category_type = 'Ticket' AND category_archived_at IS NULL ORDER BY category_name ASC");
                                    while ($row = mysqli_fetch_assoc($sql_categories)) {
                                        $category_id = intval($row['category_id']);
                                        $category_name = nullable_htmlentities($row['category_name']);
                                        ?>
                                        <option value="<?php echo $category_id; ?>"><?php echo $category_name; ?></option>
                                    <?php } ?>

                                </select>
                                <div class="input-group-append">
                                    <button class="btn btn-secondary ajax-modal" type="button"
                                            data-modal-url="../admin/modals/category/category_add.php?category=Ticket">
                                        <i class="fas fa-fw fa-plus"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>

                <div class="form-group">
                    <label>Assign to</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-user-check"></i></span>
                        </div>
                        <select class="form-control select2" name="assigned_to">
                            <option value="0">- Unassigned -</option>
                            <?php

                            $sql = mysqli_query(
                                $mysqli,
                                "SELECT user_id, user_name FROM users
                                WHERE user_type = 1 AND user_status = 1 AND user_archived_at IS NULL ORDER BY user_name ASC"
                            );
                            while ($row = mysqli_fetch_assoc($sql)) {
                                $user_id = intval($row['user_id']);
                                $user_name = nullable_htmlentities($row['user_name']); ?>
                                <option value="<?php echo $user_id; ?>"><?php echo $user_name; ?></option>
                            <?php } ?>
                        </select>
                    </div>
                </div>

                <?php if ($config_module_enable_accounting) { ?>
                    <div class="form-group">
                        <div class="custom-control custom-switch">
                            <input type="checkbox" class="custom-control-input" name="billable" <?php if ($config_ticket_default_billable == 1) { echo "checked"; } ?> value="1" id="billable">
                            <label class="custom-control-label" for="billable">Mark Billable</label>
                        </div>
                    </div>
                <?php } ?>

            </div>

            <!-- Ticket client/contact -->
            <?php if ($contact_id) { ?>
                <input type="hidden" name="contact_id" value="<?php echo $contact_id; ?>">
            <?php } else { ?>
                <div class="tab-pane fade" id="pills-add-contacts">

                    <div class="form-group">
                        <label>Client <strong class="text-danger">*</strong></label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                            </div>
                            <select class="form-control select2" name="client_id" id="changeClientSelect" required <?php if ($client_id) { echo "disabled"; } ?>>
                                <option value="">- Client -</option>
                                <?php

                                $sql = mysqli_query($mysqli, "SELECT * FROM clients WHERE client_lead = 0 AND client_archived_at IS NULL $access_permission_query ORDER BY client_name ASC");
                                while ($row = mysqli_fetch_assoc($sql)) {
                                    $client_id_select = intval($row['client_id']);
                                    $client_name = nullable_htmlentities($row['client_name']); ?>

                                    <option value="<?php echo $client_id_select; ?>" <?php if ($client_id == $client_id_select) {echo "selected"; } ?>><?php echo $client_name; ?></option>

                                <?php } ?>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Contact </label>
                        <div class="input-group">
                            <div class="input-group-prepend">
                                <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                            </div>
                            <select class="form-control select2" name="contact_id" id="contactSelect">
                            </select>
                        </div>
                    </div>

                </div>
            <?php } ?>

            <div class="tab-pane fade" id="pills-add-relationships">
                To-do: project, etc.

                <div class="form-group">
                    <label>Asset</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-desktop"></i></span>
                        </div>
                        <select class="form-control select2" name="asset_id" id="assetSelect">
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label>Location</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-map-marker-alt"></i></span>
                        </div>
                        <select class="form-control select2" name="location_id" id="locationSelect">
                        </select>
                    </div>
                </div>

                <div class="row">

                    <div class="col">
                        <div class="form-group">
                            <label>Vendor</label>
                            <div class="input-group">
                                <div class="input-group-prepend">
                                    <span class="input-group-text"><i class="fa fa-fw fa-building"></i></span>
                                </div>
                                <select class="form-control select2" name="vendor_id" id="vendorSelect">
                                </select>
                            </div>
                        </div>
                    </div>

                    <div class="col">
                        <div class="form-group">
                            <label>Vendor Ticket Number</label>
                            <div class="input-group">
                                <div class="input-group-prepend">
                                    <span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span>
                                </div>
                                <input type="text" class="form-control" name="vendor_ticket_number" placeholder="Vendor ticket number">
                            </div>
                        </div>
                    </div>

                </div>

            </div>

        </div>

    </div>

    <div class="modal-footer">
        <button type="submit" name="add_ticket" class="btn btn-primary text-bold"><i class="fas fa-check mr-2"></i>Create</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fas fa-times mr-2"></i>Cancel</button>
    </div>

</form>

<!-- Ticket Templates -->
<script>
$(document).on('change', '#ticket_template_select', function () {
    const $opt = $(this).find(':selected');
    const templateSubject = $opt.data('subject') || '';
    const templateDetails = $opt.data('details') || '';

    $('#subjectInput').val(templateSubject);

    if (window.tinymce) {
        const editor = tinymce.get('detailsInput');
        if (editor) {
            editor.setContent(templateDetails);
        } else {
            $('#detailsInput').val(templateDetails);
        }
    } else {
        $('#detailsInput').val(templateDetails);
    }
});
</script>

<!-- Ticket Client/Contact JS -->
<link rel="stylesheet" href="/plugins/jquery-ui/jquery-ui.min.css">
<script src="/plugins/jquery-ui/jquery-ui.min.js"></script>
<script src="/agent/js/tickets_add_modal.js"></script>

<?php

require_once '../../../includes/modal_footer.php';
?>

<style>
/* ITFLOW_NEW_TICKET_REQUIRED_TAB_VALIDATION */
.itflow-required-tab-indicator {
    margin-left: 0.25rem;
    color: #dc3545;
    font-weight: 700;
}

.itflow-required-tab-missing-badge {
    display: inline-block;
    margin-left: 0.35rem;
    padding: 0.1rem 0.35rem;
    border-radius: 0.5rem;
    background: #dc3545;
    color: #fff;
    font-size: 0.7rem;
    line-height: 1;
    vertical-align: middle;
}

.itflow-tab-has-missing {
    color: #dc3545 !important;
    font-weight: 700;
}

.itflow-new-ticket-validation-alert {
    margin: 0 0 1rem 0;
}

.itflow-new-ticket-invalid-field {
    border-color: #dc3545 !important;
}

.select2-container.itflow-new-ticket-invalid-field .select2-selection {
    border-color: #dc3545 !important;
}
</style>

<script>
// ITFLOW_NEW_TICKET_REQUIRED_TAB_VALIDATION
(function () {
    var initializedForms = [];

    function textOf(element) {
        return element ? (element.textContent || element.innerText || '').replace(/\s+/g, ' ').trim() : '';
    }

    function getNewTicketModals() {
        return Array.prototype.slice.call(document.querySelectorAll('.modal')).filter(function (modal) {
            var title = modal.querySelector('.modal-title, h1, h2, h3, h4, h5, h6');
            var titleText = textOf(title);
            var modalText = textOf(modal);
            return titleText.indexOf('New Ticket') !== -1 || (
                modalText.indexOf('New Ticket') !== -1 &&
                modalText.indexOf('Details') !== -1 &&
                modalText.indexOf('Contact') !== -1 &&
                modalText.indexOf('Assignment') !== -1
            );
        });
    }

    function getForm(modal) {
        return modal.querySelector('form');
    }

    function getCreateButtons(modal, form) {
        var root = form || modal;
        return Array.prototype.slice.call(root.querySelectorAll('button, input[type="submit"], input[type="button"]')).filter(function (button) {
            var text = textOf(button) || button.value || '';
            return /\bCreate\b/i.test(text);
        });
    }

    // ITFLOW_NEW_TICKET_HIDDEN_TAB_REQUIRED_VALIDATION
    function fieldRoot(field) {
        return field.closest('.form-group, .input-group, .col, .col-md-2, .col-md-3, .col-md-4, .col-md-5, .col-md-6, .col-md-8, .col-md-9, .col-md-12, .form-row, .row') || field.parentElement || field;
    }

    function findNearbyLabel(field) {
        var label = null;

        if (field.id) {
            try {
                label = document.querySelector('label[for="' + field.id.replace(/"/g, '\\"') + '"]');
            } catch (error) {}
        }

        if (!label) {
            var root = fieldRoot(field);
            if (root) {
                label = root.querySelector('label');
            }
        }

        if (!label) {
            var pane = field.closest('.tab-pane, [role="tabpanel"]');
            if (pane) {
                var labels = Array.prototype.slice.call(pane.querySelectorAll('label'));
                labels.some(function (candidate) {
                    var candidateRoot = fieldRoot(candidate);
                    if (candidateRoot && candidateRoot.contains(field)) {
                        label = candidate;
                        return true;
                    }
                    return false;
                });
            }
        }

        return label;
    }

    function labelLooksRequired(field) {
        var label = findNearbyLabel(field);
        var labelText = textOf(label);

        if (!labelText) {
            return false;
        }

        return labelText.indexOf('*') !== -1;
    }

    function fieldLooksRequired(field) {
        if (field.required || field.getAttribute('aria-required') === 'true' || field.getAttribute('data-required') === 'true') {
            return true;
        }

        if (labelLooksRequired(field)) {
            return true;
        }

        var root = fieldRoot(field);
        if (root && textOf(root).indexOf('*') !== -1 && (
            field.tagName === 'SELECT' ||
            field.tagName === 'TEXTAREA' ||
            (field.tagName === 'INPUT' && ['hidden', 'button', 'submit', 'reset'].indexOf((field.type || '').toLowerCase()) === -1)
        )) {
            return true;
        }

        return false;
    }

    // ITFLOW_NEW_TICKET_MODAL_WIDE_REQUIRED_VALIDATION
    function validationScope(form) {
        return (form && form.closest && form.closest('.modal')) || form || document;
    }

    function isSkippableValidationField(field) {
        var type = (field.type || '').toLowerCase();

        if (field.disabled) {
            return true;
        }

        if (type === 'hidden' || type === 'button' || type === 'submit' || type === 'reset') {
            return true;
        }

        if (field.closest('.note-toolbar') || field.closest('.tox-toolbar') || field.closest('.ql-toolbar')) {
            return true;
        }

        if (field.hasAttribute('data-itflow-ignore-required-validation')) {
            return true;
        }

        return false;
    }

    function findRequiredFieldForLabel(label, scope) {
        var field = null;

        if (!label) {
            return null;
        }

        if (label.getAttribute('for')) {
            try {
                field = document.getElementById(label.getAttribute('for'));
            } catch (error) {}
        }

        if (field && !isSkippableValidationField(field)) {
            return field;
        }

        var containers = [
            label.closest('.form-group'),
            label.closest('.input-group'),
            label.closest('.col-md-12'),
            label.closest('.col-md-8'),
            label.closest('.col-md-6'),
            label.closest('.col-md-4'),
            label.closest('.col-md-3'),
            label.closest('.col'),
            label.parentElement
        ].filter(function (item, index, array) {
            return item && array.indexOf(item) === index;
        });

        for (var i = 0; i < containers.length; i++) {
            field = containers[i].querySelector('select, textarea, input:not([type="hidden"]):not([type="button"]):not([type="submit"]):not([type="reset"])');
            if (field && !isSkippableValidationField(field)) {
                return field;
            }
        }

        var pane = label.closest('.tab-pane, [role="tabpanel"]');
        if (pane) {
            var labels = Array.prototype.slice.call(pane.querySelectorAll('label'));
            var labelIndex = labels.indexOf(label);
            var fields = Array.prototype.slice.call(pane.querySelectorAll('select, textarea, input:not([type="hidden"]):not([type="button"]):not([type="submit"]):not([type="reset"])')).filter(function (candidate) {
                return !isSkippableValidationField(candidate);
            });

            if (fields.length === 1) {
                return fields[0];
            }

            if (labelIndex >= 0 && fields[labelIndex]) {
                return fields[labelIndex];
            }
        }

        return null;
    }

    function requiredFieldsFromStarLabels(scope) {
        var fields = [];

        Array.prototype.slice.call(scope.querySelectorAll('label')).forEach(function (label) {
            if (textOf(label).indexOf('*') === -1) {
                return;
            }

            var field = findRequiredFieldForLabel(label, scope);
            if (field && fields.indexOf(field) === -1) {
                fields.push(field);
            }
        });

        return fields;
    }

    function getRequiredFields(form) {
        var scope = validationScope(form);
        var fields = Array.prototype.slice.call(scope.querySelectorAll('input, select, textarea')).filter(function (field) {
            if (isSkippableValidationField(field)) {
                return false;
            }

            return fieldLooksRequired(field);
        });

        requiredFieldsFromStarLabels(scope).forEach(function (field) {
            if (fields.indexOf(field) === -1) {
                fields.push(field);
            }
        });

        // Deduplicate radio/checkbox groups so one missing group does not produce repeated tab counts.
        var seenGroups = {};
        return fields.filter(function (field) {
            var type = (field.type || '').toLowerCase();

            if ((type === 'checkbox' || type === 'radio') && field.name) {
                var key = type + ':' + field.name;
                if (seenGroups[key]) {
                    return false;
                }
                seenGroups[key] = true;
            }

            return true;
        });
    }

    function fieldLabel(field) {
        var label = findNearbyLabel(field);
        var labelText = textOf(label);

        if (labelText) {
            return labelText.replace(/\*/g, '').trim();
        }

        return field.getAttribute('placeholder') || field.getAttribute('name') || 'Required field';
    }

    function getFieldValue(field) {
        if (field.tagName === 'SELECT' && field.multiple) {
            return Array.prototype.slice.call(field.selectedOptions).map(function (option) {
                return option.value;
            }).filter(function (value) {
                return value !== '' && value !== 'any' && value !== '__clear__' && value.indexOf('__separator_') !== 0;
            }).join(',');
        }

        if ((field.type || '').toLowerCase() === 'checkbox') {
            if (!field.name) {
                return field.checked ? 'checked' : '';
            }

            var group = field.form ? field.form.querySelectorAll('input[type="checkbox"][name="' + field.name.replace(/"/g, '\\"') + '"]') : [field];
            return Array.prototype.slice.call(group).some(function (item) {
                return item.checked;
            }) ? 'checked' : '';
        }

        if ((field.type || '').toLowerCase() === 'radio') {
            if (!field.name) {
                return field.checked ? 'checked' : '';
            }

            var radios = field.form ? field.form.querySelectorAll('input[type="radio"][name="' + field.name.replace(/"/g, '\\"') + '"]') : [field];
            return Array.prototype.slice.call(radios).some(function (item) {
                return item.checked;
            }) ? 'checked' : '';
        }

        return (field.value || '').trim();
    }

    function isInvalid(field) {
        if (field.disabled) {
            return false;
        }

        if (fieldLooksRequired(field) && getFieldValue(field) === '') {
            return true;
        }

        // Only use native validity as a secondary check. Manual required validation above is what catches hidden-tab fields.
        if (typeof field.checkValidity === 'function' && !field.checkValidity()) {
            return true;
        }

        return false;
    }

    function getPane(field) {
        return field.closest('.tab-pane, [role="tabpanel"]');
    }

    function getTabForPane(modal, pane) {
        if (!pane || !pane.id) {
            return null;
        }

        return modal.querySelector(
            'a[href="#' + pane.id + '"], button[data-target="#' + pane.id + '"], a[data-target="#' + pane.id + '"], button[data-bs-target="#' + pane.id + '"], a[data-bs-target="#' + pane.id + '"]'
        );
    }

    function cleanTabName(tab) {
        var clone = tab.cloneNode(true);
        Array.prototype.slice.call(clone.querySelectorAll('.itflow-required-tab-indicator, .itflow-required-tab-missing-badge')).forEach(function (item) {
            item.parentNode.removeChild(item);
        });
        return textOf(clone) || 'Tab';
    }

    function clearValidation(modal) {
        Array.prototype.slice.call(modal.querySelectorAll('.itflow-new-ticket-validation-alert')).forEach(function (alert) {
            alert.parentNode.removeChild(alert);
        });

        Array.prototype.slice.call(modal.querySelectorAll('.itflow-tab-has-missing')).forEach(function (tab) {
            tab.classList.remove('itflow-tab-has-missing');
        });

        Array.prototype.slice.call(modal.querySelectorAll('.itflow-required-tab-missing-badge')).forEach(function (badge) {
            badge.parentNode.removeChild(badge);
        });

        Array.prototype.slice.call(modal.querySelectorAll('.itflow-new-ticket-invalid-field')).forEach(function (field) {
            field.classList.remove('itflow-new-ticket-invalid-field');
        });

        Array.prototype.slice.call(modal.querySelectorAll('.is-invalid')).forEach(function (field) {
            if (field.getAttribute('data-itflow-new-ticket-invalid') === '1') {
                field.classList.remove('is-invalid');
                field.removeAttribute('data-itflow-new-ticket-invalid');
            }
        });
    }

    function markInvalidField(field) {
        field.classList.add('is-invalid');
        field.setAttribute('data-itflow-new-ticket-invalid', '1');

        if (window.jQuery && window.jQuery.fn && window.jQuery.fn.select2 && window.jQuery(field).data('select2')) {
            var container = window.jQuery(field).next('.select2-container');
            if (container && container.length) {
                container.addClass('itflow-new-ticket-invalid-field');
            }
        } else {
            field.classList.add('itflow-new-ticket-invalid-field');
        }
    }

    function addRequiredTabIndicators(modal, form) {
        var tabs = [];

        getRequiredFields(form).forEach(function (field) {
            var tab = getTabForPane(modal, getPane(field));
            if (tab && tabs.indexOf(tab) === -1) {
                tabs.push(tab);
            }
        });

        tabs.forEach(function (tab) {
            if (!tab.querySelector('.itflow-required-tab-indicator')) {
                var indicator = document.createElement('span');
                indicator.className = 'itflow-required-tab-indicator';
                indicator.title = 'This tab has required fields';
                indicator.textContent = '*';
                tab.appendChild(indicator);
            }
        });
    }

    function markMissingTabs(modal, invalidFields) {
        var tabCounts = [];
        var tabOrder = [];

        invalidFields.forEach(function (field) {
            var tab = getTabForPane(modal, getPane(field));
            if (!tab) {
                return;
            }

            var existing = tabCounts.filter(function (item) {
                return item.tab === tab;
            })[0];

            if (!existing) {
                existing = { tab: tab, count: 0 };
                tabCounts.push(existing);
                tabOrder.push(tab);
            }

            existing.count++;
        });

        tabCounts.forEach(function (item) {
            item.tab.classList.add('itflow-tab-has-missing');

            var badge = document.createElement('span');
            badge.className = 'itflow-required-tab-missing-badge';
            badge.textContent = item.count + ' missing';
            item.tab.appendChild(badge);
        });

        return tabOrder;
    }

    function showAlert(modal, tabNames, invalidFields) {
        var body = modal.querySelector('.modal-body') || modal;
        var alert = document.createElement('div');
        alert.className = 'alert alert-danger itflow-new-ticket-validation-alert';
        alert.setAttribute('role', 'alert');

        var uniqueTabs = tabNames.filter(function (value, index, array) {
            return value && array.indexOf(value) === index;
        });

        var fieldNames = invalidFields.slice(0, 5).map(fieldLabel).filter(function (value, index, array) {
            return value && array.indexOf(value) === index;
        });

        var html = '<strong>Please finish the required fields before creating this ticket.</strong>';

        if (uniqueTabs.length > 0) {
            html += '<br>Missing required fields in: <strong>' + uniqueTabs.join(', ') + '</strong>.';
        }

        if (fieldNames.length > 0) {
            html += '<br>Fields to check: ' + fieldNames.join(', ') + '.';
        }

        alert.innerHTML = html;
        body.insertBefore(alert, body.firstChild);
    }

    function focusField(field) {
        if (!field) {
            return;
        }

        if (window.jQuery && window.jQuery.fn && window.jQuery.fn.select2 && window.jQuery(field).data('select2')) {
            try {
                window.jQuery(field).select2('open');
                return;
            } catch (error) {}
        }

        try {
            field.focus({ preventScroll: false });
        } catch (error) {
            try {
                field.focus();
            } catch (ignored) {}
        }
    }

    function showTab(tab) {
        if (!tab) {
            return;
        }

        if (window.jQuery && window.jQuery.fn && window.jQuery.fn.tab) {
            window.jQuery(tab).tab('show');
        } else {
            tab.click();
        }
    }

    function validateNewTicketForm(modal, form) {
        if (window.tinymce && typeof window.tinymce.triggerSave === 'function') {
            window.tinymce.triggerSave();
        }

        if (window.CKEDITOR && window.CKEDITOR.instances) {
            Object.keys(window.CKEDITOR.instances).forEach(function (key) {
                try {
                    window.CKEDITOR.instances[key].updateElement();
                } catch (error) {}
            });
        }

        clearValidation(modal);
        addRequiredTabIndicators(modal, form);

        var invalidFields = getRequiredFields(form).filter(isInvalid);

        if (invalidFields.length === 0) {
            return true;
        }

        invalidFields.forEach(markInvalidField);

        var missingTabs = markMissingTabs(modal, invalidFields);
        var missingTabNames = missingTabs.map(cleanTabName);
        showAlert(modal, missingTabNames, invalidFields);

        var firstField = invalidFields[0];
        var firstTab = missingTabs[0] || getTabForPane(modal, getPane(firstField));

        showTab(firstTab);

        window.setTimeout(function () {
            focusField(firstField);
        }, 250);

        return false;
    }

    function installModal(modal) {
        var form = getForm(modal);
        if (!form || initializedForms.indexOf(form) !== -1) {
            return;
        }

        initializedForms.push(form);
        form.setAttribute('novalidate', 'novalidate');

        addRequiredTabIndicators(modal, form);

        getRequiredFields(form).forEach(function (field) {
            ['input', 'change', 'blur'].forEach(function (eventName) {
                field.addEventListener(eventName, function () {
                    field.classList.remove('is-invalid');
                    field.classList.remove('itflow-new-ticket-invalid-field');
                    field.removeAttribute('data-itflow-new-ticket-invalid');

                    if (window.jQuery && window.jQuery.fn && window.jQuery.fn.select2 && window.jQuery(field).data('select2')) {
                        window.jQuery(field).next('.select2-container').removeClass('itflow-new-ticket-invalid-field');
                    }
                });
            });
        });

        form.addEventListener('submit', function (event) {
            if (form.getAttribute('data-itflow-new-ticket-validation-passed') === '1') {
                return;
            }

            event.preventDefault();
            event.stopPropagation();

            if (validateNewTicketForm(modal, form)) {
                form.setAttribute('data-itflow-new-ticket-validation-passed', '1');
                form.submit();
            }
        }, true);

        getCreateButtons(modal, form).forEach(function (button) {
            button.addEventListener('click', function (event) {
                if (form.getAttribute('data-itflow-new-ticket-validation-passed') === '1') {
                    return;
                }

                event.preventDefault();
                event.stopPropagation();

                if (validateNewTicketForm(modal, form)) {
                    form.setAttribute('data-itflow-new-ticket-validation-passed', '1');
                    form.submit();
                }
            }, true);
        });
    }

    function install() {
        getNewTicketModals().forEach(installModal);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', install);
    } else {
        install();
    }

    document.addEventListener('shown.bs.modal', install);
})();
</script>

