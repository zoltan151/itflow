<?php
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

$name = sanitizeInput($_POST['name']);
$folder = intval($_POST['folder']);
$description = sanitizeInput($_POST['description']);

// ITFLOW_DOCUMENT_TYPES_PHASE2A
$document_type_options = [
    'General',
    'SOP',
    'Client SOP',
    'Runbook',
    'Onboarding',
    'Offboarding',
    'Network Diagram',
    'Diagram / Whiteboard',
    'Process Map',
    'Mind Map',
    'Planner',
    'Timeline',
    'Internal KB',
    'Other',
];

$document_type = sanitizeInput($_POST['document_type'] ?? 'General');

if (!in_array($document_type, $document_type_options, true)) {
    $document_type = 'General';
}

$content = mysqli_real_escape_string($mysqli,$_POST['content']);
$content_raw = sanitizeInput($_POST['name'] . " " . str_replace("<", " <", $_POST['content']));
// Content Raw is used for FULL INDEX searching. Adding a space before HTML tags to allow spaces between newlines, bulletpoints, etc. for searching.
