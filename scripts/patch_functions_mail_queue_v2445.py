#!/usr/bin/env python3
from pathlib import Path
import datetime
import sys

path = Path('functions.php')
if not path.exists():
    print('ERROR: functions.php not found. Run this from the ITFlow web root.', file=sys.stderr)
    sys.exit(1)

text = path.read_text()
start_marker = 'function addToMailQueue($data) {'
end_marker = '\nfunction createiCalStr'
if start_marker not in text or end_marker not in text:
    print('ERROR: Could not locate addToMailQueue() function boundaries.', file=sys.stderr)
    sys.exit(1)

start = text.index(start_marker)
end = text.index(end_marker, start)
current = text[start:end]
if 'mysqli_real_escape_string($mysqli, strval($email[\'subject\'] ?? \'\'))' in current:
    print('addToMailQueue() already appears patched. No change made.')
    sys.exit(0)

backup = path.with_name('functions.php.bak.' + datetime.datetime.now().strftime('%Y-%m-%d-%H%M%S'))
backup.write_text(text)

new_func = r'''function addToMailQueue($data) {

    global $mysqli;

    if (!is_array($data)) {
        return false;
    }

    foreach ($data as $email) {
        if (!is_array($email)) {
            continue;
        }

        $from = mysqli_real_escape_string($mysqli, strval($email['from'] ?? ''));
        $from_name = mysqli_real_escape_string($mysqli, strval($email['from_name'] ?? ''));
        $recipient = mysqli_real_escape_string($mysqli, strval($email['recipient'] ?? ''));
        $recipient_name = mysqli_real_escape_string($mysqli, strval($email['recipient_name'] ?? ''));
        $subject = mysqli_real_escape_string($mysqli, strval($email['subject'] ?? ''));
        $body = mysqli_real_escape_string($mysqli, strval($email['body'] ?? ''));

        if (empty($recipient)) {
            continue;
        }

        $cal_str = '';
        if (isset($email['cal_str'])) {
            $cal_str = mysqli_real_escape_string($mysqli, strval($email['cal_str']));
        }

        if (isset($email['queued_at']) && !empty($email['queued_at'])) {
            $queued_at = "'" . mysqli_real_escape_string($mysqli, sanitizeInput($email['queued_at'])) . "'";
        } else {
            $queued_at = 'CURRENT_TIMESTAMP()';
        }

        mysqli_query($mysqli, "INSERT INTO email_queue SET email_recipient = '$recipient', email_recipient_name = '$recipient_name', email_from = '$from', email_from_name = '$from_name', email_subject = '$subject', email_content = '$body', email_queued_at = $queued_at, email_cal_str = '$cal_str'");
    }

    return true;
}
'''

path.write_text(text[:start] + new_func + text[end:])
print(f'Patched functions.php. Backup saved to {backup}')
