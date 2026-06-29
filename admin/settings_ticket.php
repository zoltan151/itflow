<?php
require_once "includes/inc_all_admin.php";
 ?>
<div class="card card-dark">
        <div class="card-header py-3">
            <h3 class="card-title"><i class="fas fa-fw fa-reply mr-2"></i>Ticket Reply Target Status</h3>
        </div>
        <div class="card-body">
            <form action="post.php" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

                <p class="text-secondary">
                    Choose the active ticket status that should be applied when a customer or watcher replies by email to an existing ticket. The selected status is also used for the matching helpdesk notification label.
                </p>

                <div class="form-group">
                    <label>Reply Target Status</label>
                    <select class="form-control" name="config_ticket_reply_target_status_id">
                        <?php
                        $reply_target_status_id = intval($config_ticket_reply_target_status_id ?? 0);
                        $status_sql = mysqli_query($mysqli, "SELECT ticket_status_id, ticket_status_name FROM ticket_statuses WHERE ticket_status_active = 1 ORDER BY ticket_status_order, ticket_status_id");
                        while ($status = mysqli_fetch_assoc($status_sql)) {
                            $status_id = intval($status['ticket_status_id']);
                            $status_name = nullable_htmlentities($status['ticket_status_name']);
                            $selected = ($reply_target_status_id === $status_id) ? 'selected' : '';
                            echo "<option value=\"$status_id\" $selected>$status_name</option>";
                        }
                        ?>
                    </select>
                    <small class="text-secondary">Current golden behavior uses the active helpdesk-attention status.</small>
                </div>

                <button type="submit" name="edit_ticket_reply_target_status_settings" class="btn btn-primary text-bold"><i class="fas fa-check mr-2"></i>Save</button>
            </form>
        </div>
    </div>

    <div class="card card-dark">
        <div class="card-header py-3">
            <h3 class="card-title"><i class="fas fa-fw fa-life-ring mr-2"></i>Ticket Settings</h3>
        </div>
        <div class="card-body">
            <form action="post.php" method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token'] ?>">

                <div class="form-group">
                    <label>Ticket Prefix</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-life-ring"></i></span>
                        </div>
                        <input type="text" class="form-control" name="config_ticket_prefix" placeholder="Ticket Prefix" value="<?php echo nullable_htmlentities($config_ticket_prefix); ?>" pattern="^[A-Za-z-]+$" title="Only letters and hyphens are allowed" required>
                    </div>
                </div>

                <div class="form-group">
                    <label>Next Number</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-barcode"></i></span>
                        </div>
                        <input type="number" min="<?php echo intval($config_ticket_next_number); ?>" class="form-control" name="config_ticket_next_number" placeholder="Next Ticket Number" value="<?php echo intval($config_ticket_next_number); ?>" required>
                    </div>
                </div>

                <div class="form-group">
                    <div class="custom-control custom-switch">
                        <input type="checkbox" class="custom-control-input" name="config_ticket_email_parse" <?php if($config_ticket_email_parse == 1){ echo "checked"; } ?> value="1" id="emailToTicketParseSwitch">
                        <label class="custom-control-label" for="emailToTicketParseSwitch">Email-to-ticket parsing <small class="text-secondary">(cron_ticket_email_parser.php must also be added to cron and run every few mins)</small></label>
                    </div>
                </div>

                <div class="form-group">
                    <div class="custom-control custom-switch">
                        <input type="checkbox" class="custom-control-input" name="config_ticket_email_parse_unknown_senders" <?php if($config_ticket_email_parse_unknown_senders == 1){ echo "checked"; } ?> value="1" id="emailToTicketAnonParseSwitch" <?php if($config_ticket_email_parse == 0){ echo "disabled"; } ?>>
                        <label class="custom-control-label" for="emailToTicketAnonParseSwitch">Create tickets for emails from unknown senders/domains <small class="text-secondary">(Enable to ensure all emails automatically create tickets)</small></label>
                    </div>
                </div>

                <?php if ($config_module_enable_accounting) { ?>
                <div class="form-group">
                    <div class="custom-control custom-switch">
                        <input type="checkbox" class="custom-control-input" name="config_ticket_default_billable" <?php if ($config_ticket_default_billable == 1) { echo "checked"; } ?> value="1" id="ticketBillableSwitch">
                        <label class="custom-control-label" for="ticketBillableSwitch">Default to Billable <small class="text-secondary">(This will check the billable box on all new tickets)</small></label>
                    </div>
                </div>
                <?php } ?>

                <div class="form-group">
                    <div class="custom-control custom-switch">
                        <input type="checkbox" class="custom-control-input" name="config_ticket_timer_autostart" <?php if ($config_ticket_timer_autostart == 1) { echo "checked"; } ?> value="1" id="ticketTimerSwitch">
                        <label class="custom-control-label" for="ticketTimerSwitch">Autostart Ticket Timer <small class="text-secondary">(This option will control if the timer starts automatically or manually)</small></label>
                    </div>
                </div>

                <div class="form-group">
                    <label>Number of hours to auto close resolved tickets</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-clock"></i></span>
                        </div>
                        <input type="number" min="24" class="form-control" name="config_ticket_autoclose_hours" placeholder="Delay in hours before a resolved ticket is fully closed" value="<?php echo intval($config_ticket_autoclose_hours); ?>">
                    </div>
                </div>


                <div class="card card-outline card-secondary mt-4">
                    <div class="card-header">
                        <h4 class="card-title"><i class="fa fa-fw fa-envelope-open-text mr-2"></i>Ticket Email Conversation Behavior</h4>
                    </div>
                    <div class="card-body">
                        <p class="text-secondary">
                            Controls how email parser CCs, ticket watchers, and conversation history behave for customer-facing ticket emails.
                        </p>

                        <div class="form-group">
                            <label>Inbound CC watcher behavior</label>
                            <select class="form-control" name="config_ticket_inbound_cc_watcher_mode">
                                <option value="all" <?php if (($config_ticket_inbound_cc_watcher_mode ?? 'all') === 'all') { echo 'selected'; } ?>>Add all valid inbound CCs as watchers</option>
                                <option value="known_contacts" <?php if (($config_ticket_inbound_cc_watcher_mode ?? 'all') === 'known_contacts') { echo 'selected'; } ?>>Only add CCs that are known contacts for the client</option>
                                <option value="disabled" <?php if (($config_ticket_inbound_cc_watcher_mode ?? 'all') === 'disabled') { echo 'selected'; } ?>>Do not auto-add inbound CCs as watchers</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label>Watcher email reply classification</label>
                            <select class="form-control" name="config_ticket_watcher_reply_type">
                                <option value="client" <?php if (($config_ticket_watcher_reply_type ?? 'client') === 'client') { echo 'selected'; } ?>>Client-visible reply</option>
                                <option value="internal" <?php if (($config_ticket_watcher_reply_type ?? 'client') === 'internal') { echo 'selected'; } ?>>Internal reply</option>
                            </select>
                            <small class="text-secondary">This controls replies from ticket watcher email addresses when they are not the primary ticket contact.</small>
                        </div>

                        <div class="form-group">
                            <div class="custom-control custom-switch">
                                <input type="checkbox" class="custom-control-input" name="config_ticket_initial_history_enable" <?php if (($config_ticket_initial_history_enable ?? 1) == 1) { echo "checked"; } ?> value="1" id="ticketInitialHistorySwitch">
                                <label class="custom-control-label" for="ticketInitialHistorySwitch">Include original request context in ticket-created customer emails</label>
                            </div>
                        </div>

                        <div class="form-group">
                            <div class="custom-control custom-switch">
                                <input type="checkbox" class="custom-control-input" name="config_ticket_mail_queue_history_enable" <?php if (($config_ticket_mail_queue_history_enable ?? 1) == 1) { echo "checked"; } ?> value="1" id="ticketMailQueueHistorySwitch">
                                <label class="custom-control-label" for="ticketMailQueueHistorySwitch">Append ticket conversation history to outgoing customer ticket emails</label>
                            </div>
                        </div>

                        <div class="form-group mb-0">
                            <div class="custom-control custom-switch">
                                <input type="checkbox" class="custom-control-input" name="config_ticket_mail_queue_watcher_cc_enable" <?php if (($config_ticket_mail_queue_watcher_cc_enable ?? 1) == 1) { echo "checked"; } ?> value="1" id="ticketMailQueueWatcherCcSwitch">
                                <label class="custom-control-label" for="ticketMailQueueWatcherCcSwitch">Add ticket watchers as CCs on outgoing customer ticket emails</label>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="form-group">
                    <label>Email address to notify when new tickets are raised <small class="text-secondary">(Ideally a distribution list/shared mailbox)</small></label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-bell"></i></span>
                        </div>
                        <input type="email" class="form-control" name="config_ticket_new_ticket_notification_email" placeholder="Address to notify for new tickets, leave blank for none" value="<?php echo nullable_htmlentities($config_ticket_new_ticket_notification_email); ?>">
                    </div>

                        <div class="form-group">
                            <label>Attention Helpdesk Notification Email</label>
                            <input type="text" class="form-control" name="config_ticket_attention_notification_email" value="<?php echo htmlentities($config_ticket_attention_notification_email ?? '', ENT_QUOTES, 'UTF-8'); ?>" placeholder="helpdesk-attention@example.com">
                            <small class="form-text text-muted">
                                Email address(es) notified when a ticket requires internal helpdesk attention, such as when the ticket is moved to the configured Attention Helpdesk status. Separate multiple addresses with commas, semicolons, spaces, or new lines.
                            </small>
                        </div>


                </div>
                                <div class="card card-outline card-secondary mt-4">
                    <div class="card-header">
                        <h4 class="card-title"><i class="fa fa-fw fa-comment-dots mr-2"></i>Resolved Ticket Feedback</h4>
                    </div>
                    <div class="card-body">
                        <div class="form-group">
                            <div class="custom-control custom-switch">
                                <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_enable" <?php if ($config_ticket_resolved_feedback_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackSwitch">
                                <label class="custom-control-label" for="ticketResolvedFeedbackSwitch">Include feedback section in resolved-ticket emails <small class="text-secondary">(Disabled by default)</small></label>
                            </div>
                        </div>

                        <hr>

                        <div class="card card-outline card-light">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Intro Message</h5>
                            </div>
                            <div class="card-body">
                                <div class="custom-control custom-switch mb-3">
                                    <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_message_enable" <?php if ($config_ticket_resolved_feedback_message_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackMessageSwitch">
                                    <label class="custom-control-label" for="ticketResolvedFeedbackMessageSwitch">Include intro message</label>
                                </div>
                                <div class="form-row">
                                    <div class="form-group col-md-3">
                                        <label>Display Order</label>
                                        <input type="number" class="form-control" name="config_ticket_resolved_feedback_message_order" value="<?php echo intval($config_ticket_resolved_feedback_message_order); ?>" min="0" step="10">
                                    </div>
                                    <div class="form-group col-md-9">
                                        <label>Intro Message</label>
                                        <textarea class="form-control" name="config_ticket_resolved_feedback_message" rows="3" placeholder="Thank you for trusting us with your IT support."><?php echo nullable_htmlentities($config_ticket_resolved_feedback_message); ?></textarea>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="card card-outline card-light">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Private Feedback Section</h5>
                            </div>
                            <div class="card-body">
                                <div class="custom-control custom-switch mb-3">
                                    <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_private_enable" <?php if ($config_ticket_resolved_feedback_private_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackPrivateSwitch">
                                    <label class="custom-control-label" for="ticketResolvedFeedbackPrivateSwitch">Include private feedback section</label>
                                </div>
                                <div class="form-row">
                                    <div class="form-group col-md-3">
                                        <label>Display Order</label>
                                        <input type="number" class="form-control" name="config_ticket_resolved_feedback_private_order" value="<?php echo intval($config_ticket_resolved_feedback_private_order); ?>" min="0" step="10">
                                    </div>
                                </div>

                                <div class="ml-4 pl-3 border-left">
                                    <div class="custom-control custom-switch mb-2">
                                        <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_private_heading_enable" <?php if ($config_ticket_resolved_feedback_private_heading_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackPrivateHeadingSwitch">
                                        <label class="custom-control-label" for="ticketResolvedFeedbackPrivateHeadingSwitch">Include heading</label>
                                    </div>
                                    <div class="form-row">
                                        <div class="form-group col-md-6">
                                            <label>Heading</label>
                                            <input type="text" class="form-control" name="config_ticket_resolved_feedback_private_heading" placeholder="Something we can improve?" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_private_heading); ?>">
                                        </div>
                                    </div>

                                    <div class="custom-control custom-switch mb-2">
                                        <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_private_message_enable" <?php if ($config_ticket_resolved_feedback_private_message_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackPrivateMessageSwitch">
                                        <label class="custom-control-label" for="ticketResolvedFeedbackPrivateMessageSwitch">Include message</label>
                                    </div>
                                    <div class="form-row">
                                        <div class="form-group col-md-12">
                                            <label>Private Feedback Message</label>
                                            <textarea class="form-control" name="config_ticket_resolved_feedback_private_message" rows="3" placeholder="If something wasn’t right, please send us private feedback so our management team can review it and make it right."><?php echo nullable_htmlentities($config_ticket_resolved_feedback_private_message); ?></textarea>
                                        </div>
                                    </div>

                                    <div class="custom-control custom-switch mb-2">
                                        <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_private_button_enable" <?php if ($config_ticket_resolved_feedback_private_button_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackPrivateButtonSwitch">
                                        <label class="custom-control-label" for="ticketResolvedFeedbackPrivateButtonSwitch">Include button</label>
                                    </div>
                                    <div class="form-row">
                                        <div class="form-group col-md-6">
                                            <label>Private Feedback URL <small class="text-secondary">(Internal form, escalation page, etc.)</small></label>
                                            <input type="url" class="form-control" name="config_ticket_resolved_feedback_private_url" placeholder="https://" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_private_url); ?>">
                                        </div>
                                        <div class="form-group col-md-3">
                                            <label>Button Text</label>
                                            <input type="text" class="form-control" name="config_ticket_resolved_feedback_private_text" placeholder="Send Private Feedback" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_private_text); ?>">
                                        </div>
                                        <div class="form-group col-md-3">
                                            <label>Button Color</label>
                                            <input type="color" class="form-control" name="config_ticket_resolved_feedback_private_button_color" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_private_button_color); ?>">
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="card card-outline card-light mb-0">
                            <div class="card-header">
                                <h5 class="card-title mb-0">Public Review Section</h5>
                            </div>
                            <div class="card-body">
                                <div class="custom-control custom-switch mb-3">
                                    <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_review_enable" <?php if ($config_ticket_resolved_feedback_review_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackReviewSwitch">
                                    <label class="custom-control-label" for="ticketResolvedFeedbackReviewSwitch">Include public review section</label>
                                </div>
                                <div class="form-row">
                                    <div class="form-group col-md-3">
                                        <label>Display Order</label>
                                        <input type="number" class="form-control" name="config_ticket_resolved_feedback_review_order" value="<?php echo intval($config_ticket_resolved_feedback_review_order); ?>" min="0" step="10">
                                    </div>
                                </div>

                                <div class="ml-4 pl-3 border-left">
                                    <div class="custom-control custom-switch mb-2">
                                        <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_review_heading_enable" <?php if ($config_ticket_resolved_feedback_review_heading_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackReviewHeadingSwitch">
                                        <label class="custom-control-label" for="ticketResolvedFeedbackReviewHeadingSwitch">Include heading</label>
                                    </div>
                                    <div class="form-row">
                                        <div class="form-group col-md-6">
                                            <label>Heading</label>
                                            <input type="text" class="form-control" name="config_ticket_resolved_feedback_review_heading" placeholder="Happy with our service?" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_review_heading); ?>">
                                        </div>
                                    </div>

                                    <div class="custom-control custom-switch mb-2">
                                        <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_review_message_enable" <?php if ($config_ticket_resolved_feedback_review_message_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackReviewMessageSwitch">
                                        <label class="custom-control-label" for="ticketResolvedFeedbackReviewMessageSwitch">Include message</label>
                                    </div>
                                    <div class="form-row">
                                        <div class="form-group col-md-12">
                                            <label>Public Review Message</label>
                                            <textarea class="form-control" name="config_ticket_resolved_feedback_review_message" rows="3" placeholder="If you’re happy with the service you received, we’d greatly appreciate a quick public review."><?php echo nullable_htmlentities($config_ticket_resolved_feedback_review_message); ?></textarea>
                                        </div>
                                    </div>

                                    <div class="custom-control custom-switch mb-2">
                                        <input type="checkbox" class="custom-control-input" name="config_ticket_resolved_feedback_review_button_enable" <?php if ($config_ticket_resolved_feedback_review_button_enable == 1) { echo "checked"; } ?> value="1" id="ticketResolvedFeedbackReviewButtonSwitch">
                                        <label class="custom-control-label" for="ticketResolvedFeedbackReviewButtonSwitch">Include button</label>
                                    </div>
                                    <div class="form-row">
                                        <div class="form-group col-md-6">
                                            <label>Public Review URL <small class="text-secondary">(Google, Yelp, Facebook, etc.)</small></label>
                                            <input type="url" class="form-control" name="config_ticket_resolved_feedback_review_url" placeholder="https://" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_review_url); ?>">
                                        </div>
                                        <div class="form-group col-md-3">
                                            <label>Button Text</label>
                                            <input type="text" class="form-control" name="config_ticket_resolved_feedback_review_text" placeholder="Leave a Review" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_review_text); ?>">
                                        </div>
                                        <div class="form-group col-md-3">
                                            <label>Button Color</label>
                                            <input type="color" class="form-control" name="config_ticket_resolved_feedback_review_button_color" value="<?php echo nullable_htmlentities($config_ticket_resolved_feedback_review_button_color); ?>">
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="form-group">
                    <label>Tickets Default View</label>
                    <div class="input-group">
                        <div class="input-group-prepend">
                            <span class="input-group-text"><i class="fa fa-fw fa-eye"></i></span>
                        </div>
                        <select class="form-control" name="config_ticket_default_view">
                            <option value=0 <?php if ($config_ticket_default_view == 0) { echo "selected"; } ?>>List</option>
                            <option value=1 <?php if ($config_ticket_default_view == 1) { echo "selected"; } ?>>Compact</option>
                            <option value=2 <?php if ($config_ticket_default_view == 2) { echo "selected"; } ?>>Kanban</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                <label>Kanban Settings</label>
                    <div class="custom-control custom-switch">
                        <input type="checkbox" class="custom-control-input" name="config_ticket_ordering" <?php if ($config_ticket_ordering == 1) { echo "checked"; } ?> value="1" id="ticketOrderingSwitch">
                        <label class="custom-control-label" for="ticketOrderingSwitch">Allow ticket ordering within its column<small class="text-secondary"> (unchecked = order by priority and id)</small></label>
                    </div>
                    <div class="custom-control custom-switch">
                    <input type="checkbox" class="custom-control-input" name="config_ticket_moving_columns" <?php if ($config_ticket_moving_columns == 1) { echo "checked"; } ?> value="1" id="ticketMovingColumnsSwitch">
                        <label class="custom-control-label" for="ticketMovingColumnsSwitch">Allow moving columns</label>
                    </div>
                </div>

                <hr>

                <button type="submit" name="edit_ticket_settings" class="btn btn-primary text-bold"><i class="fas fa-check mr-2"></i>Save</button>

            
            </form>
        </div>
    </div>

<?php
require_once "../includes/footer.php";

