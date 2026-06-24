<?php
require_once "inc_confirm_modal.php";
?>

<?php
if (basename(dirname($_SERVER['REQUEST_URI'])) === 'admin') { ?>
    <p class="text-right font-weight-light">ITFlow <?php echo APP_VERSION ?> &nbsp; · &nbsp; <a target="_blank" href="https://docs.itflow.org">Docs</a> &nbsp; · &nbsp; <a target="_blank" href="https://forum.itflow.org">Forum</a> &nbsp; · &nbsp; <a target="_blank" href="https://services.itflow.org">Services</a></p>
    <br>
<?php } ?>
<?php
if (basename(dirname($_SERVER['REQUEST_URI'])) === 'guest') { ?>
<p class="text-center">
    <?php
        echo nullable_htmlentities($session_company_name);
        if (!$config_whitelabel_enabled) {
            echo '<br><small class="text-muted">Powered by ITFlow</small>';
        }
    ?>
</p>
<?php } ?>

</div><!-- /.container-fluid -->
</div> <!-- /.content -->
</div> <!-- /.content-wrapper -->
</div> <!-- ./wrapper -->

<!-- Set the browser window title to the clients name -->
<script>document.title = <?php echo json_encode("$tab_title - $page_title"); ?>;</script>

<!-- REQUIRED SCRIPTS -->

<!-- Bootstrap 4 -->
<script src="/plugins/bootstrap/js/bootstrap.bundle.min.js"></script>

<!-- Custom js-->
<script src="/plugins/moment/moment.min.js"></script>
<script src="/plugins/chart.js/chart.umd.min.js"></script>
<script src="/plugins/tempusdominus-bootstrap-4/js/tempusdominus-bootstrap-4.min.js"></script>
<script src="/plugins/daterangepicker/daterangepicker.js"></script>
<script src="/plugins/select2/js/select2.min.js"></script>
<script src="/plugins/inputmask/jquery.inputmask.min.js"></script>
<script src="/plugins/tinymce/tinymce.min.js" referrerpolicy="origin"></script>
<script src="/plugins/Show-Hide-Passwords-Bootstrap-4/bootstrap-show-password.min.js"></script>
<script src="/plugins/clipboardjs/clipboard.min.js"></script>
<script src="/js/keepalive.js"></script>
<script src="/plugins/DataTables/datatables.min.js"></script>
<script src="/plugins/intl-tel-input/js/intlTelInput.min.js"></script>

<!-- AdminLTE App -->
<script src="/plugins/adminlte/js/adminlte.min.js"></script>
<script src="/js/app.js"></script>
<script src="/js/ajax_modal.js"></script>
<script src="/js/confirm_modal.js"></script>
<script src="/js/date_filter.js"></script>

<!-- ITFlow layout: viewport-scoped content height; body never scrolls from AdminLTE math -->
<style>
    html,
    body {
        height: 100% !important;
        min-height: 100% !important;
        overflow: hidden !important;
    }
    .wrapper {
        height: 100vh !important;
        min-height: 100vh !important;
        max-height: 100vh !important;
        overflow: hidden !important;
    }
    .main-sidebar {
        height: 100vh !important;
        max-height: 100vh !important;
        overflow: hidden !important;
    }
    .content-wrapper {
        height: calc(100vh - var(--itflow-content-wrapper-top, 57px)) !important;
        min-height: calc(100vh - var(--itflow-content-wrapper-top, 57px)) !important;
        max-height: calc(100vh - var(--itflow-content-wrapper-top, 57px)) !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
        box-sizing: border-box !important;
    }
</style>
<script>
(function () {
    function normalizeViewportLayout() {
        var contentWrapper = document.querySelector('.content-wrapper');
        if (!contentWrapper) { return; }

        var topOffset = Math.max(0, Math.ceil(contentWrapper.getBoundingClientRect().top || 0));
        var availableHeight = Math.max(0, window.innerHeight - topOffset);

        document.documentElement.style.setProperty('--itflow-content-wrapper-top', topOffset + 'px');
        contentWrapper.style.height = availableHeight + 'px';
        contentWrapper.style.minHeight = availableHeight + 'px';
        contentWrapper.style.maxHeight = availableHeight + 'px';
        contentWrapper.style.overflowY = 'auto';
        contentWrapper.style.overflowX = 'hidden';
    }

    var queued = false;
    function queueNormalize() {
        if (queued) { return; }
        queued = true;
        window.requestAnimationFrame(function () {
            queued = false;
            normalizeViewportLayout();
        });
    }

    function normalizeBurst() {
        queueNormalize();
        setTimeout(queueNormalize, 25);
        setTimeout(queueNormalize, 100);
        setTimeout(queueNormalize, 250);
        setTimeout(queueNormalize, 750);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', normalizeBurst);
    } else {
        normalizeBurst();
    }

    window.addEventListener('load', normalizeBurst);
    window.addEventListener('resize', normalizeBurst);

    document.addEventListener('click', function (event) {
        if (event.target.closest('[data-widget="pushmenu"]')) {
            normalizeBurst();
        }
    });

    if (window.jQuery) {
        window.jQuery(document).on('collapsed.lte.pushmenu shown.lte.pushmenu expanded.lte.pushmenu', normalizeBurst);
    }

    if (window.MutationObserver && document.body) {
        new MutationObserver(normalizeBurst).observe(document.body, { attributes: true, attributeFilter: ['class', 'style'] });
    }
})();
</script>

</body>
</html>

<?php

// Calculate Execution time Uncomment for test

//$time_end = microtime(true);
//$execution_time = ($time_end - $time_start);
//echo '<h2>Total Execution Time: '.number_format((float) $execution_time, 10) .' seconds</h2>';
