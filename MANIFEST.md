# v2.4.4.49 - Viewport-scoped content layout / phantom scrollbar hard fix

- Replaces the previous content-wrapper min-height-only approach.
- Locks html/body/wrapper to the viewport so the browser body does not get a phantom scrollbar from AdminLTE rounding/offset math.
- Makes `.content-wrapper` the scroll container for actual long page content.
- Recalculates content-wrapper height from its real rendered top offset.
- Re-runs after page load, resize, and PushMenu collapse/expand.
- Preserves sidebar branding, separator, Internal Workspace behavior, brand colors, and sizing controls.
