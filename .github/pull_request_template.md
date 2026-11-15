## What this changes

<!-- What it does, and why. Link the issue it closes (Closes #...). -->

## How it was checked

<!-- The tests you added or ran, and what you looked at on a test installation. -->

## Checklist

### Security and data
- [ ] No real constituent data anywhere (code, tests, screenshots, messages): documentation addresses and example.org only.
- [ ] Server-side permission and channel checks on every new route; the CSRF token on every change.
- [ ] Masked roles stay masked (researchers never see host identities); sensitive actions are in the audit log.
- [ ] New code is in its own module; large existing files only got small fixes.
- [ ] A test of the new behaviour is added to `tests/run_all_checks.sh` and the CI list, and the checks pass.
- [ ] My commits are signed.

### Accessibility (pages only)
- [ ] Everything can be done with the keyboard alone, with a visible focus.
- [ ] New controls have a visible label or an accessible name; images have text alternatives.
- [ ] Colour is not the only signal; motion follows *reduce motion*.
- [ ] Text shows in full (no "…") and reads at 200% zoom.
- [ ] Checked with an automated accessibility checker (for example axe DevTools).

### Documentation
- [ ] The user guide, configuration or technical reference is updated where behaviour or a setting changed.
