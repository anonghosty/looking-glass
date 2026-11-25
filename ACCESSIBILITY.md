# Accessibility

Looking Glass is used by analysts, researchers, managers, advisors, auditors and administrators of a CSIRT. Everyone
on that team should be able to use it, whatever the way they work.

## Goals

- **WCAG 2.2 level AA where feasible**, for every page of the platform and the documentation site.
- Every action can be done with the keyboard alone, with a visible focus; dialogs keep the focus inside them.
- Colour is never the only signal: states, severities and changes are also given in words.
- Animations follow the system's *reduce motion* setting.
- Text is real text (never an image of text), shown in full, and readable when zoomed to 200%.
- Films in the documentation have captions.

### Checked so far

- **Keyboard (2026-11-17):** every page each role reaches was gone through with Tab and Shift+Tab only, on test data:
  every control is reached, shows a visible focus ring, and none traps the focus. The chart legends and the hourly
  and 15-minute charts, mouse-only until then, became keyboard controls (Enter on a legend; Left and Right arrows, then
  Enter, on a time chart). How to use them: *With the keyboard only* in the user guide.
- The keyboard shortcuts (L on the map, / in Intel gathered, the arrows in lists, drop-downs and the tour) are listed
  under *With the keyboard only* in the user guide.

### Known limitations

- **The 3D map and the charts** are visual. Their figures are also given as text: the analysis window, the tables,
  the key findings and the PDF and CSV reports carry the same information. The charts' legends and time slots can be
  chosen with the keyboard; the map itself is panned and zoomed with the arrow keys and + / -.
- **Unusual activity's charts** give their dates and normal in words, but each day's count only on hover; the card's
  text and **Show the devices** carry the figures.
- **Dialogs keeping the focus inside them** has not yet been checked dialog by dialog.
- **The dark theme's contrast** is being checked page by page against WCAG 2.2 AA; small grey helper text may fall
  short in places.
- **Screen reader support** has not yet been checked page by page; some controls may lack an accessible name. Please
  report any you find.

## Supported environments

- Current versions of Chrome, Edge and Firefox on Windows, macOS and Linux; Safari on macOS.
- Phones and tablets: the pages adapt to narrow screens; the 3D map is best used on a larger screen.
- Screen readers: NVDA and JAWS on Windows, VoiceOver on macOS.

## Contributor requirements

- Changes to pages are checked with the keyboard alone and with an automated checker (for example axe DevTools)
  before the pull request; the pull-request template has the checklist.
- New controls have a visible label or an accessible name; images have text alternatives.
- New text is shown in full, never cut with "…".

## Reporting accessibility barriers

Open an issue with the **Accessibility barrier** form. Tell us what you tried, what happened, the browser and any
assistive technology you use, and how much it blocks you. Barriers that stop someone from doing their work are
treated like bugs that block a release. We answer every report, and say honestly when a fix will take time.
