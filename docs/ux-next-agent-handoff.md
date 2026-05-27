# UX Next Agent Handoff

Date: 2026-05-25

## User Prompt To Preserve

Ryan flagged that the current site still feels too wordy and unclear:

> i just saved a screenshot to pictures. it should show a section of the site that seems too much words for users. maybe we can minimize all the words and get the key points across with less text, posibly in side panel so the website feels more minimla. also when i click Try live demo scan, it doesnt scroll down to the results but it needs to. also its unclear what the button 'load gemma review' does because IMO the live demo scan should be 'test an example one' and 'scan now' buttons depending if the field is empty or not. needs to detect if theres a error link, and it needs to actually scan. if it takes a min, make a simple loading animation from a popular github repo. risk signals should be color coded green, yellow, red- and only go 1-3. also at the bottom, its unclear what parsed config section, and evidence/safe workflow notes section is intended for. store this prompt, extract all todos from it, and proceed -- write all this down and store it all as tasks plus your current state for a next agent handoff

## Screenshot State

Expected user screenshot location was "Pictures." The newest matching file found
was:

```text
/home/yin/Desktop/SAVE/Pictures/Screenshot from 2026-05-25 18-58-44.png
```

That image shows a GitHub PR page, not Agent Surface Map. The next agent should
re-check `Pictures`, `Desktop/SAVE/Pictures`, and any new screenshot path Ryan
provides before making visual edits.

## Current Public State

- Repo: `/home/yin/security-research/openclaw-workspace/gemma-agent-surface-map`
- Branch: `main`
- Last pushed commit: `2f94221 Prepare Agent Surface Map for Gemma submission`
- Live demo: `https://gemma-agent-surface-map.vercel.app`
- Live demo now loads `public/verified-gemma-review.json` by default.
- Live screenshot check passed after deploy: first viewport shows:
  - "Loaded the saved verified Gemma 4 review for the public demo fixture."
  - review mode `read-only scan + live/saved Gemma 4 review`
  - risk score `45`
- DEV article updated through API with the verified-Gemma-default wording.
- DEV public page currently works with trailing slash:
  `https://dev.to/vonb/agent-surface-map-gemma-4-review-before-you-install-an-mcp-1nbn/`
- The no-slash DEV URL returned a cached 404 after a brief accidental unpublish
  caused by frontmatter. The article API says it is published again. Re-check the
  no-slash route later; this may be CDN cache.

## Local Working Tree State

Known uncommitted/untracked files after the main release commit:

- `docs/dev-submission-draft.md` modified only to change frontmatter from
  `published: false` to `published: true`.
- `docs/public-readiness-review.md` untracked local readiness note.
- Untracked local/internal positioning notes should stay private unless rewritten.
- This file is a new handoff note.

Do not accidentally publish internal-only notes unless Ryan explicitly wants
them public.

## Verification Already Run

- `python3 -m unittest discover -s tests -v` -> 70 tests passed.
- `python3 -m py_compile remediation_pr_body.py remediation_apply.py remediation_approval.py remediation_renderer.py drift_watch.py runtime_telemetry.py policy.py surface_map.py server.py api/scan.py mcp_server.py scripts/mcp_workflow_smoke.py` -> passed.
- `node --check public/app.js` -> passed.
- `curl https://gemma-agent-surface-map.vercel.app/app.js` confirmed deployed JS loads `verified-gemma-review.json`.
- `curl https://gemma-agent-surface-map.vercel.app/verified-gemma-review.json` confirmed `review_source: "gemma"`.
- Headless Chrome screenshot of live site saved to `/tmp/asm-live-home.png`.

## Extracted UX Todos

### 1. Reduce Text Density

Problem:
The site has too many explanatory paragraphs in the main flow. It feels less
minimal than it should for a judge/user trying to understand the product fast.

Tasks:

- Cut visible explanatory text in the homepage flow by at least 40%.
- Replace paragraph-heavy sections with short labels, compact state chips, and
  one-line explanations.
- Move deeper explanation into a side panel, drawer, details element, or
  secondary "Why this matters" rail.
- Keep first viewport focused on:
  - what it does
  - what to paste/click
  - current verdict
  - why Gemma matters
- Avoid long text blocks inside the verdict, risk signals, parsed config, and
  evidence sections.

Acceptance:

- A non-technical judge can understand the product in 10 seconds.
- The page still says Gemma is central, but does not feel like a blog post.
- No major text block in the primary app surface should exceed 2 short lines.

### 2. Fix Demo Button Semantics

Problem:
`Load verified Gemma 4 review` is unclear. Ryan thinks the UX should be based on
whether the URL field is empty.

Tasks:

- Replace the current two-button ambiguity with clearer states:
  - If URL field is empty: primary button should behave like "Test example".
  - If URL field has a valid URL: primary button should behave like "Scan now".
- Keep the verified Gemma proof accessible, but label it clearly as a saved proof
  if it remains a separate control.
- Consider making saved Gemma proof a small secondary link/chip:
  "Saved Gemma proof" rather than a primary action.
- Avoid wording that makes a static JSON load feel like the live scanner.

Acceptance:

- Empty input does not produce confusion; it runs the example fixture.
- Filled input runs the live scanner.
- The saved Gemma proof is understandable as proof, not a fake scan.

### 3. Scroll To Results After Live Scan

Problem:
Clicking `Try live demo scan` does not scroll down to the results.

Tasks:

- After any successful scan, scroll to `.verdict-panel` or the result summary.
- On failed scan, keep the user near the input and show a concise error.
- For example/demo scans, scroll after render completes.

Acceptance:

- Clicking example/live scan visibly lands the user on the verdict/results.
- Keyboard focus should also move to the result heading for accessibility.

### 4. URL Validation And Error Handling

Problem:
The scan path needs to detect bad/error links and make it clear what happened.

Tasks:

- Validate URL before request:
  - must be GitHub repo URL
  - must include owner/repo
  - no issue/PR/blob/tree URLs unless converted or rejected clearly
- Show inline error under the input.
- If user pastes a GitHub issue/PR/blob URL, offer a cleaner message:
  "Use the repo URL, e.g. https://github.com/org/repo."
- Avoid leaving stale results looking like a new scan succeeded.

Acceptance:

- Invalid URL never silently falls back to old sample content.
- Error message is short and specific.
- Valid example URL always scans or reports provider/API failure cleanly.

### 5. Loading Animation

Problem:
If the scan takes a while, the current loading state is too plain.

Tasks:

- Add a simple loading animation during scan.
- Use a known lightweight GitHub-style loader pattern or CSS-only spinner/skeleton.
- Loading should show the stages:
  - fetching repo
  - scanning config
  - reviewing install posture
- Keep animation restrained; no flashy marketing effect.

Acceptance:

- User can tell the scan is still running.
- Loading state does not shift layout or hide the input.

### 6. Risk Signals Should Be 1-3 And Color Coded

Problem:
Risk signals are too numerous and not visually ranked.

Tasks:

- Collapse risk signals to max 3 primary risks.
- Color-code them:
  - green: low/okay/controlled
  - yellow: review/sandbox
  - red: block/high danger
- Use clear labels rather than raw internal category names where possible.
- Keep detailed rule/finding evidence available in a secondary panel.

Acceptance:

- The primary risk section shows 1-3 items max.
- Each item has a color and simple severity label.
- Raw detailed findings are not the first thing users see.

### 7. Clarify Parsed Config And Evidence Sections

Problem:
Bottom sections are unclear:

- "Parsed config"
- "Evidence / safe workflow notes"

Tasks:

- Rename sections in user-facing terms:
  - "What the tool can access" instead of "Parsed config"
  - "Why we flagged it" or "Evidence behind the verdict" instead of "Safe workflow notes"
- Add short one-line purpose text for each section.
- Consider moving both into tabs or collapsible panels:
  - Summary
  - Access
  - Evidence
  - Agent instructions
- Keep default view minimal; detailed evidence should be available but not loud.

Acceptance:

- A user knows why the section exists without reading docs.
- The page still supports credibility/evidence for judges.
- The bottom does not feel like raw scanner output dumped into the UI.

## Implementation Update

Date: 2026-05-25

Completed in this pass:

- Replaced ambiguous hero actions with one primary stateful action:
  - empty field: `Test example`
  - filled field: `Scan now`
  - saved model fixture: secondary `Saved Gemma proof`
- Empty-field example now calls `/api/scan` against the public demo repo instead
  of only loading static JSON.
- Added client-side GitHub repo URL validation for non-GitHub URLs and issue,
  PR, blob, or branch links.
- Added inline errors and clears stale rendered results after scan failure.
- Added a compact loading state with fetching/scanning/reviewing stages.
- Successful scans and template/proof loads scroll to the verdict and move focus
  to the result heading.
- Reduced visible copy in the hero, model/workflow strips, scanner checks, and
  bottom sections.
- Renamed bottom sections to `What the tool can access` and `Why we flagged it`.
- Limited primary risk signals to three and color-coded them green/yellow/red.
- Updated `docs/demo-script.md` and `docs/dev-submission-draft.md` for the new
  button labels.

Verification run:

- `node --check public/app.js`
- `python3 -m py_compile remediation_pr_body.py remediation_apply.py remediation_approval.py remediation_renderer.py drift_watch.py runtime_telemetry.py policy.py surface_map.py server.py api/scan.py mcp_server.py scripts/mcp_workflow_smoke.py`
- `python3 -m unittest discover -s tests -v` -> 70 tests passed.
- Local browser QA with Playwright at `http://127.0.0.1:8787`:
  - desktop screenshot: `/tmp/asm-ux-desktop.png`
  - post-example-scroll screenshot: `/tmp/asm-ux-after-scan.png`
  - mobile screenshot: `/tmp/asm-ux-mobile.png`
  - confirmed initial button `Test example`, filled button `Scan now`, PR URL
    error message, loading stages, completed example scan, and nonzero scroll to
    results.

Current local server:

- `python3 server.py` was started on `http://127.0.0.1:8787` during QA.

Production deployment:

- Deployed with `vercel deploy --prod --yes`.
- Production alias: `https://gemma-agent-surface-map.vercel.app`
- Deployment URL:
  `https://gemma-agent-surface-c3ovpoqxl-dodge1218s-projects.vercel.app`
- Vercel inspect URL:
  `https://vercel.com/dodge1218s-projects/gemma-agent-surface-map/3AzpoFVyTGjKzAnZoPeQJtLQnMGK`
- Live smoke checks confirmed the deployed HTML/JS include `Test example`,
  `Scan now`, `Saved Gemma proof`, `What the tool can access`, and
  `Why we flagged it`.
- Live Playwright check saved `/tmp/asm-live-ux.png` and confirmed the invalid
  PR URL message.

### 8. Preserve Gemma Challenge Compliance

Problem:
Previous UI exposed fallback text too prominently. That was fixed, but future
UX cleanup must not reintroduce it.

Tasks:

- Default public load must remain the verified Gemma review or an actual live
  Gemma result.
- Never show "Gemma was not used" in the primary judge path.
- If provider fallback appears, label it as fallback and include a visible route
  back to saved Gemma proof.

Acceptance:

- First page load shows `review_source: "gemma"` data.
- The judge can inspect a Gemma-produced review without depending on provider
  availability.

## Suggested Implementation Order

1. Fix button model and scan flow in `public/app.js`.
2. Add scroll/focus-to-results after successful render.
3. Add validation and inline error state.
4. Reduce text in `public/index.html`.
5. Update `public/styles.css` for compact layout, side panel/drawer, loader, and
   risk chips.
6. Adjust render functions to show top 3 colored risk signals.
7. Rename bottom sections and hide detail behind tabs/collapsible panels.
8. Run:
   - `node --check public/app.js`
   - `python3 -m unittest discover -s tests -v`
   - live/local screenshot pass at desktop and mobile widths.

## Files Most Likely To Change

- `public/index.html`
- `public/app.js`
- `public/styles.css`
- `public/verified-gemma-review.json` only if the displayed proof fields need
  better summary copy.
- `docs/dev-submission-draft.md` if button names or demo instructions change.

## Current Product Constraint

Do not turn this back into a marketing page. It is an app surface. The better
direction is a compact scanner/result UI with a small side rail for explanation,
not more homepage copy.
