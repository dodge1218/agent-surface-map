# Design Decision

## Direction

Agent Surface Map should feel like a developer portfolio piece, not a generic SaaS dashboard.

The page uses:

- Google-inspired blue/red/yellow/green accents for Gemma challenge fit.
- Warm paper background and fine grid texture for a studio/workbench feel.
- Custom SVG brush strokes as the primary visual asset.
- A glass verdict tile for the install decision.
- A terminal chip to keep the product grounded in developer workflow.

## Website SOP Notes

- No new package was added for this polish pass.
- Custom CSS is used because the project is a small static HTML/CSS/JS deployment and no approved component system is currently installed.
- No stock image is used. The SOP allows abstract/geometric visuals when no real product imagery exists.
- UI remains focused on the primary conversion path: paste repo URL, scan, review Gemma 4 verdict.

## Palette

- Ink: `#1b1c1f`
- Paper: `#fffaf2`
- Google blue: `#1a73e8`
- Google red: `#ea4335`
- Google yellow: `#fbbc04`
- Google green: `#34a853`

## Verification

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile surface_map.py server.py api/scan.py mcp_server.py
node --check public/app.js
```

