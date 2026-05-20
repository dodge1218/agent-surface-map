# Assets

Generated demo assets for the submission.

Current assets:

- `agent-surface-map-home.png` — current homepage screenshot.
- `agent-surface-map-demo.mp4` — silent 18-second teaser made from the current UI screenshot.

Recommended capture command:

```bash
python3 server.py
google-chrome --headless --disable-gpu --no-sandbox --window-size=1440,1100 --screenshot=docs/assets/agent-surface-map-home.png http://localhost:8787
```

Use the screenshot in the DEV post only if it matches the current deployed UI.
