"""Small Fisi HTML entry point; presentation and interaction live in browser assets."""
PAGE = '''<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fisi · Verstehen. Ausprobieren. Nachweisen.</title>
<script src="/static/fisi-style.js"></script></head>
<body><a class="skip" href="#main">Zum Inhalt</a><div id="app"><main class="loading" id="main" tabindex="-1"><h1>Fisi</h1><p>Lernworkspace wird geöffnet …</p><noscript>Für die Lernoberfläche muss JavaScript aktiviert sein.</noscript></main></div>
<div id="notice" role="status" aria-live="polite"></div><script src="/static/fisi.js"></script></body></html>'''
