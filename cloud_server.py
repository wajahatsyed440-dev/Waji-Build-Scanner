"""Always-on read-only scanner + password-protected mobile web dashboard."""
import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import scanner_core as core

ROOT = Path(os.getenv('DATA_DIR', '/data')).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
STATE = ROOT / 'last_seen.json'
SEEN = ROOT / 'seen_terms.json'
EVENTS = ROOT / 'changes.jsonl'
RESPONSES = ROOT / 'latest_responses.json'
STATUS = {'last_scan': None, 'last_error': '', 'changed': 0, 'status': 'Starting'}
LOCK = threading.RLock()
PASSWORD = os.getenv('DASHBOARD_PASSWORD', '')
TOPIC = os.getenv('NTFY_TOPIC', '')
KEY = os.getenv('API_KEY', '')
PUBLIC_URL = os.getenv('PUBLIC_URL', '').rstrip('/')
PATHS = [core.normalized_endpoint(p) for p in os.getenv('API_PATHS', '/api/builds,/api/old_build').split(',') if p.strip()]
INTERVAL = max(30, int(os.getenv('SCAN_INTERVAL', '60')))
PORT = int(os.getenv('PORT', '8080'))
if not PASSWORD or len(PASSWORD) < 12:
    raise SystemExit('Set DASHBOARD_PASSWORD to a strong password (12+ characters).')
if not TOPIC or not __import__('re').fullmatch(r'[a-zA-Z0-9_-]{12,120}', TOPIC):
    raise SystemExit('Set NTFY_TOPIC to a private random 12-120 character topic.')
if not PATHS:
    raise SystemExit('Set API_PATHS to one or more authorised paths.')
if '/api/builds' in PATHS and not KEY:
    raise SystemExit('Set API_KEY for the /api/builds endpoint, if authorised.')


def notify(events):
    if not events:
        return
    lines = [f'{len(events)} change(s) detected']
    for ev in events[:8]:
        lines.append(f"{ev['type']} | {ev['endpoint']} | {str(ev['field'])[:85]}")
    if len(events) > 8:
        lines.append(f'...plus {len(events)-8} more. Open Full View for every change.')
    headers = {'Title': 'Waji Build Scanner - Changes', 'Priority': 'high',
               'Tags': 'mag', 'Content-Type': 'text/plain; charset=utf-8'}
    if PUBLIC_URL.startswith('https://'):
        headers['Click'] = PUBLIC_URL + '/'
    req = Request('https://ntfy.sh/' + TOPIC, data='\n'.join(lines).encode(), headers=headers, method='POST')
    with urlopen(req, timeout=15) as r:
        r.read(1024)


def scan_once():
    with LOCK:
        states = core.load_json(STATE, {})
        seen = set(core.load_json(SEEN, []))
        latest = core.load_json(RESPONSES, {})
    detected, errors = [], []
    for path in PATHS:
        try:
            payload = core.fetch_endpoint(path, KEY)
            now = core.stamp()
            previous = states.get(path)
            differences = core.changes(previous, payload) if previous is not None else []
            tracked = core.analyse_leaks(previous, payload, seen) if previous is not None else []
            seen.update(core.detect_terms(payload))
            latest[path] = {'observed_at': now, 'response': payload}
            for typ, token, group in tracked:
                detected.append({'timestamp': now, 'endpoint': path, 'type': typ, 'field': token,
                                 'old': group, 'new': 'Watchlist match'})
            for typ, field, old, new in differences:
                detected.append({'timestamp': now, 'endpoint': path, 'type': typ, 'field': field, 'old': old, 'new': new})
            states[path] = payload
        except Exception as exc:
            errors.append(f'{path}: {exc}')
    with LOCK:
        core.save_json(STATE, states)
        core.save_json(SEEN, sorted(seen))
        core.save_json(RESPONSES, latest)
        if detected:
            with EVENTS.open('a', encoding='utf-8') as stream:
                for event in detected:
                    stream.write(json.dumps(event, ensure_ascii=False, default=str) + '\n')
        STATUS.update(last_scan=core.stamp(), last_error='; '.join(errors), changed=len(detected),
                      status='Online' if not errors else 'Some API requests failed')
    if detected:
        try:
            notify(detected)
        except Exception as exc:
            with LOCK:
                STATUS['last_error'] += f' | Notification error: {exc}'
    return detected


def scan_loop():
    while True:
        try:
            scan_once()
        except Exception as exc:
            with LOCK:
                STATUS['last_error'] = 'Scan error: ' + str(exc)
                STATUS['status'] = 'Error'
        time.sleep(INTERVAL)


def render_page():
    with LOCK:
        status = dict(STATUS)
        latest = core.load_json(RESPONSES, {})
        events = []
        if EVENTS.exists():
            # Show most recent 500 records; full log remains downloadable as JSON.
            from collections import deque
            with EVENTS.open(encoding='utf-8') as f:
                for line in deque(f, maxlen=500):
                    try: events.append(json.loads(line))
                    except ValueError: pass
    events.reverse()
    esc = lambda x: html.escape(str(x), quote=True)
    panels = []
    for path, item in latest.items():
        body = esc(json.dumps(item['response'], ensure_ascii=False, indent=2))
        panels.append(f'<details class="card"><summary>Full API response: {esc(path)} · {esc(item["observed_at"])}</summary><pre>{body}</pre></details>')
    records = []
    for ev in events:
        full = esc(json.dumps({'old': ev.get('old'), 'new': ev.get('new')}, ensure_ascii=False, indent=2))
        records.append(f'<details class="event"><summary><b>{esc(ev["type"])}</b> · {esc(ev["field"])}<small>{esc(ev["timestamp"])} · {esc(ev["endpoint"])}</small></summary><pre>{full}</pre></details>')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Waji Scanner · Full View</title>
<style>body{{margin:0;background:#0b1326;color:#eaf1ff;font:15px system-ui,sans-serif}}header{{padding:22px 16px;background:#152344;position:sticky;top:0;z-index:1}}h1{{font-size:22px;margin:0 0 7px;color:#83b9ff}}main{{max-width:950px;margin:auto;padding:15px}}.card,.event{{background:#182844;border:1px solid #314366;border-radius:12px;margin:10px 0;padding:14px}}summary{{cursor:pointer;overflow-wrap:anywhere}}small{{display:block;color:#a5b8db;margin-top:7px}}pre{{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:#0e1930;padding:12px;border-radius:9px;font-size:12px}}a{{color:#a9ccff}}.stats{{background:#21345b;padding:12px;border-radius:12px}}.muted{{color:#a5b8db}}input{{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;background:#0d1b34;color:white;border:1px solid #4f6183}}</style></head>
<body><header><h1>Waji Build Scanner · Full View</h1><span class="muted">Cloud monitor — refresh to see the latest results</span></header><main><div class="stats"><b>Status: {esc(status['status'])}</b><p>Last scan (UTC): {esc(status['last_scan'] or 'Not yet')}<br>Changes last scan: {status['changed']}<br>Scan interval: {INTERVAL} seconds</p><small>{esc(status['last_error'])}</small></div>
<h2>All latest API responses</h2>{''.join(panels) or '<p>No responses yet. The first scan builds a baseline.</p>'}
<h2>Detection history</h2><p class="muted">Most recent 500 detections are shown here. Full records are available in <a href="/events.json">events.json</a>.</p><input type="search" id="filter" placeholder="Search changes..." oninput="document.querySelectorAll('.event').forEach(e=>e.hidden=!e.textContent.toLowerCase().includes(this.value.toLowerCase()))">{''.join(records) or '<p>No changes yet. The first scan is a baseline.</p>'}
</main></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Basic authentication is only safe over HTTPS (provided by the cloud host).
        auth = self.headers.get('Authorization', '')
        expected = 'Basic ' + base64.b64encode(('waji:' + PASSWORD).encode()).decode()
        if not hmac.compare_digest(auth, expected):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Waji Scanner Private Dashboard"')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            return
        path = urlparse(self.path).path
        if path == '/':
            data = render_page().encode('utf-8')
            ctype = 'text/html; charset=utf-8'
        elif path == '/events.json':
            with LOCK:
                data = EVENTS.read_bytes() if EVENTS.exists() else b''
            ctype = 'application/x-ndjson; charset=utf-8'
        elif path == '/latest.json':
            with LOCK:
                data = RESPONSES.read_bytes() if RESPONSES.exists() else b'{}'
            ctype = 'application/json; charset=utf-8'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)


if __name__ == '__main__':
    threading.Thread(target=scan_loop, daemon=True).start()
    print(f'Web dashboard on port {PORT}. Interval {INTERVAL}s. Monitoring {PATHS}', flush=True)
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
