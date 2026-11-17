"""Waji Build Scanner v5: authorised, read-only API monitor and detailed mobile dashboard."""
import base64
from collections import Counter, deque
import datetime as dt
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import scanner_core as core

ROOT = Path(os.getenv('DATA_DIR', '/data')).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
STATE, SEEN = ROOT/'last_seen.json', ROOT/'seen_terms.json'
EVENTS, RESPONSES = ROOT/'changes.jsonl', ROOT/'latest_responses.json'
SCANS = ROOT/'scan_history.jsonl'
LOCK = threading.RLock()
SCAN_LOCK = threading.Lock()
PASSWORD = os.getenv('DASHBOARD_PASSWORD', '')
TOPIC = os.getenv('NTFY_TOPIC', '')
KEY = os.getenv('API_KEY', '')
PUBLIC_URL = os.getenv('PUBLIC_URL', '').rstrip('/')
PATHS = list(dict.fromkeys(core.normalized_endpoint(p) for p in os.getenv('API_PATHS', '/api/script').split(',') if p.strip()))
INTERVAL = max(30, int(os.getenv('SCAN_INTERVAL', '60')))
PORT = int(os.getenv('PORT', '8080'))
STATUS = {'last_scan': None, 'last_error': '', 'changed': 0, 'status': 'Starting', 'scanning': False, 'notification': 'Not sent yet'}
if not PASSWORD or len(PASSWORD) < 12:
    raise SystemExit('Set DASHBOARD_PASSWORD to a strong password (12+ characters).')
if not TOPIC or not re.fullmatch(r'[a-zA-Z0-9_-]{12,120}', TOPIC):
    raise SystemExit('Set NTFY_TOPIC to a random 12-120 character topic.')
if not PATHS:
    raise SystemExit('Set API_PATHS to one or more authorised paths.')
if not KEY:
    raise SystemExit('Set API_KEY to an authorised API key in Railway Variables.')


def write_line(path, value):
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(value, ensure_ascii=False, default=str) + '\n')


def tail_jsonl(path, n=100):
    if not path.exists():
        return []
    with path.open(encoding='utf-8') as f:
        lines = deque(f, maxlen=n)
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def values_preview(value, length=350):
    s = json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value
    return s[:length] + ('…' if len(s) > length else '')


def data_size(payload):
    return len(json.dumps(payload, ensure_ascii=False, default=str).encode('utf-8'))


def notify(events):
    """Use ntfy's JSON publish API. Only send field paths, not raw values or credentials."""
    if not events:
        return
    message = [f'{len(events)} detected change(s) across configured endpoints.']
    for ev in events[:8]:
        message.append(f"{ev['type']}: {ev['endpoint']} → {str(ev['field'])[:85]}")
    if len(events) > 8:
        message.append(f'And {len(events)-8} more; open dashboard for full details.')
    body = {'topic': TOPIC, 'title': 'Waji Scanner — Changes',
            'message': '\n'.join(message)[:3500], 'priority': 4, 'tags': ['mag']}
    if PUBLIC_URL.startswith('https://'):
        body['click'] = PUBLIC_URL + '/'
    req = Request('https://ntfy.sh/', data=json.dumps(body).encode('utf-8'), method='POST',
                  headers={'Content-Type': 'application/json'})
    with urlopen(req, timeout=15) as r:
        r.read(1024)


def scan_once():
    if not SCAN_LOCK.acquire(blocking=False):
        return False
    try:
        with LOCK:
            STATUS['scanning'] = True
            states = core.load_json(STATE, {})
            seen = set(core.load_json(SEEN, []))
            latest = core.load_json(RESPONSES, {})
        detected, records, errors = [], [], []
        for path in PATHS:
            start = time.monotonic()
            now = core.stamp()
            try:
                payload = core.fetch_endpoint(path, KEY)
                now = core.stamp()
                previous = states.get(path)
                initial = previous is None
                differences = [] if initial else core.changes(previous, payload)
                tracked = [] if initial else core.analyse_leaks(previous, payload, seen)
                all_terms = core.detect_terms(payload)
                # Mark string matches without duplicating the normal JSON-path change count.
                for typ, token, group in tracked:
                    detected.append({'timestamp': now, 'endpoint': path, 'type': typ,
                                     'category': group, 'field': token,
                                     'old': None, 'new': None})
                for typ, field, old, new in differences:
                    detected.append({'timestamp': now, 'endpoint': path, 'type': typ,
                                     'category': 'API field', 'field': field,
                                     'old': old, 'new': new})
                current_hash = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode('utf-8')).hexdigest()
                latest[path] = {'observed_at': now, 'response': payload, 'sha256': current_hash}
                records.append({'timestamp': now, 'endpoint': path, 'ok': True, 'baseline': initial,
                                'changes': len(differences), 'watchlist_changes': len(tracked),
                                'watch_terms_present': len(all_terms),
                                'watch_terms': [core.watch_terms().get(t, (t, 'Other'))[0] for t in sorted(all_terms)],
                                'bytes': data_size(payload), 'sha256': current_hash,
                                'duration_ms': round((time.monotonic()-start)*1000), 'error': ''})
                states[path] = payload
                seen.update(all_terms)
            except Exception as exc:
                err = f'{type(exc).__name__}: {exc}'
                errors.append(f'{path}: {err}')
                records.append({'timestamp': now, 'endpoint': path, 'ok': False, 'baseline': False,
                                'changes': 0, 'watchlist_changes': 0, 'watch_terms_present': 0,
                                'watch_terms': [], 'bytes': 0, 'sha256': '',
                                'duration_ms': round((time.monotonic()-start)*1000), 'error': err})
        with LOCK:
            core.save_json(STATE, states)
            core.save_json(SEEN, sorted(seen))
            core.save_json(RESPONSES, latest)
            for event in detected:
                write_line(EVENTS, event)
            for record in records:
                write_line(SCANS, record)
            STATUS.update(last_scan=core.stamp(), last_error='; '.join(errors),
                          changed=len(detected), status='Online' if not errors else 'Some API requests failed')
        if detected:
            try:
                notify(detected)
                with LOCK:
                    STATUS['notification'] = f'Sent at {core.stamp()}'
            except Exception as exc:
                with LOCK:
                    STATUS['notification'] = 'Failed: ' + str(exc)
        return True
    finally:
        with LOCK:
            STATUS['scanning'] = False
        SCAN_LOCK.release()


def scan_loop():
    while True:
        try:
            scan_once()
        except Exception as exc:
            with LOCK:
                STATUS.update(status='Error', last_error=f'Unexpected scan error: {exc}')
        time.sleep(INTERVAL)


def esc(value):
    return html.escape(str(value), quote=True)


def json_html(value):
    return esc(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def render_page():
    with LOCK:
        status = STATUS.copy()
        latest = core.load_json(RESPONSES, {})
        events = tail_jsonl(EVENTS, 500)
        scans = tail_jsonl(SCANS, 300)
    counts = Counter(e.get('type', '') for e in events)
    panels = []
    for path in PATHS:
        item = latest.get(path)
        row = next((x for x in reversed(scans) if x['endpoint'] == path), None)
        health = 'No scan yet' if row is None else ('OK' if row['ok'] else 'ERROR')
        details = (f"{row['duration_ms']}ms · {row['bytes']:,} bytes · "
                   f"{row['watch_terms_present']} watch terms · {row['changes']} changes"
                   if row and row['ok'] else (row.get('error', '') if row else 'Awaiting first scan'))
        if item is None:
            panels.append(f'<section class="card"><h3>{esc(path)}</h3><p>{esc(health)} — {esc(details)}</p></section>')
            continue
        terms = ', '.join(row.get('watch_terms', [])) if row and row['ok'] else '(none found in last successful scan)'
        panels.append(f'''<section class="card"><h3>{esc(path)} <span class="pill">{esc(health)}</span></h3>
        <p class="sub">{esc(details)} · Captured {esc(item.get('observed_at',''))}</p>
        <p class="sub">SHA-256: <code>{esc(item.get('sha256','unknown'))}</code></p>
        <details><summary>Watchlist IDs detected</summary><p>{esc(terms or 'None')}</p></details>
        <details><summary>Full latest API response (JSON or text)</summary><pre>{json_html(item.get('response'))}</pre></details></section>''')
    event_html = []
    for e in reversed(events):
        old, new = e.get('old'), e.get('new')
        fields = f'<div class="comparison"><div><b>Previous</b><pre>{json_html(old)}</pre></div><div><b>Current</b><pre>{json_html(new)}</pre></div></div>'
        event_html.append(f'''<details class="event" data-type="{esc(e.get('type',''))}"><summary>
        <b>{esc(e.get('type',''))}</b> · {esc(e.get('field',''))}
        <small>{esc(e.get('timestamp',''))} UTC · {esc(e.get('endpoint',''))} · {esc(e.get('category',''))}</small></summary>
        {fields}</details>''')
    scan_rows = []
    for s in reversed(scans[-100:]):
        scan_rows.append(f'''<tr><td>{esc(s['timestamp'])}</td><td>{esc(s['endpoint'])}</td>
        <td>{'OK' if s['ok'] else 'ERROR'}</td><td>{esc(s['changes'])}</td>
        <td>{esc(s['duration_ms'])}ms</td><td>{esc(s.get('error','') or ('Baseline' if s['baseline'] else ''))}</td></tr>''')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Waji Scanner v6 · Detailed View</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0c1427;color:#eaf1ff;font:15px system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.5}}
header{{padding:20px 16px;background:#172748;border-bottom:1px solid #31466a}}h1{{font-size:23px;margin:0;color:#99c5ff}}h2{{font-size:19px;margin:24px 0 10px}}h3{{font-size:16px;margin:0 0 5px;overflow-wrap:anywhere}}
main{{max-width:1100px;margin:auto;padding:16px}}.card,.event,.stats{{background:#172640;border:1px solid #314463;border-radius:12px;padding:14px;margin:10px 0}}
.stats{{background:#1c3155}}.sub,small{{color:#abc0df;font-size:12px}}small{{display:block;margin-top:5px}}pre{{padding:12px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:450px;overflow:auto;border-radius:8px;background:#0c182e;font-size:12px}}summary{{cursor:pointer;overflow-wrap:anywhere;padding:5px 0}}
a{{color:#a9cbff}}button{{background:#377ad6;color:#fff;border:0;border-radius:8px;padding:10px 14px;font-weight:650;cursor:pointer}}
form{{display:inline-block;margin-top:10px}}.pill{{font-size:12px;border-radius:20px;padding:3px 8px;background:#2b4367}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}}.metric{{padding:13px;border-radius:10px;background:#25395e}}
.metric b{{display:block;font-size:22px}}.comparison{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:9px}}input,select{{width:100%;padding:11px;border:1px solid #51688d;border-radius:8px;color:#fff;background:#101e37;margin:5px 0}}
table{{width:100%;border-collapse:collapse;font-size:12px}}td,th{{border-bottom:1px solid #384b6d;padding:8px;vertical-align:top;text-align:left;overflow-wrap:anywhere}}.scroll{{overflow:auto}}code{{overflow-wrap:anywhere}}[hidden]{{display:none!important}}
</style></head><body><header><h1>Waji Build Scanner · Detailed View</h1><div class="sub">Read-only cloud API monitor · {esc(core.BASE)} · {len(PATHS)} configured endpoint(s)</div></header><main>
<div class="stats"><strong>Status: {esc(status['status'])}</strong><div class="sub">Last scan (UTC): {esc(status['last_scan'] or 'Not yet')} · Interval: {INTERVAL} seconds · Scanning now: {'Yes' if status['scanning'] else 'No'}</div>
<div class="grid"><div class="metric">Last scan changes<b>{status['changed']}</b></div><div class="metric">Recent added<b>{counts['ADDED']}</b></div><div class="metric">Recent removed<b>{counts['REMOVED']}</b></div><div class="metric">Recent modified<b>{counts['CHANGED']}</b></div></div>
<div class="sub">Notifications: {esc(status['notification'])}</div><div class="sub">Errors: {esc(status['last_error'] or 'None reported')}</div>
<form action="/scan-now" method="post"><button type="submit">Scan now</button></form> <a href="/scan-history.json">Download scan history</a> · <a href="/events.json">Download detections</a></div>
<h2>Endpoint health and full responses</h2>{''.join(panels)}
<h2>Detailed change history</h2><div class="sub">Showing up to 500 latest events. Previous and current values are visible only after login. First scan establishes baseline.</div>
<input id="filter" placeholder="Search path, endpoint, type, time..." aria-label="Search detection history">
<select id="kind" aria-label="Filter by change type"><option value="">All change types</option><option>ADDED</option><option>REMOVED</option><option>CHANGED</option><option>NEW STRING</option><option>RETURNED</option><option>REMOVED STRING</option></select>
<div id="records">{''.join(event_html) or '<p>No changes detected yet.</p>'}</div>
<h2>Recent scan history</h2><div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Endpoint</th><th>Status</th><th>Changes</th><th>Duration</th><th>Notes</th></tr></thead><tbody>{''.join(scan_rows)}</tbody></table></div>
<p class="sub">This tool monitors only configured, authorised endpoints. It cannot identify undisclosed endpoints or guarantee seeing short-lived changes between scans.</p>
</main><script>
const filter=document.getElementById('filter'),kind=document.getElementById('kind');
function apply(){{document.querySelectorAll('.event').forEach(el=>{{const text=el.textContent.toLowerCase(),q=filter.value.toLowerCase();el.hidden=!(text.includes(q)&&(!kind.value||el.dataset.type===kind.value));}})}}
filter.addEventListener('input',apply);kind.addEventListener('change',apply);
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def authorised(self):
        auth = self.headers.get('Authorization', '')
        expected = 'Basic ' + base64.b64encode(('waji:' + PASSWORD).encode()).decode()
        if hmac.compare_digest(auth, expected):
            return True
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Waji Scanner Private Dashboard"')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        return False

    def respond(self, data, content_type='text/html; charset=utf-8', status=200, extra=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.authorised():
            return
        path = urlparse(self.path).path
        if path == '/':
            self.respond(render_page().encode('utf-8'))
        elif path in ('/events.json', '/latest.json', '/scan-history.json'):
            filename = {'/events.json': EVENTS, '/latest.json': RESPONSES, '/scan-history.json': SCANS}[path]
            with LOCK:
                data = filename.read_bytes() if filename.exists() else (b'{}' if path == '/latest.json' else b'')
            self.respond(data, 'application/json; charset=utf-8' if path == '/latest.json' else 'application/x-ndjson; charset=utf-8')
        else:
            self.respond(b'Not found', 'text/plain', 404)

    def do_POST(self):
        if not self.authorised():
            return
        if urlparse(self.path).path != '/scan-now':
            self.respond(b'Not found', 'text/plain', 404)
            return
        # Reject browser cross-origin form submissions. Non-browser clients must use Basic auth.
        origin = self.headers.get('Origin', '')
        if origin and PUBLIC_URL.startswith('https://') and origin.rstrip('/') != PUBLIC_URL:
            self.respond(b'Origin mismatch', 'text/plain', 403)
            return
        if SCAN_LOCK.locked():
            self.respond(b'Scan already in progress', 'text/plain', 409)
            return
        threading.Thread(target=scan_once, daemon=True).start()
        self.respond(b'Refresh dashboard to view results', 'text/plain', 303, {'Location': '/'})

    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)


if __name__ == '__main__':
    threading.Thread(target=scan_loop, daemon=True).start()
    print(f'Waji v6 on {PORT}, scanning {PATHS} every {INTERVAL}s', flush=True)
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
