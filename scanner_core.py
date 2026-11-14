"""Stumble Guys Waji's Build Scanner — read-only API change monitor."""
import csv
import os
import sys
import secrets
import collections
import datetime as dt
import hashlib
import json
import queue
import re
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, quote
from urllib.request import Request, urlopen

APP = "Stumble Guys Waji's Build Scanner"
BASE = "https://api.sgtourtrack.com"
DATA_DIR = Path.home() / "WajiBuildScanner"
CONFIG_FILE = DATA_DIR / "settings.json"
STATE_FILE = DATA_DIR / "last_seen.json"
EVENTS_FILE = DATA_DIR / "changes.jsonl"
LEAK_EVENTS_FILE = DATA_DIR / "leak_changes.jsonl"
WATCH_FILE = DATA_DIR / "watchlist.json"
SNAP_DIR = DATA_DIR / "snapshots"
DEFAULT_ENDPOINTS = ["/api/builds", "/api/old_build"]
MAX_BODY = 8 * 1024 * 1024
STARTUP_FILE = Path(os.environ.get("APPDATA", str(Path.home()))) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "Waji Build Scanner.cmd"

# User-provided strings are WATCH TERMS, not confirmed live releases.
WATCH_GROUPS = {
    "Wheels": "King_of_Kings_Wheel Collector_Wheel Countdown_Wheel Stumble_Fever_Wheel Boxing_Wheel Loot_Bash_Wheel Snow_Brawl_Wheel All_Stars_Wheel Jingle_Wheel Brrrrr_Wheel Holly_Wheel Noel_Wheel Santastic_Wheel Merry_Loot_Wheel Snowball_Wheel Reindeer_Wheel".split(),
    "Offers": "Rewind_2026_Offer Rewind_Offer Ability_Sale_Offer St_Nicholas_bundles_Offer Ice_Warriors_Offer Bouncing_Bundle_Offer Epic_Jurassic_Offer Legendary_Jurassic_Offer Mythic_Jurassic_Offer Jurassic_Bundle_Offer Naughty_or_Nice_Bundle_Offer Jingle_All_The_Way_Bundle_Offer Cat_Splat_Offer Cat_Splat_Sale_Offer Aqua_Special_Offer Mythic_Xmas_Offer Xmas_Sale_Offer Christmas_Special_Trio_Offer OG_Bundle_Offer Xmas_Ability_Offer Xmas_Ability_Celebration_Offer Mega_Xmas_Bundle_Offer Unboxing_Day_Offer Boxing_Day_Offer Santas_Special_Offer Candy_Cane_Offer Candy_Cane_Bundle".split(),
    "Ranked": [f"Ranked_Season_{i}" for i in range(36,41)],
    "Winter and events": "Winter_Maps_ONLY Santaverse Ho_Ho_Havoc Santa_Box Holiday_Box Ho_Ho_Ho_Box Mega_Box Candy_Canes Holiday_Edition Christmas_Event Santa_Event Spooky_Christmas_Event Winter_Event Winter_Race_Event Christmas_Elimination_Event Ability_Showcase_Love_Bomb_Event Lion_Clash_Dash_Event Frozen_Race_Event Winter_Elimination_Event Laser_Elimination_Event Dino_Blocks_Event Dinosaur_Race_Event Icy_Gravity_Elimination_Event Lava_Snowball_Elimination_Event Jingle_Gnomes_Dash_Event Cold_Water_Race_Event Cookie_Elimination_Event Race_to_the_North_Pole_Event Naughty_or_Nice_Holiday_Dash_Event Santaverse_Elimination_Event Race_All_the_Way_Event".split(),
    "Previously reported missing": "Block_Dash_Town Spectator_Camera_Mode SHOW_OTHER_PLAYER_NAMES SHOW_OWN_PLAYER_NAME ELIMINATED_BY KILL_FEED".split(),
}


def watch_terms():
    """Map exact internal IDs to their collection (case-insensitive)."""
    return {term.lower(): (term, group) for group, terms in WATCH_GROUPS.items() for term in terms}


def detect_terms(response):
    """Look for exact ID tokens in all JSON keys/string values, not just one field."""
    text = json.dumps(response, ensure_ascii=False) if not isinstance(response, str) else response
    found = set()
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_]*", text):
        if token.lower() in watch_terms():
            found.add(token.lower())
    return found


def analyse_leaks(before, after, seen_before=None):
    old, new = detect_terms(before), detect_terms(after)
    seen_before = seen_before or set()
    terms = watch_terms()
    output = []
    for token in sorted(new - old):
        output.append(("RETURNED" if token in seen_before else "NEW STRING", terms[token][0], terms[token][1]))
    for token in sorted(old - new):
        output.append(("REMOVED STRING", terms[token][0], terms[token][1]))
    return output


def recent_snapshots(endpoint, days=7):
    """Use real on-disk captures only; no fake API history."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    captures = []
    for path in SNAP_DIR.glob("*.json"):
        snap = load_json(path, None)
        if not isinstance(snap, dict) or snap.get("endpoint") != endpoint or "response" not in snap:
            continue
        try:
            when = dt.datetime.fromisoformat(snap["observed_at"].replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=dt.timezone.utc)
        except (TypeError, ValueError, KeyError):
            continue
        if cutoff <= when <= dt.datetime.now(dt.timezone.utc):
            captures.append((when, snap["response"]))
    return sorted(captures, key=lambda x: x[0])


def history_report(days=7):
    """Read local snapshots + previous change log within requested UTC window."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    endpoints = set()
    for f in SNAP_DIR.glob("*.json"):
        obj = load_json(f, None)
        if isinstance(obj, dict) and isinstance(obj.get("endpoint"), str):
            endpoints.add(obj["endpoint"])
    found = []
    for endpoint in sorted(endpoints):
        captures = recent_snapshots(endpoint, days)
        prev = None
        seen = set()
        for when, body in captures:
            if prev is not None:
                for kind, token, group in analyse_leaks(prev, body, seen):
                    found.append({"timestamp": when.isoformat(timespec="seconds"), "endpoint": endpoint, "type": kind, "field": token, "old": group, "new": "Historical snapshot comparison"})
            seen.update(detect_terms(body))
            prev = body
    for log_file in (EVENTS_FILE, LEAK_EVENTS_FILE):
        if log_file.exists():
            for line in log_file.read_text(encoding="utf-8").splitlines():
                try:
                    ev = json.loads(line)
                    when = dt.datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
                    if when.tzinfo is None: when = when.replace(tzinfo=dt.timezone.utc)
                    if cutoff <= when <= dt.datetime.now(dt.timezone.utc):
                        found.append(ev)
                except (ValueError, KeyError, TypeError):
                    pass
    # Deduplication: previous live events and reconstructed snapshot events may overlap.
    unique = {}
    for ev in found:
        k = (ev.get("timestamp"), ev.get("endpoint"), ev.get("type"), ev.get("field"))
        unique[k] = ev
    return sorted(unique.values(), key=lambda ev: ev.get("timestamp", ""), reverse=True)



def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def normalized_endpoint(path):
    path = path.strip()
    if not path.startswith("/") or path.startswith("//") or "#" in path or "\\" in path:
        raise ValueError("Endpoints must be paths beginning with /, e.g. /api/builds")
    if urlparse(path).scheme or urlparse(path).netloc:
        raise ValueError("Only paths on api.sgtourtrack.com are supported")
    return path


def fetch_endpoint(path, api_key):
    headers = {"Accept": "application/json, text/plain;q=0.9", "User-Agent": "WajiBuildScanner/1.0"}
    if path.split("?")[0] != "/api/old_build" and api_key:
        headers["x-api-key"] = api_key
    req = Request(BASE + path, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=12) as response:
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ValueError("Response exceeded 8 MB safety limit")
            content = data.decode("utf-8", errors="replace")
            try:
                return json.loads(content)
            except ValueError:
                return content.strip()
    except HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"Connection failed: {exc.reason}") from exc


def notify_phone(topic, events):
    """Send a single compact push per scan cycle, never sending API secrets/values."""
    if not topic or not events:
        return
    if not re.fullmatch(r"[a-zA-Z0-9_-]{12,120}", topic):
        raise ValueError("Notification topic must be 12-120 letters, numbers, _ or -")
    overview = ", ".join(f"{e['type']}: {str(e['field'])[:65]}" for e in events[:5])
    if len(events) > 5:
        overview += f" (+{len(events)-5} more)"
    msg = f"{len(events)} change(s) detected. {overview}"[:1500]
    req = Request(f"https://ntfy.sh/{quote(topic, safe='')}",
                  data=msg.encode("utf-8"), method="POST",
                  headers={"Title": "Waji Build Scanner", "Priority": "default", "Tags": "mag", "Content-Type": "text/plain; charset=utf-8"})
    with urlopen(req, timeout=12) as result:
        result.read(1024)


def flatten(obj, prefix="$", output=None, depth=0):
    if output is None:
        output = {}
    if depth > 24 or len(output) > 20000:
        output[prefix] = "[truncated]"
    elif isinstance(obj, dict):
        if not obj:
            output[prefix] = {}
        for key, value in obj.items():
            flatten(value, f"{prefix}.{key}", output, depth + 1)
    elif isinstance(obj, list):
        if not obj:
            output[prefix] = []
        for i, value in enumerate(obj):
            flatten(value, f"{prefix}[{i}]", output, depth + 1)
    else:
        output[prefix] = obj
    return output


def changes(before, after):
    old = flatten(before)
    new = flatten(after)
    results = []
    for key in sorted(old.keys() | new.keys()):
        if key not in old:
            results.append(("ADDED", key, None, new[key]))
        elif key not in new:
            results.append(("REMOVED", key, old[key], None))
        elif old[key] != new[key]:
            results.append(("CHANGED", key, old[key], new[key]))
    return results


def short(value, width=200):
    s = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return s if len(s) <= width else s[:width] + "…"


