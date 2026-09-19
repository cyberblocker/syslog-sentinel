#!/usr/bin/env python3
"""Syslog Sentinel: a dependency-free educational collector and offline analyzer."""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
import socket
import socketserver
import sqlite3
import threading
import time

MAX_FRAME = 65535
HEADER = re.compile(r'^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) -(?: (.*))?$', re.S)
LEGACY = re.compile(r'^<(\d{1,3})>([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^: ]+): ?(.*)$', re.S)
FAIL = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)')
OK = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+)')
SEVERITIES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug']


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec='seconds')


def parse(raw, peer, transport, received=None):
    text = raw.decode('utf-8', errors='replace').rstrip('\r\n')
    event = dict(received=time.time() if received is None else received, peer=peer,
                 transport=transport, raw=text, host=peer, app='unknown',
                 message=text, timestamp=None, facility=None, severity=None, parsed=False)
    match = HEADER.match(text)
    if match:
        pri, stamp, host, app, _, _, message = match.groups()
    else:
        match = LEGACY.match(text)
        if not match:
            return event
        pri, stamp, host, app, message = match.groups()
    if int(pri) > 191:
        return event
    event.update(timestamp=stamp, host=host if host != '-' else peer,
                 app=app, message=message or '', facility=int(pri)//8,
                 severity=int(pri)%8, parsed=True)
    return event


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, received REAL, event TEXT)')
        self.db.execute('CREATE INDEX IF NOT EXISTS by_received ON events(received)')
        self.db.commit()

    def add(self, raw, peer, transport):
        event = parse(raw, peer, transport)
        with self.lock:
            self.db.execute('INSERT INTO events(received,event) VALUES (?,?)', (event['received'], json.dumps(event)))
            self.db.commit()

    def close(self):
        self.db.close()


class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                first = self.rfile.read(1)
                if not first:
                    return
                if first.isdigit():
                    prefix = first
                    while True:
                        ch = self.rfile.read(1)
                        if ch == b' ':
                            break
                        if not ch.isdigit() or len(prefix) >= 5:
                            return
                        prefix += ch
                    length = int(prefix)
                    if not 0 < length <= MAX_FRAME:
                        return
                    frame = self.rfile.read(length)
                    if len(frame) != length:
                        return
                else:
                    frame = first + self.rfile.readline(MAX_FRAME)
                    if len(frame) > MAX_FRAME:
                        return
                self.server.store.add(frame, self.client_address[0], 'tcp')
        except (TimeoutError, ConnectionError):
            return


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.store.add(self.request[0], self.client_address[0], 'udp')


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPServer(socketserver.UDPServer):
    allow_reuse_address = True
    max_packet_size = MAX_FRAME


def servers(store, bind, port):
    tcp = TCPServer((bind, port), TCPHandler)
    try:
        udp = UDPServer((bind, tcp.server_address[1]), UDPHandler)
    except Exception:
        tcp.server_close()
        raise
    for server in (tcp, udp):
        server.store = store
    return tcp, udp


def collect(args):
    store = Store(args.db)
    pair = servers(store, args.bind, args.port)
    for server in pair:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f'Listening on {args.bind}:{args.port} TCP + UDP. Database: {args.db}', flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in pair:
            server.shutdown()
            server.server_close()
        # Daemon handlers may still be completing a frame; process exit closes DB.


def send(host, port, transport, messages):
    if transport == 'tcp':
        with socket.create_connection((host, port), timeout=5) as sock:
            for message in messages:
                payload = message.encode()
                sock.sendall(str(len(payload)).encode() + b' ' + payload)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for message in messages:
                sock.sendto(message.encode(), (host, port))
                time.sleep(0.02)


def demo_messages():
    stamp = utc(time.time())
    events = [('web-01', 'heartbeat', 'status=ok synthetic=true'),
              ('fw-01', 'firewall', 'DENY src=198.51.100.23 dst=192.0.2.10 dport=22 synthetic=true')]
    events += [('web-01', 'sshd', f'Failed password for invalid user admin from 198.51.100.23 port {45000+i} ssh2 synthetic=true') for i in range(6)]
    events += [('web-01', 'sshd', 'Accepted password for admin from 198.51.100.23 port 45010 ssh2 synthetic=true')]
    return [f'<{84 if app == "sshd" else 134}>1 {stamp} {host} {app} - - - {msg}' for host, app, msg in events]


def read_events(path):
    if not Path(path).is_file():
        raise SystemExit(f'No database at {path}. Start the collector and send events first.')
    with sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True) as db:
        rows = db.execute('SELECT id,event FROM events ORDER BY received,id').fetchall()
    return [dict(json.loads(payload), id=event_id) for event_id, payload in rows]


def analyze(events, expected, now=None, silence=120):
    now = time.time() if now is None else now
    windows = defaultdict(deque)
    findings = []
    last_seen = {}
    for event in sorted(events, key=lambda e: (e['received'], e['id'])):
        host, stamp = event['host'], event['received']
        last_seen[host] = max(last_seen.get(host, stamp), stamp)
        if not event['parsed'] or not re.fullmatch(r'sshd(?:\[\d+\])?', event['app']):
            continue
        failure, success = FAIL.search(event['message']), OK.search(event['message'])
        match = failure or success
        if not match:
            continue
        user, source = match.groups()
        key = (host, user, source)
        window = windows[key]
        while window and stamp - window[0]['received'] > 60:
            window.popleft()
        if failure:
            window.append(event)
            if len(window) == 5:
                findings.append(dict(rule='SSH-001', level='medium', host=host,
                    detail=f'5 failures in 60 seconds for {user} from {source}. Investigate possible password guessing.',
                    evidence=[e['id'] for e in window]))
        elif len(window) >= 5:
            findings.append(dict(rule='SSH-002', level='high', host=host,
                detail=f'Successful login after repeated failures for {user} from {source}. Validate whether authorized.',
                evidence=[e['id'] for e in window] + [event['id']]))
            window.clear()
    health = []
    for host in expected:
        age = now - last_seen[host] if host in last_seen else None
        state = 'never seen' if age is None else ('silent' if age > silence else 'recent')
        health.append(dict(host=host, state=state, age_seconds=None if age is None else max(0, round(age))))
    return dict(generated_at=utc(now), total_events=len(events),
                parsed_events=sum(e['parsed'] for e in events),
                hosts=dict(Counter(e['host'] for e in events)), findings=findings, health=health)


def write_report(events, result, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output/'report.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    esc = lambda value: html.escape(str(value), quote=True)
    cards = ''.join(f'<article><span class="tag">{esc(f["level"])} · {esc(f["rule"])}</span><h3>{esc(f["host"])}</h3><p>{esc(f["detail"])}</p><small>Evidence IDs: {esc(f["evidence"])}</small></article>' for f in result['findings']) or '<article>No SSH rules matched.</article>'
    health = ''.join(f'<tr><td>{esc(h["host"])}</td><td>{esc(h["state"])}</td><td>{esc(h["age_seconds"]) if h["age_seconds"] is not None else "—"}</td></tr>' for h in result['health'])
    rows = ''.join(f'<tr><td>{e["id"]}</td><td>{esc(utc(e["received"]))}</td><td>{esc(e["host"])}</td><td>{esc(e["transport"])}</td><td>{esc(e["app"])}</td><td class="msg">{esc(e["message"])}</td></tr>' for e in events[-200:])
    content = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Syslog Sentinel | CyberBlocker</title>
<style>body{background:#0b1420;color:#e9f0f7;font:16px/1.6 system-ui;margin:0}main{max-width:1140px;margin:auto;padding:48px 24px}header{border-bottom:1px solid #324050;padding-bottom:26px}.eyebrow,.tag{color:#7ae3c6;font-size:12px;letter-spacing:1px;text-transform:uppercase}h1{font-size:48px;margin:8px 0}h2{margin-top:36px}p,small{color:#b8c8d9}.stats,.cards{display:flex;gap:16px;flex-wrap:wrap;margin-top:24px}.stat,article{background:#152334;border:1px solid #2c4056;border-radius:12px;padding:20px;flex:1;min-width:200px}.stat b{display:block;font-size:32px;color:#7ae3c6}.table{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:12px;text-align:left;border-bottom:1px solid #2c4056;vertical-align:top}.msg{min-width:330px;overflow-wrap:anywhere}input{box-sizing:border-box;background:#152334;border:1px solid #61778c;color:white;padding:12px;width:100%;border-radius:8px}footer{margin-top:40px;color:#96abc0;font-size:13px}@media(max-width:600px){h1{font-size:34px}}</style>
<main><header><div class="eyebrow">CyberBlocker / Detection engineering lab</div><h1>Syslog Sentinel</h1><p>Centralized evidence. Visible collection gaps.</p><small>Offline report · Generated at GENERATED</small></header>
<div class="stats"><div class="stat"><b>TOTAL</b>Events collected</div><div class="stat"><b>HOSTS</b>Reported hosts</div><div class="stat"><b>ALERTS</b>SSH findings</div></div>
<h2>Investigation queue</h2><div class="cards">CARDS</div><h2>Expected-source health</h2><p>Recent messages show activity, not verified device identity. Silence can mean inactivity or collection failure.</p><div class="table"><table><thead><tr><th>Expected host</th><th>Status</th><th>Seconds since receipt</th></tr></thead><tbody>HEALTH</tbody></table></div>
<h2>Evidence explorer</h2><p>Last 200 stored events. Filter this table by any displayed value.</p><label for="filter">Search evidence</label><input id="filter" placeholder="Try sshd, web-01, or an IP address"><div class="table"><table><thead><tr><th>ID</th><th>Received UTC</th><th>Host</th><th>Transport</th><th>App</th><th>Message</th></tr></thead><tbody id="events">ROWS</tbody></table></div>
<footer>Educational lab. Findings require analyst review. Report is a snapshot; regenerate after new events. Raw messages remain in SQLite.</footer></main><script>document.querySelector('#filter').addEventListener('input',function(){const q=this.value.toLowerCase();document.querySelectorAll('#events tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q))});</script></html>'''
    for token, value in dict(GENERATED=esc(result['generated_at']), TOTAL=result['total_events'], HOSTS=len(result['hosts']), ALERTS=len(result['findings']), CARDS=cards, HEALTH=health, ROWS=rows).items():
        content = content.replace(token, str(value))
    (output/'report.html').write_text(content, encoding='utf-8')
    print(f'Report: {output / "report.html"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    collector = subs.add_parser('collect', help='Receive TCP and UDP syslog')
    collector.add_argument('--bind', default='127.0.0.1')
    collector.add_argument('--port', type=int, default=5514)
    collector.add_argument('--db', default='data/events.db')
    demo = subs.add_parser('demo', help='Send nine synthetic syslog events')
    demo.add_argument('--host', default='127.0.0.1')
    demo.add_argument('--port', type=int, default=5514)
    demo.add_argument('--transport', choices=['tcp', 'udp'], default='tcp')
    report = subs.add_parser('report', help='Analyze collected events and generate HTML/JSON')
    report.add_argument('--db', default='data/events.db')
    report.add_argument('--inventory', default='inventory.json')
    report.add_argument('--out', default='reports')
    report.add_argument('--silence', type=int, default=120)
    args = parser.parse_args()
    if args.command == 'collect':
        collect(args)
    elif args.command == 'demo':
        send(args.host, args.port, args.transport, demo_messages())
        print('Sent 9 synthetic events. Run the report command to verify receipt.')
    else:
        if args.silence < 1:
            parser.error('--silence must be positive')
        events = read_events(args.db)
        expected = json.loads(Path(args.inventory).read_text(encoding='utf-8'))['expected_hosts']
        result = analyze(events, expected, silence=args.silence)
        write_report(events, result, args.out)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
