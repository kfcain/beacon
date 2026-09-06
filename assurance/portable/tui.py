#!/usr/bin/env python3
"""Read-only Beacon terminal client. Python standard library; no shell execution."""
import argparse
import curses
import json
import os
from pathlib import Path
import stat
import time
import urllib.request
import urllib.parse

LIMIT = 8 * 1024 * 1024
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def clean(value):
    return ''.join(c if c.isprintable() else ' ' for c in str(value))

def load_snapshot(args):
    if args.snapshot:
        with open(args.snapshot, 'rb') as file:
            raw = file.read(LIMIT + 1)
    else:
        url = urllib.parse.urlsplit(args.url)
        if url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
            raise ValueError('Use an API origin without credentials or path')
        if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost', '::1')):
            raise ValueError('Remote API access requires HTTPS')
        if not args.token_file:
            raise ValueError('A private --token-file is required for API mode')
        info = os.lstat(args.token_file)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Token file must be a private regular file (0600)')
        token = Path(args.token_file).read_text().strip()
        if len(token) < 32 or '\n' in token or '\r' in token:
            raise ValueError('Invalid API token')
        request = urllib.request.Request(args.url.rstrip('/') + '/api/beacon', headers={'Authorization': 'Bearer ' + token})
        with urllib.request.build_opener(NoRedirect).open(request, timeout=10) as response:
            raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('Response too large')
    data = json.loads(raw)
    state = data.get('state', data)
    if state.get('schema') != 'beacon.workspace.v1':
        raise ValueError('Unsupported Beacon workspace')
    return state

def rows_for(state, view):
    if view == 'Infrastructure':
        return [{'label': r['id'], 'status': r['status'], 'context': b['manifest']['name'], 'detail': {'boundary': b['manifest'], 'resource': r, 'provenance': b.get('observed', {}).get('provenance', 'MISSING') if b.get('observed') else 'MISSING'}}
                for b in state.get('infrastructureView', {}).get('boundaries', []) for r in b['rows']]
    if view == 'Claims':
        return [{'label': c['id'] + ' ' + c['title'], 'status': c.get('current', {}).get('status', 'UNKNOWN'), 'context': c['owner'], 'detail': c} for c in state.get('claims', [])]
    return [{'label': p['docId'] + ' v' + str(p['version']), 'status': 'REVIEW', 'context': str(len(p['report']['statements'])) + ' statements', 'detail': p} for p in state.get('policies', [])]

def screen(stdscr, args):
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(500)
    views = ['Infrastructure', 'Claims', 'Policies']
    view, selected, query, details, offset = 0, 0, '', False, 0
    state, error, refreshed, next_refresh = {}, '', 0, 0
    while True:
        if time.monotonic() >= next_refresh:
            try:
                state = load_snapshot(args)
                error = ''
                refreshed = time.time()
            except Exception as exc:
                error = 'Refresh failed; retained data is not current: ' + clean(exc)
            next_refresh = time.monotonic() + args.refresh
        rows = [r for r in rows_for(state, views[view]) if query.lower() in (r['label'] + ' ' + r['context']).lower()]
        selected = min(selected, max(0, len(rows)-1))
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        def line(y, text, style=0):
            if 0 <= y < height-1:
                try: stdscr.addnstr(y, 0, clean(text), max(0, width-1), style)
                except curses.error: pass
        line(0, 'BEACON / ' + views[view] + ' / read-only', curses.A_BOLD)
        line(1, 'Tab views   j/k move   Enter inspect   / filter   r refresh   q back/quit')
        line(2, error or ('Snapshot file (not live)' if args.snapshot else 'API last read: ' + time.strftime('%H:%M:%S', time.localtime(refreshed))))
        line(3, 'Declared scope only | ' + str(len(rows)) + ' rows | filter: ' + query)
        if details and rows:
            text = json.dumps(rows[selected]['detail'], indent=2, ensure_ascii=True).splitlines()
            for n, text_line in enumerate(text[offset:offset+max(0,height-6)]): line(n+5, text_line)
            line(height-2, 'j/k scroll details; q returns to the list.')
        else:
            start = max(0, selected - max(0,height-8))
            for n, row in enumerate(rows[start:start+max(0,height-6)]):
                line(n+5, row['status'].ljust(8) + ' ' + row['label'] + ' | ' + row['context'], curses.A_REVERSE if n+start==selected else 0)
            if not rows: line(5, 'No matching records. Register a boundary or load the GUI capstone demonstration.')
        stdscr.refresh()
        key = stdscr.getch()
        if key in (ord('q'),27):
            if details: details=False
            else: return
        elif key == 9: view=(view+1)%len(views);selected=0;details=False
        elif key in (ord('j'),curses.KEY_DOWN):
            if details: offset=min(offset+1,max(0,len(text)-1))
            else: selected=min(selected+1,max(0,len(rows)-1))
        elif key in (ord('k'),curses.KEY_UP):
            if details: offset=max(0,offset-1)
            else: selected=max(0,selected-1)
        elif key in (10,13): details=not details;offset=0
        elif key == ord('r'): next_refresh=0
        elif key == ord('/'):
            curses.echo()
            try:
                stdscr.move(max(0,height-2),0);stdscr.clrtoeol();stdscr.addstr('Filter: ')
                query=stdscr.getstr(max(0,height-2),8,max(1,min(100,width-10))).decode('utf8',errors='replace')
                selected=0
            finally: curses.noecho()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8787')
    parser.add_argument('--token-file')
    parser.add_argument('--snapshot', help='Inspect a portable CLI status export, without a server')
    parser.add_argument('--refresh', type=int, default=15)
    parser.add_argument('--once', action='store_true', help='Print structured posture once for automation')
    args=parser.parse_args()
    if not 5 <= args.refresh <= 3600: parser.error('Refresh must be 5–3600 seconds')
    try:
        if args.once:
            state=load_snapshot(args)
            print(json.dumps({'scope':state.get('infrastructureView',{}).get('scope','No inventory snapshot'),'infrastructure':rows_for(state,'Infrastructure'),'claims':rows_for(state,'Claims')},ensure_ascii=True))
        else: curses.wrapper(screen,args)
    except (Exception,KeyboardInterrupt) as exc:
        parser.exit(2, clean(exc)+'\n')
if __name__ == '__main__': main()
