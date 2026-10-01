#!/usr/bin/env python3
"""Run an isolated demo and graph real loopback packets. No plotting dependencies."""
import argparse
import html
import fcntl
import json
import math
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def capture(port, destination):
    # Privilege is needed only to open the packet socket. Drop it immediately.
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind(('lo', 0))
    if 'SUDO_UID' in os.environ:
        os.setgroups([])
        os.setgid(int(os.environ['SUDO_GID']))
        os.setuid(int(os.environ['SUDO_UID']))
    sock.settimeout(0.1)
    with open(destination, 'wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        print('ready', flush=True)
        while not select.select([sys.stdin], [], [], 0)[0]:
            try:
                packet, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            # Linux loopback exposes outgoing and incoming copies. Keep one copy.
            if address[2] != socket.PACKET_OUTGOING or len(packet) < 54 or packet[12:14] != b'\x08\x00':
                continue
            ihl = (packet[14] & 15) * 4
            if packet[23] != 6 or packet[26:34] != b'\x7f\0\0\x01' * 2:
                continue
            source, target = struct.unpack_from('!HH', packet, 14 + ihl)
            if port not in (source, target):
                continue
            now = time.time()
            output.write(struct.pack('<IIII', int(now), int(now % 1 * 1e6), len(packet), len(packet)))
            output.write(packet)
        output.flush()
    sock.close()


def read_packets(path, port):
    packets = []
    with path.open('rb') as source:
        source.read(24)
        while header := source.read(16):
            sec, usec, size, _ = struct.unpack('<IIII', header)
            raw = source.read(size)
            ihl = (raw[14] & 15) * 4
            offset = 14 + ihl
            src, dst, seq = struct.unpack_from('!HHI', raw, offset)
            ip_size = struct.unpack_from('!H', raw, 16)[0]
            tcp_size = (raw[offset + 12] >> 4) * 4
            packets.append(dict(time=sec + usec / 1e6, size=ip_size,
                                payload=ip_size - ihl - tcp_size,
                                direction='agent → server' if dst == port else 'server → agent',
                                agent_port=src if dst == port else dst,
                                flags=raw[offset + 13], sequence=seq))
    return packets


def graph(output, packets, events, connections, handshakes):
    start = min(packets[0]['time'], events[0]['time'])
    duration = max(packets[-1]['time'] - start, 1)
    maximum = max(p['size'] for p in packets)
    view_duration = min(5, duration)
    width, height = 1400, 850 + len(events) * 21
    left, top, plot_w, plot_h = 95, 175, 1240, 380
    x = lambda t: left + (t - start) / view_duration * plot_w
    y = lambda n: top + plot_h * (1 - math.log1p(n) / math.log1p(maximum))
    esc = html.escape
    # Peak packet size in each 100 ms interval; zero means no captured packet.
    series = {}
    for direction in ['agent → server', 'server → agent']:
        bins = {}
        for packet in packets:
            if packet['direction'] == direction:
                bucket = int((packet['time'] - start) / 0.1)
                bins[bucket] = max(bins.get(bucket, 0), packet['size'])
        series[direction] = [[round(i * 0.1, 4), bins.get(i, 0)] for i in range(math.ceil(duration / 0.1))]
    def line(points, limit, panel_top, panel_height):
        return ' '.join(f'{"M" if i == 0 else "L"}{left+t/limit*plot_w:.2f},{panel_top+panel_height*(1-math.log1p(n)/math.log1p(maximum)):.2f}'
                        for i, (t, n) in enumerate((t, n) for t, n in points if t <= limit))
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-label="Packet sizes over time on one TCP connection">',
             '<rect width="100%" height="100%" fill="#fff"/>',
             '<g font-family="sans-serif" fill="#18212f">',
             '<text x="35" y="42" font-size="26">One connection, both directions</text>',
             f'<text x="35" y="73" font-size="16">{connections} TCP stream · {handshakes} initial handshake · {len(packets)} captured packets · {duration:.1f} seconds</text>',
             '<text x="35" y="104" fill="#2563eb">━ Agent → server</text>',
             '<text x="230" y="104" fill="#d97706">━ Server → agent</text>',
             ]
    for i in range(5):
        n = math.expm1(math.log1p(maximum) * i / 4)
        yy = y(n)
        parts += [f'<path class="grid" data-fraction="{i/4}" d="M{left},{yy}h{plot_w}" stroke="#e2e8f0"/>',
                  f'<text class="ytick" data-fraction="{i/4}" x="{left-12}" y="{yy+5}" text-anchor="end" font-size="12">{n:,.0f}</text>']
    for i in range(9):
        xx = left + plot_w * i / 8
        parts.append(f'<text class="xtick" data-fraction="{i/8}" x="{xx}" y="{top+plot_h+25}" text-anchor="middle" font-size="12">{view_duration*i/8:.1f}s</text>')
    parts.append(f'<text id="size-label" x="{left}" y="{top-12}" font-size="13">Bytes (log scale)</text>')
    for i, event in enumerate(events):
        xx = x(event['time'])
        hidden = ' style="display:none"' if xx > left + plot_w else ''
        parts += [f'<g class="event" data-time="{event["time"]-start}"{hidden}><path d="M{xx},{top}v{plot_h}" stroke="#94a3b8" stroke-dasharray="4 5"/>',
                  f'<text x="{xx+3}" y="{top+16+(i%4)*18}" font-size="12">{i+1}</text></g>']
    for direction, points in series.items():
        color = '#2563eb' if direction == 'agent → server' else '#d97706'
        data = esc(json.dumps(points), quote=True)
        parts.append(f'<path class="traffic" data-points="{data}" d="{line(points,view_duration,top,plot_h)}" fill="none" stroke="{color}" stroke-width="2.5"><title>{direction}: largest IPv4 packet in each 100 ms interval; zero means no packet</title></path>')
    overview_top, overview_h = 630, 110
    parts.append('<text x="35" y="605" font-size="16">Full session, including the later heartbeat</text>')
    parts.append(f'<rect x="{left}" y="{overview_top}" width="{plot_w}" height="{overview_h}" fill="#f8fafc" stroke="#cbd5e1"/>')
    for lane, (direction, points) in enumerate(series.items()):
        color = '#2563eb' if direction == 'agent → server' else '#d97706'
        lane_top = overview_top + lane * 60
        label = 'Agent' if lane == 0 else 'Server'
        parts.append(f'<text x="35" y="{lane_top+28}" fill="{color}" font-size="12">{label}</text>')
        parts.append(f'<path d="M{left},{lane_top+45}h{plot_w}" stroke="#cbd5e1"/>')
        parts.append(f'<path d="{line(points,duration,lane_top,45)}" fill="none" stroke="{color}" stroke-width="1.5"/>')
    for i, event in enumerate(events):
        xx = left + (event['time'] - start) / duration * plot_w
        parts.append(f'<path d="M{xx},{overview_top}v{overview_h}" stroke="#94a3b8" stroke-dasharray="3 4"/>')
        parts.append(f'<text x="{xx+3}" y="{overview_top+14+(i%3)*15}" font-size="11">{i+1}</text>')
    for i in range(9):
        xx = left + plot_w * i / 8
        parts.append(f'<text x="{xx}" y="{overview_top+overview_h+20}" text-anchor="middle" font-size="12">{duration*i/8:.1f}s</text>')
    for i, event in enumerate(events):
        parts.append(f'<text x="35" y="{815+i*21}" font-size="13">{i+1}. {event["time"]-start:6.2f}s: {esc(event["label"])}</text>')
    parts += ['</g></svg>']
    svg = '\n'.join(parts)
    (output / 'connection.svg').write_text(svg)
    (output / 'connection.html').write_text('''<!doctype html><meta charset="utf-8"><title>bidi: one connection</title>
<style>body{margin:24px auto;max-width:1450px;font:15px sans-serif;color:#18212f}svg{width:100%;height:auto}p{margin:12px 35px}</style>'''
        + '<p><button onclick="zoom(fullDuration)">Full session</button> <button onclick="zoom(Math.min(5,fullDuration))">First 5 seconds</button> <label><input type="checkbox" id="logscale" checked onchange="scale()"> Log scale for packet sizes</label></p>'
        + svg + '<script>const fullDuration=' + str(duration) + ',maximum=' + str(maximum) + ';'
        + """let visibleDuration=Math.min(5,fullDuration);
        function redraw(){
            const log=document.getElementById('logscale').checked;
            document.querySelectorAll('.traffic').forEach(p=>{
                const points=JSON.parse(p.dataset.points).filter(([t,n])=>t<=visibleDuration);
                p.setAttribute('d',points.map(([t,n],i)=>`${i?'L':'M'}${95+t/visibleDuration*1240},${175+380*(1-(log?Math.log1p(n)/Math.log1p(maximum):n/maximum))}`).join(' '));
            });
        }
        function zoom(duration){
            visibleDuration=duration;redraw();
            document.querySelectorAll('.event').forEach(g=>{
                const t=+g.dataset.time;g.style.display=t>duration?'none':'';
                g.querySelector('path').setAttribute('d',`M${95+t/duration*1240},175v380`);
                g.querySelector('text').setAttribute('x',98+t/duration*1240);
            });
            document.querySelectorAll('.xtick').forEach(t=>t.textContent=(duration*t.dataset.fraction).toFixed(1)+'s');
        }
        function scale(){
            redraw();
            const log=document.getElementById('logscale').checked;
            document.querySelectorAll('.ytick').forEach(t=>{
                const f=+t.dataset.fraction;
                t.textContent=Math.round(log?Math.expm1(f*Math.log1p(maximum)):f*maximum).toLocaleString();
            });
            document.getElementById('size-label').textContent=log?'Bytes (log scale)':'Bytes';
        }</script>"""
        + '<p>Event markers come from the demo and application logs. TLS encrypts the payload, so the capture cannot identify individual actions. Multiple packets may carry one action, and one packet may carry several messages.</p>'
        + '<p>The capture covers the isolated agent/server TCP port on Linux loopback. Local Unix operator commands and plugin child processes are outside this connection. Loopback offloading can produce large captured packets; this is not a physical-network MTU measurement.</p>')


def wait(check, description, processes, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        for proc in processes:
            if proc.poll() is not None:
                raise RuntimeError(f'Process exited during {description}: status {proc.returncode}')
        time.sleep(0.05)
    raise RuntimeError('Timed out: ' + description)


def demo():
    if sys.platform != 'linux':
        raise RuntimeError('Packet capture currently requires Linux')
    privilege = [] if os.geteuid() == 0 else ['sudo', '-n']
    if privilege:
        subprocess.run(privilege + ['true'], check=True, capture_output=True)
    output = ROOT / '.connection-proof'
    output.mkdir(mode=0o700, exist_ok=True)
    lock = (output / 'run.lock').open('w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('Another connection proof is already running')
    for name in ['audit.log', 'connection.html', 'connection.svg', 'events.json']:
        (output / name).unlink(missing_ok=True)
    processes, files, events = [], [], []
    mark = lambda label: events.append(dict(time=time.time(), label=label))
    with tempfile.TemporaryDirectory(prefix='bidi-proof-') as temporary:
        work = Path(temporary)
        capture_proc = None
        try:
            for name in ['scripts', 'examples', 'cmd', 'internal']:
                shutil.copytree(ROOT / name, work / name)
            for name in ['go.mod', 'go.sum', 'permissions.example.json']:
                shutil.copy2(ROOT / name, work / name)
            (work / 'bin').symlink_to(ROOT / 'bin', target_is_directory=True)
            def run(args):
                subprocess.run(args, cwd=work, check=True, stdout=subprocess.DEVNULL)
            print('Preparing isolated certificates and plugins…', flush=True)
            run(['bash', 'scripts/dev-certs.sh'])
            release = work / '.dev-plugins'
            release.mkdir(mode=0o700)
            run([str(ROOT/'bin/plugin-release'), '-keygen', str(release/'publisher.key')])
            for name in ['status', 'echo', 'uptime']:
                run(['go', 'build', '-o', str(release/name), './examples/'+name])
                run([str(ROOT/'bin/plugin-release'), '-key', str(release/'publisher.key'), '-manifest', 'examples/manifests/'+name+'.json', '-artifact', str(release/name), '-out', str(release/(name+'.json'))])
            (release/'publisher-keys.json').write_text(json.dumps({'operations-2026': (release/'publisher.key.pub').read_text().strip()}))
            permissions = {'agent-1': ['status', 'echo', 'uptime.get']}
            (release/'permissions.json').write_text(json.dumps(permissions))
            initial = {'status': '1.0.0', 'echo': '1.0.0'}
            catalog = dict(releases=[dict(manifest=n+'.json', artifact=n) for n in ['status', 'echo', 'uptime']], desired={'agent-1': initial}, active={'agent-1': initial})
            (release/'catalog.json').write_text(json.dumps(catalog))
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            capture_proc = subprocess.Popen(privilege + [sys.executable, str(Path(__file__).resolve()), '--capture', str(port), str(output/'traffic.pcap')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            if capture_proc.stdout.readline().strip() != 'ready':
                raise RuntimeError('Could not start packet capture')
            def launch(name, args):
                log = open(output/(name+'.log'), 'w')
                files.append(log)
                proc = subprocess.Popen(args, cwd=work, stdin=subprocess.PIPE, stdout=log, stderr=log, text=True)
                processes.append(proc)
                return proc
            server = launch('server', [str(ROOT/'bin/bidi-server'), '-addr', f'127.0.0.1:{port}', '-catalog', str(release/'catalog.json'), '-permissions', str(release/'permissions.json'), '-control-socket', str(release/'control.sock'), '-audit', str(output/'audit.log')])
            logs = lambda n: (output/(n+'.log')).read_text()
            wait(lambda: 'listening on' in logs('server'), 'server startup', processes)
            agent = launch('agent', [str(ROOT/'bin/bidi-client'), '-addr', f'127.0.0.1:{port}', '-plugin-dir', str(work/'installed'), '-publisher-keys', str(release/'publisher-keys.json'), '-plugin-allow', 'status,echo,uptime'])
            mark('Agent connects; status and echo plugins download')
            def control(**request):
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.settimeout(5)
                    conn.connect(str(release/'control.sock'))
                    conn.sendall(json.dumps(dict(agent='agent-1', **request)).encode()+b'\n')
                    result = json.loads(conn.makefile().readline())
                    if result.get('error'):
                        raise RuntimeError(result['error'])
                    return result
            def active(name):
                try:
                    return any(p['plugin_id']==name and p['active'] for p in control(operation='plugins').get('plugins', []))
                except RuntimeError:
                    return False
            wait(lambda: active('echo') and active('status'), 'initial activation', processes)
            mark('Status and echo plugins verified and active')
            def action(name, value='{}'):
                time.sleep(0.3)
                mark(name+' request')
                result = control(operation='run', action=name, input=value)
                command = result['id']
                wait(lambda: 'result '+command+' ' in logs('server'), name+' result', processes)
                if 'result '+command+' from agent-1' not in logs('server') or 'error:' in next(line for line in logs('server').splitlines() if 'result '+command+' ' in line):
                    raise RuntimeError(name+' failed')
                mark(name+' result received')
            action('status')
            action('echo', 'proof over one connection')
            time.sleep(0.3)
            mark('Bidirectional plain messages')
            server.stdin.write('send agent-1 proof-from-server\n');server.stdin.flush()
            agent.stdin.write('proof-from-agent\n');agent.stdin.flush()
            wait(lambda: 'server: proof-from-server' in logs('agent') and 'agent agent-1: proof-from-agent' in logs('server'), 'bidirectional messages', processes)
            time.sleep(0.3)
            mark('Hot install and activation of uptime plugin')
            control(operation='install', plugin='uptime', version='1.0.0')
            control(operation='activate', plugin='uptime', version='1.0.0')
            wait(lambda: active('uptime'), 'uptime activation', processes)
            action('uptime')
            print('Waiting for a real heartbeat (up to 35 seconds)…', flush=True)
            wait(lambda: 'heartbeat: ping received from server' in logs('agent'), 'heartbeat', processes, 40)
            mark('Server heartbeat received; agent returns pong')
            time.sleep(0.3)
        finally:
            for proc in reversed(processes):
                proc.terminate()
            for proc in reversed(processes):
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill();proc.wait()
            if capture_proc:
                capture_proc.stdin.close()
                try:
                    capture_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    capture_proc.kill();capture_proc.wait()
            for file in files:
                file.close()
    packets = read_packets(output/'traffic.pcap', port)
    if not packets:
        raise RuntimeError('No packets captured')
    connections = len({p['agent_port'] for p in packets})
    handshakes = len({(p['agent_port'],p['sequence']) for p in packets if p['flags'] & 2 and not p['flags'] & 16})
    audit = [json.loads(line) for line in (output/'audit.log').read_text().splitlines()]
    authenticated = sum(e.get('event') == 'connected' for e in audit)
    if connections != 1 or handshakes != 1 or authenticated != 1:
        raise RuntimeError(f'Expected one connection; streams={connections}, handshakes={handshakes}, authenticated={authenticated}')
    samples = [e for e in audit if e.get('event') == 'traffic_sample']
    if len(samples) < 2 or len({e['session_id'] for e in samples}) != 1:
        raise RuntimeError('Missing traffic measurements on the heartbeat')
    (output/'events.json').write_text(json.dumps(dict(packets=packets, events=events, port=port, streams=connections, handshakes=handshakes, authenticated_connections=authenticated), indent=2))
    graph(output, packets, events, connections, handshakes)
    print(f'PASS: one TCP stream, one handshake, one authenticated session.\nGraph: {output / "connection.html"}\nImage: {output / "connection.svg"}\nCapture: {output / "traffic.pcap"}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', nargs=2, metavar=('PORT', 'PCAP'))
    args = parser.parse_args()
    try:
        if args.capture:
            capture(int(args.capture[0]), args.capture[1])
        else:
            demo()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f'Connection proof failed: {error}')
