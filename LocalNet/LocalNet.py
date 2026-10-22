import os
import sys
import re
import socket
import threading
import queue
import subprocess
import ctypes
import shutil
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext

APP_DIR = Path(__file__).resolve().parent
DOMAINS_DIR = APP_DIR / "Domains"
HOSTS_FILE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
MARKER = "# LocalNet-managed entry"
HTTP_PORT = 8000
DOMAIN_SUFFIX = "localnet"
FIREWALL_RULE_NAME = "LocalNet HTTP (TCP 8000, Private)"
LOCAL_IP = "127.0.0.1"

DEFAULT_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name}.{suffix}</title>
</head>
<body>
<h1>{name}.{suffix}</h1>
<p>Edit <code>Domains/{name}/index.html</code> to change this page.</p>
</body>
</html>
"""


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    try:
        script = str(Path(sys.argv[0]).resolve())
        params = f'"{script}"'
        if len(sys.argv) > 1:
            params += " " + " ".join(f'"{a}"' for a in sys.argv[1:])
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, str(Path(script).parent), 1
        )
        return int(result) > 32
    except Exception:
        return False


def validate_name(name):
    if not name or not isinstance(name, str):
        return None
    name = name.strip().lower()
    if name.endswith("." + DOMAIN_SUFFIX):
        name = name[: -(len(DOMAIN_SUFFIX) + 1)]
    if not re.fullmatch(r"[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?", name):
        return None
    return name


def full_domain(name):
    return f"{name}.{DOMAIN_SUFFIX}"


def detect_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def detect_upstream_dns():
    try:
        ps = (
            "Get-DnsClientServerAddress -AddressFamily IPv4 | "
            "Where-Object {$_.ServerAddresses} | "
            "Select-Object -First 1 -ExpandProperty ServerAddresses"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                return line
    except Exception:
        pass
    return "8.8.8.8"


def port_in_use_tcp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def udp_port_free(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("0.0.0.0", port))
            return True
        finally:
            s.close()
    except OSError:
        return False


class LogQueue:
    def __init__(self):
        self.q = queue.Queue()

    def put(self, msg, level="info"):
        self.q.put((level, msg))

    def drain(self, widget):
        try:
            while True:
                level, msg = self.q.get_nowait()
                widget.configure(state="normal")
                widget.insert(tk.END, msg + "\n", level)
                widget.see(tk.END)
                widget.configure(state="disabled")
        except queue.Empty:
            pass


class SiteStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.hosted = {}
        self.restricted = set()

    def add(self, name):
        with self.lock:
            self.hosted[name] = full_domain(name)
            self.restricted.discard(name)

    def remove(self, name):
        with self.lock:
            self.hosted.pop(name, None)
            self.restricted.discard(name)

    def restrict(self, name):
        with self.lock:
            if name in self.hosted:
                self.restricted.add(name)
                return True
            return False

    def unrestrict(self, name):
        with self.lock:
            if name in self.hosted and name in self.restricted:
                self.restricted.discard(name)
                return True
            return False

    def is_restricted(self, name):
        with self.lock:
            return name in self.restricted

    def lookup(self, host_header):
        host = host_header.split(":")[0].strip().lower()
        if host.endswith("." + DOMAIN_SUFFIX):
            short = host[: -(len(DOMAIN_SUFFIX) + 1)]
            with self.lock:
                if short in self.hosted:
                    return short
        return None

    def list_hosted(self):
        with self.lock:
            return sorted(self.hosted.keys())

    def list_restricted(self):
        with self.lock:
            return sorted(self.restricted)


def ensure_domain_folder(name):
    d = DOMAINS_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    index = d / "index.html"
    if not index.exists():
        index.write_text(DEFAULT_PAGE.format(name=name, suffix=DOMAIN_SUFFIX), encoding="utf-8")
    return d


class Handler(BaseHTTPRequestHandler):
    store = None
    log = None

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle(head=True)

    def _handle(self, head=False):
        host = self.headers.get("Host", "")
        name = self.store.lookup(host)
        if name is None:
            self._send(404, b"Unknown domain")
            return
        if self.store.is_restricted(name):
            self._send(403, b"Domain is restricted")
            return

        root = (DOMAINS_DIR / name).resolve()

        raw_path = self.path.split("?", 1)[0].split("#", 1)[0]
        try:
            raw_path = urllib.parse.unquote(raw_path)
        except Exception:
            self._send(400, b"Bad request")
            return

        if raw_path in ("", "/"):
            raw_path = "/index.html"

        parts = [p for p in raw_path.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            self._send(403, b"Forbidden")
            return

        target = root.joinpath(*parts)

        if target.is_dir():
            target = target / "index.html"

        try:
            target = target.resolve()
            target.relative_to(root)
        except (ValueError, OSError):
            self._send(403, b"Forbidden")
            return

        if not target.is_file():
            self._send(404, b"Not found")
            return

        try:
            data = target.read_bytes()
        except OSError:
            self._send(500, b"Read error")
            return

        ctype = self._guess_type(target)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _guess_type(self, p):
        ext = p.suffix.lower()
        return {
            ".html": "text/html; charset=utf-8",
            ".htm": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".txt": "text/plain; charset=utf-8",
            ".webp": "image/webp",
        }.get(ext, "application/octet-stream")

    def _send(self, code, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class Server:
    def __init__(self, store, log):
        self.store = store
        self.log = log
        self.httpd = None
        self.thread = None

    def running(self):
        return self.httpd is not None

    def start(self):
        if self.httpd:
            return True
        Handler.store = self.store
        Handler.log = self.log
        try:
            self.httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
        except OSError as e:
            self.log(f"HTTP server failed to bind port {HTTP_PORT}: {e}", "error")
            self.httpd = None
            return False
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.log(f"HTTP server listening on 0.0.0.0:{HTTP_PORT}")
        return True

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
            try:
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
            self.thread = None
            self.log("HTTP server stopped.")


class HostsManager:
    def __init__(self, log):
        self.log = log

    def _read(self):
        if not HOSTS_FILE.exists():
            return []
        try:
            return HOSTS_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as e:
            self.log(f"Could not read hosts file: {e}", "error")
            return []

    def _write(self, lines):
        tmp = HOSTS_FILE.with_suffix(".localnet.tmp")
        try:
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
            shutil.move(str(tmp), str(HOSTS_FILE))
            return True
        except PermissionError:
            self.log("Administrator privileges are required to modify the hosts file.", "error")
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            return False
        except OSError as e:
            self.log(f"Could not write hosts file: {e}", "error")
            return False

    def ensure(self, domain, ip):
        lines = self._read()
        for line in lines:
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2 and domain in parts[1:]:
                existing = parts[0]
                if existing == ip:
                    self.log(f"Hosts entry for {domain} already present ({ip}).")
                    return True
                self.log(
                    f"Warning: {domain} already maps to {existing}. "
                    "Not overwriting a pre-existing entry.", "error",
                )
                return False
        lines.append(f"{ip}\t{domain}\t{MARKER}")
        if not self._write(lines):
            return False
        self.log(f"Added hosts entry: {ip} {domain}")
        self._flush_dns()
        return True

    def remove_managed(self):
        lines = self._read()
        new_lines = [ln for ln in lines if MARKER not in ln]
        if len(new_lines) != len(lines):
            if self._write(new_lines):
                self.log("Removed LocalNet-managed hosts entries.")
                self._flush_dns()

    def _flush_dns(self):
        try:
            subprocess.run(
                ["ipconfig", "/flushdns"], capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass


class FirewallManager:
    def __init__(self, log):
        self.log = log

    def rule_exists(self):
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f'Get-NetFirewallRule -DisplayName "{FIREWALL_RULE_NAME}" -ErrorAction SilentlyContinue'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return FIREWALL_RULE_NAME in result.stdout
        except Exception:
            return False

    def add_rule(self):
        if self.rule_exists():
            self.log(f"Firewall rule already exists: {FIREWALL_RULE_NAME}")
            return True
        try:
            cmd = (
                f'New-NetFirewallRule -DisplayName "{FIREWALL_RULE_NAME}" '
                f'-Direction Inbound -Protocol TCP -LocalPort {HTTP_PORT} '
                f'-Action Allow -Profile Private '
                f'-Description "LocalNet LAN access on TCP {HTTP_PORT} (Private only)"'
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                self.log(f"Firewall rule created: {FIREWALL_RULE_NAME} (Private profile only).", "success")
                return True
            self.log(f"Failed to create firewall rule: {result.stderr.strip() or result.stdout.strip()}", "error")
            return False
        except Exception as e:
            self.log(f"Firewall error: {e}", "error")
            return False

    def remove_rule(self):
        if not self.rule_exists():
            self.log("No LocalNet firewall rule to remove.")
            return True
        try:
            cmd = f'Remove-NetFirewallRule -DisplayName "{FIREWALL_RULE_NAME}" -ErrorAction Stop'
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode == 0:
                self.log("Firewall rule removed.", "success")
                return True
            self.log(f"Failed to remove firewall rule: {result.stderr.strip()}", "error")
            return False
        except Exception as e:
            self.log(f"Firewall error: {e}", "error")
            return False


class DNSServer:
    def __init__(self, store, log):
        self.store = store
        self.log = log
        self.sock = None
        self.thread = None
        self._running = False
        self.upstream = None

    def running(self):
        return self._running and self.sock is not None

    def start(self):
        if self.running():
            return True
        if not is_admin():
            self.log("Administrator privileges are required to bind UDP port 53.", "error")
            return False
        if not udp_port_free(53):
            self.log("UDP port 53 is already in use by another DNS service. "
                     "Stop it before enabling the LocalNet DNS server.", "error")
            return False
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", 53))
            self.sock.settimeout(0.5)
            self.upstream = detect_upstream_dns()
            self._running = True
            self.thread = threading.Thread(target=self._serve, daemon=True)
            self.thread.start()
            self.log(f"DNS server listening on UDP 0.0.0.0:53 (upstream {self.upstream}).", "success")
            return True
        except OSError as e:
            self.log(f"Failed to start DNS server: {e}", "error")
            return False

    def stop(self):
        self._running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.thread = None
        self.log("DNS server stopped.")

    def _serve(self):
        while self._running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(data, addr), daemon=True).start()

    def _handle(self, data, addr):
        try:
            parsed = self._parse_question(data)
            if parsed is None:
                return
            qname, qtype, _ = parsed
            if qname.endswith("." + DOMAIN_SUFFIX):
                short = qname[: -(len(DOMAIN_SUFFIX) + 1)]
                hosted = self.store.list_hosted()
                if short in hosted:
                    if qtype == 1:
                        self.sock.sendto(self._build_a_response(data, detect_lan_ip()), addr)
                        return
                    self.sock.sendto(self._empty_noerror(data), addr)
                    return
                self.sock.sendto(self._nxdomain(data), addr)
                return
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
                    up.settimeout(2)
                    up.sendto(data, (self.upstream, 53))
                    resp, _ = up.recvfrom(4096)
                    self.sock.sendto(resp, addr)
            except Exception:
                self.sock.sendto(self._servfail(data), addr)
        except Exception:
            pass

    def _parse_question(self, data):
        if len(data) < 12:
            return None
        i = 12
        labels = []
        while i < len(data):
            length = data[i]
            if length == 0:
                i += 1
                break
            if i + 1 + length > len(data):
                return None
            try:
                labels.append(data[i + 1:i + 1 + length].decode("ascii"))
            except Exception:
                return None
            i += 1 + length
        if i + 4 > len(data):
            return None
        qtype = int.from_bytes(data[i:i + 2], "big")
        qclass = int.from_bytes(data[i + 2:i + 4], "big")
        return ".".join(labels).lower(), qtype, qclass

    def _extract_question(self, query):
        i = 12
        while i < len(query):
            length = query[i]
            if length == 0:
                i += 1
                break
            i += 1 + length
        return query[12:i + 4]

    def _build_a_response(self, query, ip):
        tid = query[:2]
        flags = b"\x81\x80"
        header = tid + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        question = self._extract_question(query)
        answer = (
            b"\xc0\x0c"
            + b"\x00\x01"
            + b"\x00\x01"
            + b"\x00\x00\x00\x3c"
            + b"\x00\x04"
            + socket.inet_aton(ip)
        )
        return header + question + answer

    def _empty_noerror(self, query):
        tid = query[:2]
        return tid + b"\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + self._extract_question(query)

    def _nxdomain(self, query):
        tid = query[:2]
        return tid + b"\x81\x83" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + self._extract_question(query)

    def _servfail(self, query):
        tid = query[:2]
        return tid + b"\x81\x82" + b"\x00\x01\x00\x00\x00\x00\x00\x00" + self._extract_question(query)


class LocalNetApp:
    def __init__(self, root):
        self.root = root
        self.logq = LogQueue()
        self.store = SiteStore()
        self.server = Server(self.store, self._log)
        self.hosts = HostsManager(self._log)
        self.firewall = FirewallManager(self._log)
        self.dns = DNSServer(self.store, self._log)
        self._build_ui()
        self._log("LocalNet ready. Type 'help' or a command.")
        if not is_admin():
            self._log("Running WITHOUT administrator privileges. "
                      "'host' and 'dns start' will fail until you run LocalNet as Administrator.", "error")
        self._pump()

    def _build_ui(self):
        self.root.title("LocalNet command line")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f0f0")
        self.root.minsize(640, 400)

        output_frame = tk.Frame(self.root, bg="#f0f0f0")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(12, 0))

        self.output = scrolledtext.ScrolledText(
            output_frame,
            bg="#ffffff",
            fg="#1a1a1a",
            insertbackground="#1a1a1a",
            font=("Consolas", 10),
            relief="solid",
            borderwidth=1,
            padx=12,
            pady=10,
            spacing1=2,
            spacing3=2,
            state="disabled",
        )
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.tag_config("error", foreground="#c00000")
        self.output.tag_config("info", foreground="#1a1a1a")
        self.output.tag_config("success", foreground="#006400")
        self.output.tag_config(
            "prompt_echo",
            foreground="#0067c0",
            font=("Consolas", 10, "bold"),
        )

        bottom = tk.Frame(self.root, bg="#f0f0f0")
        bottom.pack(fill=tk.X, padx=12, pady=12)

        self.prompt_label = tk.Label(
            bottom, text="❯", bg="#f0f0f0", fg="#0067c0",
            font=("Consolas", 12, "bold"),
        )
        self.prompt_label.pack(side=tk.LEFT, padx=(0, 8))

        self.entry = tk.Entry(
            bottom,
            bg="#ffffff",
            fg="#1a1a1a",
            insertbackground="#1a1a1a",
            font=("Consolas", 11),
            relief="solid",
            borderwidth=1,
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        self.entry.bind("<Return>", self._on_enter)
        self.entry.focus_set()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _log(self, msg, level="info"):
        self.logq.put(msg, level)

    def _pump(self):
        self.logq.drain(self.output)
        self.root.after(80, self._pump)

    def _on_enter(self, event):
        cmd = self.entry.get().strip()
        self.entry.delete(0, tk.END)
        if not cmd:
            return
        self.output.configure(state="normal")
        self.output.insert(tk.END, f"❯ {cmd}\n", "prompt_echo")
        self.output.see(tk.END)
        self.output.configure(state="disabled")
        threading.Thread(target=self._dispatch, args=(cmd,), daemon=True).start()

    def _dispatch(self, cmd):
        parts = cmd.split()
        verb = parts[0].lower()
        args = parts[1:]
        try:
            if verb == "host":
                self._cmd_host(args)
            elif verb == "open":
                self._cmd_open(args)
            elif verb == "restrict":
                self._cmd_restrict(args)
            elif verb == "unrestrict":
                self._cmd_unrestrict(args)
            elif verb == "status":
                self._cmd_status()
            elif verb == "shutdown":
                self._cmd_shutdown()
            elif verb == "firewall":
                self._cmd_firewall(args)
            elif verb == "dns":
                self._cmd_dns(args)
            elif verb == "verify":
                self._cmd_verify(args)
            elif verb == "about":
                self._cmd_about()
            elif verb == "help":
                self._cmd_help()
            else:
                self._log(f"Unknown command: {verb}", "error")
        except Exception as e:
            self._log(f"Error: {e}", "error")

    def _require_name(self, args):
        if len(args) != 1:
            self._log("Usage: <command> <name>", "error")
            return None
        name = validate_name(args[0])
        if not name:
            self._log(f"Invalid domain name: {args[0]}", "error")
            return None
        return name

    def _cmd_host(self, args):
        name = self._require_name(args)
        if not name:
            return
        folder = ensure_domain_folder(name)
        self._log(f"  Website directory: {folder}")

        if not self.server.running():
            if port_in_use_tcp(HTTP_PORT):
                self._log(f"Port {HTTP_PORT} is already in use by another process.", "error")
                return
            if not self.server.start():
                self._log("Hosting failed: HTTP server did not start.", "error")
                return

        domain = full_domain(name)

        if not self.hosts.ensure(domain, LOCAL_IP):
            self._log(f"Hosting {name} failed: could not add hosts entry for {domain}.", "error")
            self._log("Run LocalNet as Administrator and try again.", "error")
            return

        self.store.add(name)

        try:
            resolved = socket.gethostbyname(domain)
        except socket.gaierror:
            resolved = None

        if resolved == LOCAL_IP:
            self._log(f"  Verified: {domain} resolves to {resolved}.", "success")
        elif resolved:
            self._log(f"  Warning: {domain} resolves to {resolved} (expected {LOCAL_IP}).", "error")
        else:
            self._log(f"  Warning: {domain} did not resolve yet. "
                      "If the browser still fails, run 'ipconfig /flushdns' and retry.", "error")

        self._log(f"  Hosted: http://{domain}:{HTTP_PORT}", "success")
        lan_ip = detect_lan_ip()
        self._log(f"  LAN IP for other devices: {lan_ip}")
        self._log("  Other devices cannot use .localnet names without extra setup.")
        self._log("    (a) run 'dns start' and point them at this PC's DNS,")
        self._log("    (b) add hosts entries on each device,")
        self._log("    (c) configure router DNS. LocalNet does NOT configure your router.")

    def _cmd_open(self, args):
        name = self._require_name(args)
        if not name:
            return
        if name not in self.store.list_hosted():
            self._log(f"Domain '{name}' is not hosted. Use 'host {name}' first.", "error")
            return
        if self.store.is_restricted(name):
            self._log(f"Domain '{name}' is restricted.", "error")
            return
        domain = full_domain(name)
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            self._log(f"Cannot resolve {domain} on this PC. Hosts entry may not be applied.", "error")
            return
        if ip != LOCAL_IP:
            self._log(f"{domain} resolves to {ip}, not {LOCAL_IP}. "
                      "Refusing to open — the request would not reach this server.", "error")
            return
        url = f"http://{domain}:{HTTP_PORT}"
        try:
            webbrowser.open(url)
            self._log(f"  Opened {url}", "success")
        except Exception as e:
            self._log(f"Could not open browser: {e}", "error")

    def _cmd_restrict(self, args):
        name = self._require_name(args)
        if not name:
            return
        if self.store.restrict(name):
            self._log(f"  Domain '{name}' is now restricted (HTTP 403; others unaffected).", "success")
        else:
            self._log(f"Domain '{name}' is not hosted or is already restricted.", "error")

    def _cmd_unrestrict(self, args):
        name = self._require_name(args)
        if not name:
            return
        if name not in self.store.list_hosted():
            self._log(f"Domain '{name}' is not hosted.", "error")
            return
        if self.store.unrestrict(name):
            self._log(f"  Domain '{name}' is now unrestricted (HTTP 200; others unaffected).", "success")
        else:
            self._log(f"Domain '{name}' was not restricted; nothing to do.", "error")

    def _cmd_firewall(self, args):
        if args and args[0].lower() == "remove":
            if not is_admin():
                self._log("Administrator privileges are required to modify firewall rules.", "error")
                return
            self.firewall.remove_rule()
            return
        if not is_admin():
            self._log("Administrator privileges are required to modify firewall rules.", "error")
            return
        self.firewall.add_rule()

    def _cmd_dns(self, args):
        sub = args[0].lower() if args else "status"
        if sub == "start":
            if self.dns.running():
                self._log("DNS server already running.")
                return
            if self.dns.start():
                lan_ip = detect_lan_ip()
                self._log(f"  DNS server listening on {lan_ip}:53 (UDP).", "success")
                self._log("  Point other devices' DNS at this PC to resolve .localnet names.")
                self._log("  This does NOT configure your router. Set DNS per-device or in "
                          "the router's DHCP settings (router UI required).")
            return
        if sub == "stop":
            if not self.dns.running():
                self._log("DNS server is not running.")
                return
            self.dns.stop()
            return
        if self.dns.running():
            self._log(f"DNS server: running on UDP 0.0.0.0:53 (upstream {self.dns.upstream})")
        else:
            self._log("DNS server: stopped. Use 'dns start' to enable .localnet resolution for LAN clients.")

    def _cmd_verify(self, args):
        hosted = self.store.list_hosted()
        if not hosted:
            self._log("No domains hosted. Run 'host localnet' first.", "error")
            return
        self._log("--- LocalNet verification ---")
        lan_ip = detect_lan_ip()
        self._log(f"  LAN IP: {lan_ip}")
        self._log(f"  HTTP server: {'running' if self.server.running() else 'stopped'}")
        self._log(f"  DNS server: {'running' if self.dns.running() else 'stopped'}")
        self._log(f"  Firewall rule: {'present' if self.firewall.rule_exists() else 'not present'}")
        for name in hosted:
            domain = full_domain(name)
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                ip = None
            if ip == LOCAL_IP:
                self._log(f"  [OK]   {domain} -> {ip} (hosts file)", "success")
            elif ip == lan_ip:
                self._log(f"  [OK]   {domain} -> {ip} (LAN IP, via DNS)", "success")
            elif ip is None:
                self._log(f"  [FAIL] {domain} does not resolve", "error")
            else:
                self._log(f"  [WARN] {domain} -> {ip} (unexpected)", "error")

            try:
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", HTTP_PORT, timeout=2)
                conn.request("GET", "/", headers={"Host": domain})
                resp = conn.getresponse()
                status = resp.status
                resp.read()
                conn.close()
                if status == 200:
                    self._log(f"  [OK]   HTTP GET / Host: {domain} -> {status}", "success")
                else:
                    self._log(f"  [WARN] HTTP GET / Host: {domain} -> {status}", "error")
            except Exception as e:
                self._log(f"  [FAIL] HTTP request failed: {e}", "error")

    def _cmd_status(self):
        self._log("--- LocalNet status ---")
        self._log(f"  HTTP server: {'running' if self.server.running() else 'stopped'} (port {HTTP_PORT})")
        self._log(f"  Port {HTTP_PORT} TCP in use: {port_in_use_tcp(HTTP_PORT)}")
        self._log(f"  Port 53 UDP available: {udp_port_free(53)}")
        self._log(f"  Administrator: {is_admin()}")
        self._log(f"  LAN IP: {detect_lan_ip()}")
        self._log(f"  Firewall rule (TCP {HTTP_PORT}, Private): "
                  f"{'present' if self.firewall.rule_exists() else 'not present'}")
        self._log(f"  DNS server: "
                  f"{'running on UDP 0.0.0.0:53 (upstream ' + str(self.dns.upstream) + ')' if self.dns.running() else 'stopped'}")
        hosted = self.store.list_hosted()
        restricted = self.store.list_restricted()
        self._log(f"  Hosted domains: {', '.join(hosted) if hosted else '(none)'}")
        self._log(f"  Restricted domains: {', '.join(restricted) if restricted else '(none)'}")
        if hosted:
            for n in hosted:
                d = full_domain(n)
                try:
                    ip = socket.gethostbyname(d)
                except socket.gaierror:
                    ip = "unresolved"
                mark = " [restricted]" if n in restricted else ""
                self._log(f"    - http://{d}:{HTTP_PORT}  ->  {ip}{mark}")

    def _cmd_about(self):
        self._log("  LocalNet — a hobby tool for running small test domains.")
        self._log("  Hosts .localnet sites on port 8000 from Domains/<name>/index.html.")

    def _cmd_shutdown(self):
        self.dns.stop()
        self.server.stop()
        self.hosts.remove_managed()
        self.store.hosted.clear()
        self.store.restricted.clear()
        self._log("  Shutdown complete.", "success")
        self._log("  Firewall rule (if any) was left in place. Use 'firewall remove' to delete it.")

    def _cmd_help(self):
        self._log("Commands:")
        self._log("  host <name>          Create + host a domain; adds hosts entry + verifies")
        self._log("  open <name>          Open a hosted domain (checks resolution first)")
        self._log("  restrict <name>      Return HTTP 403 for a hosted domain")
        self._log("  unrestrict <name>    Re-enable HTTP access for a restricted domain")
        self._log("  firewall [remove]    Add/remove the Private-profile rule for TCP 8000")
        self._log("  dns start|stop       Optional local DNS server (UDP 53) for LAN clients")
        self._log("  verify               End-to-end check: hosts, HTTP, DNS, firewall")
        self._log("  status               Show services, firewall, DNS, hosted domains")
        self._log("  about                Show a short description of LocalNet")
        self._log("  shutdown             Stop services and clean LocalNet hosts entries")
        self._log("  help                 Show this help")

    def _on_close(self):
        try:
            self.dns.stop()
            self.server.stop()
            self.hosts.remove_managed()
        except Exception:
            pass
        self.root.destroy()


def main():
    if not is_admin():
        if relaunch_as_admin():
            return
    DOMAINS_DIR.mkdir(parents=True, exist_ok=True)
    root = tk.Tk()
    LocalNetApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()