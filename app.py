import concurrent.futures
import getpass
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DEVICE_PANEL_DATA_DIR", str(ROOT))).resolve()
DATA_FILE = DATA_DIR / "devices.json"
CONFIG_FILE = DATA_DIR / "config.json"
PASSWORD_FILE = DATA_DIR / "admin_password.json"
LOG_FILE = DATA_DIR / "changes.log"
BACKUPS_DIR = DATA_DIR / "backups"
MAX_BACKUPS = 30
PORT = 5000

ADMIN_SALT = None
ADMIN_HASH = None


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return salt, digest.hex()


def verify_password(password, salt, expected_hash):
    if not salt or not expected_hash or not password:
        return False
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected_hash)


def prompt_new_password():
    password = getpass.getpass("Ustaw haslo administratora (do zapisu zmian): ")
    confirm = getpass.getpass("Powtorz haslo: ")
    while not password or password != confirm:
        print("Hasla nie byly takie same albo byly puste - sprobuj ponownie.")
        password = getpass.getpass("Ustaw haslo administratora: ")
        confirm = getpass.getpass("Powtorz haslo: ")
    return password


def load_or_create_password_file():
    if PASSWORD_FILE.exists():
        with PASSWORD_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
        return data["salt"], data["hash"]

    print("=" * 70)
    print("Pierwsze uruchomienie: nie znaleziono zapisanego hasla administratora.")
    env_password = os.environ.get("DEVICE_PANEL_PASSWORD")
    if env_password:
        password = env_password
    else:
        password = prompt_new_password()

    salt, digest = hash_password(password)
    atomic_write_json(PASSWORD_FILE, {"salt": salt, "hash": digest})
    return salt, digest

DEFAULT_CONFIG = {
    "areas": ["EXPORT", "MALA PACZKA", "ROZBIOR"],
    "types": ["terminal", "drukarka", "komputer", "bizerba", "maszyna", "inne"],
    "groups": [],
    "sshUser": "",
    "vncLocalPort": 5900,
    "vncRemotePort": 5900,
    "vncViewerPath": "",
    "positions": {}
}

AREAS = {"104": "Starachowice"}
TYPE_PREFIXES = {"T": "terminal", "P": "drukarka", "K": "komputer", "B": "bizerba"}
WRITE_LOCK = threading.Lock()


def read_devices():
    if not DATA_FILE.exists():
        return []
    with DATA_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def compute_file_version(path):
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_write_json(path, payload):
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)


def log_change(client_ip, action, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {client_ip or 'nieznane IP'} | {action} | {details}\n"
    try:
        with LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(line)
    except OSError:
        pass


def backup_file_on_startup(path):
    if not path.exists():
        return None
    try:
        BACKUPS_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = BACKUPS_DIR / f"{path.stem}_{timestamp}{path.suffix}"
        shutil.copy2(path, backup_path)
        return backup_path
    except OSError:
        return None


def write_devices(devices):
    atomic_write_json(DATA_FILE, devices)


def normalize_words(values):
    if isinstance(values, str):
        values = values.replace(";", ",").split(",")
    if not isinstance(values, list):
        values = []
    cleaned = []
    seen = set()
    for value in values:
        word = str(value).strip()
        key = word.lower()
        if word and key not in seen:
            cleaned.append(word)
            seen.add(key)
    return cleaned


def read_config():
    config = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        with CONFIG_FILE.open("r", encoding="utf-8") as file:
            loaded = json.load(file)
        config.update({key: loaded.get(key, value) for key, value in DEFAULT_CONFIG.items()})

    devices = read_devices()
    config["areas"] = sorted(set(normalize_words(config["areas"]) + normalize_words([device.get("area", "") for device in devices])))
    config["types"] = sorted(set(normalize_words(config["types"]) + normalize_words([device.get("area", "") for device in devices])))
    return config


def parse_port(value, fallback):
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return port
    except (TypeError, ValueError):
        pass
    return fallback


def write_config(config):
    payload = {
        "areas": normalize_words(config.get("areas", [])),
        "types": normalize_words(config.get("types", [])),
        "groups": normalize_words(config.get("groups", [])),
        "sshUser": str(config.get("sshUser", "") or "").strip(),
        "vncLocalPort": parse_port(config.get("vncLocalPort"), DEFAULT_CONFIG["vncLocalPort"]),
        "vncRemotePort": parse_port(config.get("vncRemotePort"), DEFAULT_CONFIG["vncRemotePort"]),
        "vncViewerPath": str(config.get("vncViewerPath", "") or "").strip(),
        "positions": config.get("positions", {})
    }
    atomic_write_json(CONFIG_FILE, payload)
    return payload


def enrich_device(device):
    device = dict(device)
    name = device.get("name", "").strip().upper()
    device["name"] = name
    match = re.match(r"^([A-Z])(\d{3})-(\d{4})$", name)
    if match:
        prefix, area_code, number = match.groups()
        device.setdefault("type", TYPE_PREFIXES.get(prefix, "inne"))
        device["areaCode"] = area_code
        device.setdefault("site", AREAS.get(area_code, f"Zaklad {area_code}"))
        device["number"] = number

    if "keywords" not in device or not isinstance(device["keywords"], list):
        device["keywords"] = normalize_words(device.get("keywords", ""))

    device.setdefault("type", "inne")
    device["ip"] = device.get("ip", "").strip()
    if not device.get("addressMode"):
        device["addressMode"] = "static" if device["type"] == "bizerba" else "dhcp"
    return device


def require_password(handler, payload=None):
    password = handler.headers.get("X-Admin-Password", "")
    if payload and not password:
        password = payload.get("password", "")
    if not verify_password(password, ADMIN_SALT, ADMIN_HASH):
        handler.send_json({"error": "Niepoprawne haslo administratora"}, status=403)
        return False
    return True


def find_device_by_name(name):
    wanted = name.strip().upper()
    for device in [enrich_device(item) for item in read_devices()]:
        if device.get("name") == wanted:
            return device
    return None


def ping_host(target, count=3):
    system = platform.system().lower()
    command = ["ping", "-n" if system == "windows" else "-c", str(count), target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace")
    except Exception as error:
        return {"online": False, "latencyMs": None, "error": str(error)}

    output = result.stdout + result.stderr
    latency = None
    latency_match = re.search(r"(?:time|czas)[=<]\s*(\d+)\s*ms", output, re.IGNORECASE)
    if latency_match:
        latency = int(latency_match.group(1))

    return {"online": result.returncode == 0, "latencyMs": latency, "target": target, "raw": output[-800:]}


def scan_single_port(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except OSError:
        return port, False


def launch_ssh_command(device, ssh_user, cmd):
    ssh_path = shutil.which("ssh")
    if not ssh_path:
        return {"ok": False, "error": "Nie znaleziono ssh"}

    host = device.get("ip") or device.get("name")
    target = f"{ssh_user}@{host}" if ssh_user else host
    command = [ssh_path, "-o", "StrictHostKeyChecking=accept-new", target, f"echo Executing: {cmd}; {cmd}; exec $SHELL"]

    system = platform.system().lower()
    try:
        if system == "windows":
            subprocess.Popen(command, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
        else:
            subprocess.Popen(["xterm", "-e", " ".join(command)])
    except Exception as e:
        return {"ok": False, "error": str(e)}

    return {"ok": True, "target": target}


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, payload, status=200, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/devices":
            devices = [enrich_device(device) for device in read_devices()]
            self.send_json(devices)
            return

        if parsed.path == "/api/config":
            self.send_json(read_config())
            return

        if parsed.path == "/api/ping":
            target = parse_qs(parsed.query).get("target", [""])[0].strip()
            self.send_json(ping_host(target))
            return

        if parsed.path == "/":
            self.path = "/index.html"

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))

        if not require_password(self, payload):
            return

        client_ip = self.client_address[0]

        if parsed.path == "/api/config":
            config = write_config(payload.get("config", payload))
            self.send_json({"ok": True, "config": config})
            return

        if parsed.path == "/api/port-scan":
            target = str(payload.get("target", "")).strip()
            ports = payload.get("ports", [22, 80, 443, 5900, 9100])
            results = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(scan_single_port, target, p) for p in ports]
                for f in concurrent.futures.as_completed(futures):
                    port, status = f.result()
                    results[port] = status
            self.send_json({"target": target, "ports": results})
            return

        if parsed.path == "/api/ssh-cmd":
            name = str(payload.get("name", "")).strip()
            cmd = str(payload.get("cmd", "")).strip()
            device = find_device_by_name(name) or {"name": name, "ip": name}
            config = read_config()
            ssh_user = config.get("sshUser", "")
            res = launch_ssh_command(device, ssh_user, cmd)
            self.send_json(res)
            return

        if parsed.path == "/api/ssh-tunnel":
            name = str(payload.get("name", "")).strip()
            device = find_device_by_name(name) or {"name": name, "ip": name, "addressMode": "static" if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name) else "dhcp"}
            config = read_config()
            ssh_user = config.get("sshUser", "")
            local_port = config.get("vncLocalPort", 5900)
            remote_port = config.get("vncRemotePort", 5900)

            ssh_path = shutil.which("ssh")
            target = f"{ssh_user}@{device.get('ip') or name}" if ssh_user else (device.get('ip') or name)
            command = [ssh_path, "-o", "StrictHostKeyChecking=accept-new", "-L", f"{local_port}:127.0.0.1:{remote_port}", target]
            subprocess.Popen(command, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
            self.send_json({"ok": True, "target": target})
            return

        if parsed.path == "/api/devices":
            devices = [enrich_device(device) for device in payload.get("devices", payload)]
            write_devices(devices)
            self.send_json({"ok": True, "count": len(devices)})
            return


if __name__ == "__main__":
    ADMIN_SALT, ADMIN_HASH = load_or_create_password_file()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Panel urzadzen dziala na portcie {PORT}")
    server.serve_forever()
