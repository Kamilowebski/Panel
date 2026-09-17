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
        print("Znaleziono haslo w zmiennej DEVICE_PANEL_PASSWORD - zapisuje je (zahashowane) do pliku,")
        print("od teraz zmienna nie bedzie juz potrzebna.")
        password = env_password
    else:
        password = prompt_new_password()

    salt, digest = hash_password(password)
    atomic_write_json(PASSWORD_FILE, {"salt": salt, "hash": digest})
    print(f"Haslo zapisane w zahashowanej postaci w: {PASSWORD_FILE}")
    print("Aby zmienic haslo pozniej, uruchom: python app.py --set-password")
    print("=" * 70)
    return salt, digest

DEFAULT_CONFIG = {
    "areas": ["EXPORT", "MALA PACZKA", "ROZBIOR"],
    "types": ["terminal", "drukarka", "komputer", "bizerba", "maszyna", "inne"],
    "groups": [],
    "sshUser": "",
    "vncLocalPort": 5900,
    "vncRemotePort": 5900,
    "vncViewerPath": "",
}

AREAS = {
    "104": "Starachowice",
}

TYPE_PREFIXES = {
    "T": "terminal",
    "P": "drukarka",
    "K": "komputer",
    "B": "bizerba",
}


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
        pass  # logowanie nigdy nie moze wysypac zapisu danych


def backup_file_on_startup(path):
    if not path.exists():
        return None
    try:
        BACKUPS_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = BACKUPS_DIR / f"{path.stem}_{timestamp}{path.suffix}"
        shutil.copy2(path, backup_path)

        existing = sorted(
            BACKUPS_DIR.glob(f"{path.stem}_*{path.suffix}"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for old_backup in existing[MAX_BACKUPS:]:
            old_backup.unlink(missing_ok=True)

        return backup_path
    except OSError as error:
        print(f"UWAGA: nie udalo sie zrobic kopii zapasowej {path.name}: {error}")
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
    config["types"] = sorted(set(normalize_words(config["types"]) + normalize_words([device.get("type", "") for device in devices])))
    config["groups"] = sorted(set(normalize_words(config["groups"]) + normalize_words([device.get("group", "") for device in devices])))
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
    device.setdefault("area", "")
    device.setdefault("site", "")
    device.setdefault("note", "")
    device["systemId"] = str(device.get("systemId", "") or "").strip()
    device["group"] = str(device.get("group", "") or "").strip()
    device["vncUsername"] = str(device.get("vncUsername", "") or "").strip()

    if device["type"] == "bizerba":
        device["numerator"] = str(device.get("numerator", "") or "").strip()
    else:
        device.pop("numerator", None)

    device.pop("remoteAccess", None)

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
    if system == "windows":
        command = ["ping", "-n", str(count), "-w", "500", target]
    else:
        command = ["ping", "-c", str(count), "-W", "1", target]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(3, count * 2),
            encoding="utf-8",
            errors="replace",
        )
    except Exception as error:
        return {"online": False, "latencyMs": None, "error": str(error)}

    output = result.stdout + result.stderr
    latency = None
    latency_match = re.search(r"(?:time|czas)[=<]\s*(\d+)\s*ms", output, re.IGNORECASE)
    if latency_match:
        latency = int(latency_match.group(1))

    resolved_ip = None
    resolved_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", output)
    if not resolved_match:
        resolved_match = re.search(r"(?:Reply from|Odpowiedź z)\s+(\d{1,3}(?:\.\d{1,3}){3})", output, re.IGNORECASE)
    if resolved_match:
        resolved_ip = resolved_match.group(1)

    return {
        "online": result.returncode == 0,
        "latencyMs": latency,
        "target": target,
        "resolvedIp": resolved_ip,
        "raw": output[-800:],
    }


def device_ping_target(device):
    if device.get("addressMode") == "dhcp":
        return device.get("name")
    return device.get("ip") or device.get("name")


MAX_SCAN_ADDRESSES = 256


def parse_ip_range(range_str):
    range_str = (range_str or "").strip()
    if "-" not in range_str:
        raise ValueError("Nieprawidlowy zakres - uzyj formatu 192.168.1.1-192.168.1.254 albo 192.168.1.1-254")

    start_str, end_str = range_str.split("-", 1)
    start_str = start_str.strip()
    end_str = end_str.strip()

    start_parts = start_str.split(".")
    if len(start_parts) != 4:
        raise ValueError("Nieprawidlowy adres poczatkowy")

    if "." in end_str:
        end_parts = end_str.split(".")
        if len(end_parts) != 4:
            raise ValueError("Nieprawidlowy adres koncowy")
    else:
        end_parts = start_parts[:3] + [end_str]

    try:
        start_octets = tuple(int(p) for p in start_parts)
        end_octets = tuple(int(p) for p in end_parts)
    except ValueError:
        raise ValueError("Adresy IP moga zawierac tylko cyfry i kropki")

    for octet in start_octets + end_octets:
        if not (0 <= octet <= 255):
            raise ValueError("Oktet adresu IP musi byc w zakresie 0-255")

    if start_octets[:3] != end_octets[:3]:
        raise ValueError("Skaner obsluguje tylko zakres w jednej podsieci (te same pierwsze 3 oktety)")

    start_last, end_last = start_octets[3], end_octets[3]
    if start_last > end_last:
        raise ValueError("Adres poczatkowy musi byc mniejszy lub rowny koncowemu")

    if end_last - start_last + 1 > MAX_SCAN_ADDRESSES:
        raise ValueError(f"Zakres zbyt duzy - maksymalnie {MAX_SCAN_ADDRESSES} adresow na raz")

    prefix = ".".join(str(p) for p in start_octets[:3])
    return [f"{prefix}.{i}" for i in range(start_last, end_last + 1)]


_HOSTNAME_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=32)


def resolve_hostname(ip, timeout=1.5):
    # gethostbyaddr nie ma wlasnego parametru timeout i moze sie zawiesic na
    # wolnym/niedostepnym resolverze, wiec odpalamy go w osobnym watku i po
    # prostu nie czekamy dluzej niz `timeout` na wynik (watek w tle dokonczy
    # sie sam, ale nie blokuje reszty skanu).
    future = _HOSTNAME_EXECUTOR.submit(socket.gethostbyaddr, ip)
    try:
        hostname, _aliases, _addrs = future.result(timeout=timeout)
        return hostname.split(".")[0] if hostname else None
    except Exception:
        return None


def scan_network(ip_list, max_workers=24):
    online = {}

    def scan_one(ip):
        result = ping_host(ip, count=1)
        if result.get("online"):
            result["hostname"] = resolve_hostname(ip)
        return ip, result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_one, ip) for ip in ip_list]
        for future in concurrent.futures.as_completed(futures):
            ip, result = future.result()
            if result.get("online"):
                online[ip] = result

    return online


def build_ssh_target(device, ssh_user):
    host = device.get("name") if device.get("addressMode") == "dhcp" else (device.get("ip") or device.get("name"))
    ssh_user = (ssh_user or "").strip()
    return f"{ssh_user}@{host}" if ssh_user else host


def launch_ssh_tunnel(device, ssh_user, local_port, remote_port):
    ssh_path = shutil.which("ssh")
    if not ssh_path:
        return {
            "ok": False,
            "error": "Nie znaleziono polecenia 'ssh'. Zainstaluj klienta OpenSSH "
                     "(Windows: Ustawienia > Aplikacje > Opcjonalne funkcje > Dodaj funkcję > OpenSSH Client).",
        }

    target = build_ssh_target(device, ssh_user)
    forward = f"{local_port}:127.0.0.1:{remote_port}"
    # accept-new: pierwsze polaczenie z nowym hostem NIE pyta o 'yes/no' (dodaje
    # klucz automatycznie), ale jesli klucz hosta sie POTEM zmieni (np. realny
    # atak typu man-in-the-middle albo przeinstalowany system), ssh nadal
    # odmowi polaczenia i ostrzeze - ta ochrona zostaje nienaruszona
    command = [ssh_path, "-o", "StrictHostKeyChecking=accept-new", "-L", forward, target]
    system = platform.system().lower()

    try:
        if system == "windows":
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            subprocess.Popen(command, creationflags=creationflags)
        elif system == "darwin":
            script = f'tell application "Terminal" to do script "{" ".join(command)}"'
            subprocess.Popen(["osascript", "-e", script])
        else:
            terminal = None
            for candidate in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"):
                if shutil.which(candidate):
                    terminal = candidate
                    break
            if not terminal:
                return {"ok": False, "error": "Nie znaleziono terminala graficznego do uruchomienia SSH."}
            if terminal == "gnome-terminal":
                subprocess.Popen([terminal, "--", *command])
            else:
                subprocess.Popen([terminal, "-e", " ".join(command)])
    except Exception as error:
        return {"ok": False, "error": str(error)}

    return {"ok": True, "target": target, "localPort": local_port, "remotePort": remote_port}


def launch_ssh_raw(host, local_port, remote_port):
    """SSH bez użytkownika (raw) — do szybkiego połączenia z hostem spoza bazy."""
    ssh_path = shutil.which("ssh")
    if not ssh_path:
        return {
            "ok": False,
            "error": "Nie znaleziono polecenia 'ssh'. Zainstaluj klienta OpenSSH "
                     "(Windows: Ustawienia > Aplikacje > Opcjonalne funkcje > Dodaj funkcję > OpenSSH Client).",
        }

    host = (host or "").strip()
    if not host:
        return {"ok": False, "error": "Brak hosta."}

    forward = f"{local_port}:127.0.0.1:{remote_port}"
    command = [ssh_path, "-o", "StrictHostKeyChecking=accept-new", "-L", forward, host]
    system = platform.system().lower()

    try:
        if system == "windows":
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            subprocess.Popen(command, creationflags=creationflags)
        elif system == "darwin":
            script = f'tell application "Terminal" to do script "{" ".join(command)}"'
            subprocess.Popen(["osascript", "-e", script])
        else:
            terminal = None
            for candidate in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"):
                if shutil.which(candidate):
                    terminal = candidate
                    break
            if not terminal:
                return {"ok": False, "error": "Nie znaleziono terminala graficznego do uruchomienia SSH."}
            if terminal == "gnome-terminal":
                subprocess.Popen([terminal, "--", *command])
            else:
                subprocess.Popen([terminal, "-e", " ".join(command)])
    except Exception as error:
        return {"ok": False, "error": str(error)}

    return {"ok": True, "target": host, "localPort": local_port, "remotePort": remote_port}


def find_vnc_viewer(configured_path=""):
    configured_path = (configured_path or "").strip()
    if configured_path and Path(configured_path).exists():
        return configured_path

    found = shutil.which("vncviewer") or shutil.which("vncviewer.exe") or shutil.which("tigervnc")
    if found:
        return found

    common_paths = [
        r"C:\Program Files\TigerVNC\vncviewer.exe",
        r"C:\Program Files (x86)\TigerVNC\vncviewer.exe",
        "/usr/bin/vncviewer",
        "/usr/local/bin/vncviewer",
        "/Applications/TigerVNC Viewer.app/Contents/MacOS/TigerVNC Viewer",
    ]
    for candidate in common_paths:
        if Path(candidate).exists():
            return candidate
    return None


def launch_vnc(vnc_path, target_host, port, vnc_username=""):
    if not vnc_path:
        return {
            "ok": False,
            "error": "Nie znaleziono programu vncviewer (TigerVNC). Zainstaluj go albo podaj "
                     "pelna sciezke do vncviewer.exe w ustawieniach tunelu.",
        }

    target = f"{target_host}::{port}"

    # TigerVNC honoruje zmienna srodowiskowa VNC_USERNAME (dokumentacja vncviewer) -
    # dzieki temu login nie musi byc wpisywany recznie przy kazdym polaczeniu.
    # Haslo VNC celowo NIE jest tak przekazywane (VNC_PASSWORD) - nie przechowujemy
    # hasel w plikach panelu, uzytkownik wpisuje je recznie w oknie vncviewer.
    env = os.environ.copy()
    if vnc_username:
        env["VNC_USERNAME"] = vnc_username

    try:
        subprocess.Popen([vnc_path, target], env=env)
    except Exception as error:
        return {"ok": False, "error": str(error)}

    return {"ok": True, "target": target}


def launch_vnc_raw(vnc_path, host, port):
    """VNC bez użytkownika — do szybkiego połączenia z hostem spoza bazy."""
    if not vnc_path:
        return {
            "ok": False,
            "error": "Nie znaleziono programu vncviewer (TigerVNC). Zainstaluj go albo podaj "
                     "pelna sciezke do vncviewer.exe w ustawieniach tunelu.",
        }

    host = (host or "").strip()
    if not host:
        return {"ok": False, "error": "Brak hosta."}

    target = f"{host}::{port}"

    try:
        subprocess.Popen([vnc_path, target])
    except Exception as error:
        return {"ok": False, "error": str(error)}

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
        for header_name, 
