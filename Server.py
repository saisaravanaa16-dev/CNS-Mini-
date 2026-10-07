"""
server.py - Secure File Transfer Server (multi-client, threaded)

Run:  python server.py [--host 0.0.0.0] [--port 5001]

Flow for every client:
  1. Server sends its RSA public key
  2. Client sends a random AES-256 session key encrypted with that public key
  3. From now on all data is AES-GCM encrypted
  4. Client logs in (username/password), then uses LIST / UPLOAD / DOWNLOAD
"""
import os
import csv
import socket
import logging
import argparse
import threading
from datetime import datetime

import common
from common import SecureChannel, SecurityError, CHUNK_SIZE, MAX_FILE_SIZE
from auth import verify_user

BASE = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE, "users.json")

STORAGE = os.path.join(BASE, "server_files")
LOG_DIR = os.path.join(BASE, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(os.path.join(LOG_DIR, "server.log")),
              logging.StreamHandler()])
log = logging.getLogger("server")
csv_lock = threading.Lock()


def log_transfer(user, action, filename, size, status):
    """Append every transfer to a CSV (easy to open in Excel / pandas)."""
    path = os.path.join(LOG_DIR, "transfers.csv")
    with csv_lock:
        new = not os.path.exists(path)
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["time", "user", "action", "filename", "bytes", "status"])
            w.writerow([datetime.now().isoformat(timespec="seconds"),
                        user, action, filename, size, status])


def safe_name(name: str) -> str:
    """Strip any path (blocks '../../etc/passwd' style attacks)."""
    return os.path.basename(name.replace("\\", "/"))


def handle_upload(ch, user_dir, user, req):
    name = safe_name(req.get("name", ""))
    size = int(req.get("size", -1))
    expected_hash = req.get("sha256", "")
    if not name or size < 0 or size > MAX_FILE_SIZE:
        ch.send_json({"ok": False, "msg": "Invalid file name or size (max 100 MB)"})
        return
    ch.send_json({"ok": True, "msg": "Ready"})

    target = os.path.join(user_dir, name)
    tmp = target + ".part"
    received = 0
    h = __import__("hashlib").sha256()
    with open(tmp, "wb") as f:
        while received < size:
            chunk = ch.recv()
            f.write(chunk)
            h.update(chunk)
            received += len(chunk)

    if received == size and h.hexdigest() == expected_hash:
        os.replace(tmp, target)
        ch.send_json({"ok": True, "msg": "Upload complete, SHA-256 verified"})
        log.info("UPLOAD %s %s (%d bytes) OK", user, name, size)
        log_transfer(user, "UPLOAD", name, size, "OK")
    else:
        os.remove(tmp)
        ch.send_json({"ok": False, "msg": "Hash mismatch - file rejected"})
        log.warning("UPLOAD %s %s hash mismatch", user, name)
        log_transfer(user, "UPLOAD", name, size, "HASH_MISMATCH")


def handle_download(ch, user_dir, user, req):
    name = safe_name(req.get("name", ""))
    path = os.path.join(user_dir, name)
    if not name or not os.path.isfile(path):
        ch.send_json({"ok": False, "msg": "File not found"})
        return
    size = os.path.getsize(path)
    ch.send_json({"ok": True, "size": size, "sha256": common.file_sha256(path)})
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            ch.send(chunk)
    log.info("DOWNLOAD %s %s (%d bytes)", user, name, size)
    log_transfer(user, "DOWNLOAD", name, size, "OK")


def handle_client(conn, addr, private_key, public_pem):
    user = None
    try:
        # ---- Step 1 & 2: key exchange
        common.send_frame(conn, public_pem)
        encrypted_key = common.recv_frame(conn)
        session_key = common.rsa_decrypt(private_key, encrypted_key)
        ch = SecureChannel(conn, session_key, is_client=False)
        log.info("Secure channel established with %s:%s", *addr)

        # ---- Step 3: authentication (max 3 attempts)
        for attempt in range(3):
            req = ch.recv_json()
            if req.get("cmd") == "LOGIN" and verify_user(
                    USERS_FILE, req.get("user", ""), req.get("password", "")):
                user = req["user"]
                ch.send_json({"ok": True, "msg": f"Welcome {user}"})
                log.info("LOGIN OK: %s from %s", user, addr[0])
                break
            ch.send_json({"ok": False, "msg": f"Invalid login ({attempt + 1}/3)"})
            log.warning("LOGIN FAILED from %s", addr[0])
        if not user:
            return

        user_dir = os.path.join(STORAGE, safe_name(user))
        os.makedirs(user_dir, exist_ok=True)

        # ---- Step 4: command loop
        while True:
            req = ch.recv_json()
            cmd = req.get("cmd")
            if cmd == "LIST":
                files = sorted(f for f in os.listdir(user_dir) if not f.endswith(".part"))
                ch.send_json({"ok": True, "files": files})
            elif cmd == "UPLOAD":
                handle_upload(ch, user_dir, user, req)
            elif cmd == "DOWNLOAD":
                handle_download(ch, user_dir, user, req)
            elif cmd == "QUIT":
                ch.send_json({"ok": True, "msg": "Bye"})
                break
            else:
                ch.send_json({"ok": False, "msg": "Unknown command"})
    except SecurityError as e:
        log.error("SECURITY ALERT from %s: %s", addr[0], e)
    except (ConnectionError, OSError):
        pass
    except Exception as e:
        log.error("Error with %s: %s", addr[0], e)
    finally:
        conn.close()
        log.info("Connection closed: %s:%s", *addr)


def run_server(host="0.0.0.0", port=5001, ready_event=None):
    _, pub_path = common.generate_rsa_keys(os.path.join(BASE, "keys"))
    private_key = common.load_private_key(os.path.join(BASE, "keys", "server_private.pem"))
    public_pem = open(pub_path, "rb").read()
    log.info("Server key fingerprint: %s", common.fingerprint(public_pem))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    log.info("Server listening on %s:%d", host, port)
    if ready_event:
        ready_event.set()
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client,
                         args=(conn, addr, private_key, public_pem),
                         daemon=True).start()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5001)
    a = p.parse_args()
    if not os.path.exists(USERS_FILE):
        print("No users yet. Create one:  python add_user.py admin admin123")
    run_server(a.host, a.port)

