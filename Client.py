"""
client.py - Secure File Transfer Client (menu driven)

Run:  python client.py [--host 127.0.0.1] [--port 5001]
"""
import os
import socket
import getpass
import argparse

import common
from common import SecureChannel, SecurityError, CHUNK_SIZE

BASE = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_DIR = os.path.join(BASE, "client_downloads")
KNOWN_FILE = os.path.join(BASE, "known_server.txt")   # remembers server fingerprint


class SecureClient:
    def __init__(self, host="127.0.0.1", port=5001):
        self.host, self.port = host, port
        self.ch = None

    # ------------------------------------------------ connect + key exchange
    def connect(self):
        sock = socket.create_connection((self.host, self.port))
        public_pem = common.recv_frame(sock)           # server's RSA public key

        # Trust-on-first-use: remember the fingerprint, warn if it changes (MITM check)
        fp = common.fingerprint(public_pem)
        if os.path.exists(KNOWN_FILE):
            if open(KNOWN_FILE).read().strip() != fp:
                sock.close()
                raise SecurityError("SERVER KEY CHANGED! Possible man-in-the-middle attack.")
        else:
            open(KNOWN_FILE, "w").write(fp)
            print(f"[i] First connection. Server fingerprint saved:\n    {fp}")

        # Create random 256-bit session key, send it encrypted with server's RSA key
        session_key = os.urandom(32)
        public_key = common.load_public_key_pem(public_pem)
        common.send_frame(sock, common.rsa_encrypt(public_key, session_key))
        self.ch = SecureChannel(sock, session_key, is_client=True)

    # ------------------------------------------------ commands
    def login(self, user, password):
        self.ch.send_json({"cmd": "LOGIN", "user": user, "password": password})
        return self.ch.recv_json()

    def list_files(self):
        self.ch.send_json({"cmd": "LIST"})
        return self.ch.recv_json().get("files", [])

    def upload(self, path):
        size = os.path.getsize(path)
        self.ch.send_json({"cmd": "UPLOAD", "name": os.path.basename(path),
                           "size": size, "sha256": common.file_sha256(path)})
        reply = self.ch.recv_json()
        if not reply["ok"]:
            return reply
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                self.ch.send(chunk)
        return self.ch.recv_json()

    def download(self, name, dest_dir=DOWNLOAD_DIR):
        os.makedirs(dest_dir, exist_ok=True)
        self.ch.send_json({"cmd": "DOWNLOAD", "name": name})
        reply = self.ch.recv_json()
        if not reply["ok"]:
            return reply
        target = os.path.join(dest_dir, os.path.basename(name))
        received = 0
        with open(target, "wb") as f:
            while received < reply["size"]:
                chunk = self.ch.recv()
                f.write(chunk)
                received += len(chunk)
        if common.file_sha256(target) == reply["sha256"]:
            return {"ok": True, "msg": f"Saved to {target} (SHA-256 verified)"}
        os.remove(target)
        return {"ok": False, "msg": "Hash mismatch - file discarded"}

    def quit(self):
        try:
            self.ch.send_json({"cmd": "QUIT"})
            self.ch.recv_json()
        finally:
            self.ch.sock.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5001)
    a = p.parse_args()

    c = SecureClient(a.host, a.port)
    try:
        c.connect()
    except (SecurityError, ConnectionError, OSError) as e:
        print("Connection failed:", e)
        return
    print("[+] Secure channel established (RSA key exchange + AES-256-GCM)")

    for _ in range(3):
        user = input("Username: ")
        pwd = getpass.getpass("Password: ")
        r = c.login(user, pwd)
        print(r["msg"])
        if r["ok"]:
            break
    else:
        return

    while True:
        print("\n1. List files  2. Upload  3. Download  4. Quit")
        choice = input("Choice: ").strip()
        try:
            if choice == "1":
                files = c.list_files()
                print("\n".join(f" - {f}" for f in files) if files else "(no files)")
            elif choice == "2":
                path = input("Path of file to upload: ").strip().strip('"')
                if os.path.isfile(path):
                    print(c.upload(path)["msg"])
                else:
                    print("File not found")
            elif choice == "3":
                print(c.download(input("File name to download: ").strip())["msg"])
            elif choice == "4":
                c.quit()
                break
        except (SecurityError, ConnectionError) as e:
            print("Connection error:", e)
            break


if __name__ == "__main__":
    main()
  
