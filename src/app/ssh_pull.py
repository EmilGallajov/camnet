"""Pull running-configs from live devices over SSH and save them as .cfg files.

Uses netmiko. Best-effort: works when a reachable device + credentials are
provided; otherwise the demo path is ZIP upload. The pulled config is parsed
for a hostname so the saved file is named sensibly.
"""
import os
import re


def pull_config(host, username, password, dest_dir,
                device_type="cisco_ios", port=22, secret=None):
    from netmiko import ConnectHandler

    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": int(port),
        "fast_cli": False,
        "conn_timeout": 20,
    }
    if secret:
        params["secret"] = secret

    conn = ConnectHandler(**params)
    try:
        if secret:
            conn.enable()
        output = conn.send_command("show running-config", read_timeout=60)
    finally:
        conn.disconnect()

    hostname = _hostname_from_config(output) or _safe(host)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, f"{hostname}.cfg")
    with open(path, "w") as f:
        f.write(output)
    return {"hostname": hostname, "path": path, "bytes": len(output)}


def _hostname_from_config(text):
    m = re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)
    return _safe(m.group(1)) if m else None


def _safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name))
