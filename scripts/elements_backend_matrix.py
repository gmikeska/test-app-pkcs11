#!/usr/bin/env python3
"""
Elements backend-matrix e2e harness (republish DoD gate).

For each selected Elements chain backend (rpc / electrum / esplora / waterfalls)
this drives the *running* test-app-pkcs11 through the core Liquid lifecycle and
asserts it works on that backend:

    fund (node) -> app sync -> balance delta -> max-spend preview
                -> send back to node -> node receives it

It swaps ELEMENTS_CHAIN_BACKEND in .env, restarts the app, and runs the flow.
Assertions are DELTA-based (received-by-label at the node, app balance change),
so it is robust to the deterministic-key balance accumulation across re-runs.

Backends:
  rpc / electrum / esplora  -> runnable against the local regtest stack.
  waterfalls                -> needs a waterfalls server; skipped unless
                               ELEMENTS_WATERFALLS_URL is exported (Blockstream
                               enterprise, or a local OSS `waterfalls` instance).

Usage:
  python3 scripts/elements_backend_matrix.py                # rpc electrum esplora
  python3 scripts/elements_backend_matrix.py electrum rpc   # a subset
  ELEMENTS_WATERFALLS_URL=http://host:port \
      python3 scripts/elements_backend_matrix.py waterfalls

Env overrides (defaults match the 2026-08-01 regtest+electrum stack):
  APP_BASE            http://127.0.0.1:8095
  APP_DIR             /home/agent/Projects/asterism/test-app-pkcs11
  LAUNCH              /tmp/launch-pkcs11.sh
  ELEMENTS_RPC        http://elements:elementspass@host.docker.internal:18884
  ELECTRUM_URL        tcp://host.docker.internal:60112
  ESPLORA_URL         http://host.docker.internal:3112
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

APP_BASE = os.environ.get("APP_BASE", "http://127.0.0.1:8095")
APP_DIR = os.environ.get("APP_DIR", "/home/agent/Projects/asterism/test-app-pkcs11")
LAUNCH = os.environ.get("LAUNCH", "/tmp/launch-pkcs11.sh")
ENV_PATH = os.path.join(APP_DIR, ".env")
ELEMENTS_RPC = os.environ.get(
    "ELEMENTS_RPC", "http://elements:elementspass@host.docker.internal:18884"
)
ELECTRUM_URL = os.environ.get("ELECTRUM_URL", "tcp://host.docker.internal:60112")
ESPLORA_URL = os.environ.get("ESPLORA_URL", "http://host.docker.internal:3112")
WATERFALLS_URL = os.environ.get("ELEMENTS_WATERFALLS_URL")

FUND_LBTC = 0.002        # funded to test1 per backend run
FEE_LBTC = 0.001         # funded to the fee account (acct 99) per run
SYNC_WAIT_S = 18         # ingestion catch-up budget


# --------------------------------------------------------------------------
# node RPC (elementsd) via curl — matches the manual flow
# --------------------------------------------------------------------------
def erpc(method, params, wallet="default"):
    url = f"{ELEMENTS_RPC}/wallet/{wallet}" if wallet else ELEMENTS_RPC
    body = json.dumps({"jsonrpc": "1.0", "id": "matrix", "method": method, "params": params})
    out = subprocess.run(
        ["curl", "-s", "--data-binary", body, "-H", "content-type:text/plain", url],
        capture_output=True, text=True,
    ).stdout
    d = json.loads(out)
    if d.get("error"):
        raise RuntimeError(f"elementsd {method} error: {d['error']}")
    return d["result"]


# --------------------------------------------------------------------------
# app HTTP via curl with a per-user cookie jar
# --------------------------------------------------------------------------
def app_login(user):
    jar = f"/tmp/matrix-{user}.jar"
    subprocess.run(
        ["curl", "-s", "-c", jar, "-b", jar,
         "-d", f"email={user}@test.com&password=test1234",
         f"{APP_BASE}/login", "-o", "/dev/null"],
        capture_output=True, text=True,
    )
    return jar


def app_get(jar, path):
    return subprocess.run(
        ["curl", "-s", "-c", jar, "-b", jar, f"{APP_BASE}{path}"],
        capture_output=True, text=True,
    ).stdout


def liquid_balance(jar):
    html = app_get(jar, "/elements/wallet/receive")
    m = re.search(r"([0-9]+\.[0-9]{2,8})\s*L?-?BTC", html, re.I)
    return float(m.group(1)) if m else 0.0


def liquid_addr(jar):
    html = app_get(jar, "/elements/wallet/receive")
    m = re.search(r"el1[0-9a-z]{40,}", html, re.I)
    return m.group(0) if m else None


def max_spend_sat(jar, recipient):
    out = app_get(
        jar, f"/elements/wallet/max-spend?recipient_address={recipient}&fee_rate_sat_vb=2"
    )
    try:
        return int(json.loads(out).get("max_sat", 0))
    except Exception:
        return 0


def send_liquid(jar, recipient, amount_btc=None, send_max=False):
    # amount_btc is a required form field even for a max-drain (the handler
    # ignores it when send_max is set); always send it.
    args = ["curl", "-s", "-c", jar, "-b", jar,
            "--data-urlencode", f"recipient_address={recipient}",
            "--data-urlencode", f"amount_btc={amount_btc if amount_btc else '0'}",
            "--data-urlencode", "fee_rate_sat_vb=2",
            "--data-urlencode", "label=backend-matrix",
            "--data-urlencode", f"send_max={'true' if send_max else 'false'}",
            f"{APP_BASE}/elements/wallet/send", "-o", "/dev/null", "-w", "%{http_code}"]
    return subprocess.run(args, capture_output=True, text=True).stdout.strip()


# --------------------------------------------------------------------------
# app lifecycle: swap backend in .env + restart
# --------------------------------------------------------------------------
def set_backend(backend):
    with open(ENV_PATH) as f:
        lines = f.readlines()
    url_line = {
        "electrum": f"ELEMENTS_ELECTRUM_URL={ELECTRUM_URL}\n",
        "esplora": f"ELEMENTS_ESPLORA_URL={ESPLORA_URL}\n",
        "waterfalls": f"ELEMENTS_ESPLORA_URL={WATERFALLS_URL}\n",
    }.get(backend)
    out = []
    for ln in lines:
        if ln.startswith("ELEMENTS_CHAIN_BACKEND="):
            out.append(f"ELEMENTS_CHAIN_BACKEND={backend}\n")
        elif backend in ("esplora", "waterfalls") and ln.startswith("ELEMENTS_ESPLORA_URL="):
            out.append(url_line)
        else:
            out.append(ln)
    with open(ENV_PATH, "w") as f:
        f.writelines(out)


def restart_app():
    subprocess.run(["pkill", "-9", "-x", "test-app-pkcs11"], capture_output=True)
    time.sleep(1)
    subprocess.Popen(
        ["setsid", "bash", LAUNCH],
        stdin=subprocess.DEVNULL,
        stdout=open("/tmp/pkcs11-tn4.log", "w"),
        stderr=subprocess.STDOUT,
    )
    for _ in range(20):
        time.sleep(1)
        if subprocess.run(["pgrep", "-x", "test-app-pkcs11"], capture_output=True).returncode == 0:
            time.sleep(3)
            return True
    return False


# --------------------------------------------------------------------------
# one backend run
# --------------------------------------------------------------------------
def run_backend(backend):
    print(f"\n=== backend: {backend} ===", flush=True)
    if backend == "waterfalls" and not WATERFALLS_URL:
        return ("SKIP", "no ELEMENTS_WATERFALLS_URL (needs a waterfalls server)")

    set_backend(backend)
    if not restart_app():
        return ("FAIL", "app did not start")

    # Customer account can be overridden (HARNESS_CUSTOMER). For node-mode
    # waterfalls against an aged persistent chain, point it at a virgin account
    # (never funded before the waterfalls index started) so there is no
    # historical /tx lookup — the real-world "new wallet" onboarding case.
    cust = os.environ.get("HARNESS_CUSTOMER", "test1")
    t1 = app_login(cust)
    label = f"return-{backend}"

    erpc("settxfee", [0.0001])
    a1 = liquid_addr(t1)
    if not a1:
        return ("FAIL", "could not read Liquid receive address")
    bal_before = liquid_balance(t1)
    erpc("sendtoaddress", [a1, FUND_LBTC])
    # The fee account (acct 99) is only needed for migrations; a plain send-max
    # self-funds its fee. Skip it for a virgin-customer run.
    if os.environ.get("SKIP_FEE") != "1":
        admin = app_login("admin")
        a99 = liquid_addr(admin)
        if a99:
            erpc("sendtoaddress", [a99, FEE_LBTC])
    gen = erpc("getnewaddress", [])
    erpc("generatetoaddress", [2, gen])

    # sync via the selected backend
    time.sleep(SYNC_WAIT_S)
    bal_after = liquid_balance(t1)
    if bal_after < bal_before + FUND_LBTC - 1e-8:
        return ("FAIL", f"sync did not capture funding: {bal_before}->{bal_after} (want +{FUND_LBTC})")

    # max-spend preview (build path, no broadcast)
    ret_addr = erpc("getnewaddress", [f"{label}"])
    ms = max_spend_sat(t1, ret_addr)
    if ms <= 0:
        return ("FAIL", f"max-spend returned {ms} (funds not spendable on {backend})")

    # real send back to the node, signed + broadcast through this backend
    code = send_liquid(t1, ret_addr, send_max=True)
    if code != "303":
        return ("FAIL", f"send returned HTTP {code} (broadcast failed on {backend})")

    # confirm + verify the node received it
    gen2 = erpc("getnewaddress", [])
    erpc("generatetoaddress", [2, gen2])
    time.sleep(4)
    recv = erpc("getreceivedbyaddress", [ret_addr, 1])
    got = recv.get("bitcoin", recv) if isinstance(recv, dict) else recv
    if float(got) <= 0:
        return ("FAIL", f"node did not receive the return spend (got {got})")

    return ("PASS", f"sync+={FUND_LBTC} max_spend={ms}sat returned={got} L-BTC")


def main():
    backends = sys.argv[1:] or ["rpc", "electrum", "esplora"]
    results = {}
    for b in backends:
        try:
            results[b] = run_backend(b)
        except Exception as e:
            results[b] = ("FAIL", f"exception: {e}")
    print("\n================ BACKEND MATRIX ================")
    for b in backends:
        status, detail = results[b]
        mark = {"PASS": "✅", "FAIL": "❌", "SKIP": "⚠️"}.get(status, "?")
        print(f"{mark} {b:<11} {status:<5} {detail}")
    print("===============================================")
    if any(s == "FAIL" for s, _ in results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
