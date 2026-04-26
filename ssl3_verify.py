"""ssl3_verify.py — Real SSL 3.0 verification and LDAP testing against target server.

Uses nmap ssl-poodle for verification since modern OpenSSL 3.x has SSL 3.0
disabled at compile time (openssl s_client -ssl3 won't work on Kali 2024+).
"""

import subprocess
import re


def verify_ssl3(host: str, port: int) -> dict:
    """Verify SSL 3.0 / POODLE vulnerability using nmap ssl-poodle script."""
    result = {
        "host": host,
        "port": port,
        "vulnerable": False,
        "ssl_version": None,
        "cipher_suite": None,
        "cipher_is_cbc": False,
        "cert_subject": None,
        "cert_issuer": None,
        "nmap_output": None,
        "error": None,
    }

    # --- nmap ssl-poodle (primary check) ---
    try:
        proc = subprocess.run(
            ["nmap", "--script", "ssl-poodle", "-p", str(port), host],
            capture_output=True, timeout=30,
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        result["nmap_output"] = output

        if "VULNERABLE" in output.upper():
            result["vulnerable"] = True
            result["ssl_version"] = "SSLv3"

            # Extract cipher from nmap output if present
            cipher_match = re.search(r"cipher.*?:\s*(\S+)", output, re.IGNORECASE)
            if cipher_match:
                result["cipher_suite"] = cipher_match.group(1)

    except FileNotFoundError:
        result["error"] = "nmap not found in PATH"
        return result
    except subprocess.TimeoutExpired:
        result["error"] = "nmap scan timed out (30s)"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    # --- nmap ssl-enum-ciphers for cipher details ---
    try:
        proc2 = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host],
            capture_output=True, timeout=30,
        )
        enum_out = proc2.stdout.decode("utf-8", errors="replace")

        # Check for SSLv3 ciphers
        in_ssl3 = False
        for line in enum_out.splitlines():
            if "SSLv3" in line:
                in_ssl3 = True
            if in_ssl3 and "CBC" in line.upper():
                result["cipher_is_cbc"] = True
                # Extract cipher name
                m = re.search(r"TLS_\S+|SSL_\S+|\S+CBC\S*", line)
                if m and not result["cipher_suite"]:
                    result["cipher_suite"] = m.group(0)
            if in_ssl3 and line.strip().startswith("TLSv") and "SSLv3" not in line:
                in_ssl3 = False

        # If we found SSLv3 in enum but didn't get CBC info, check raw output
        if "SSLv3" in enum_out:
            if not result["cipher_suite"]:
                result["ssl_version"] = "SSLv3"
            if "CBC" in enum_out:
                result["cipher_is_cbc"] = True

    except (subprocess.TimeoutExpired, Exception):
        pass  # cipher enumeration is optional

    # --- Certificate info via openssl (doesn't need -ssl3) ---
    try:
        proc3 = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input=b"", capture_output=True, timeout=8,
        )
        combined = proc3.stdout.decode("utf-8", errors="replace") + \
                   proc3.stderr.decode("utf-8", errors="replace")

        subj = re.search(r"subject\s*=\s*(.+)", combined)
        if subj:
            result["cert_subject"] = subj.group(1).strip()

        issuer = re.search(r"issuer\s*=\s*(.+)", combined)
        if issuer:
            result["cert_issuer"] = issuer.group(1).strip()

        cipher = re.search(r"Cipher\s*:\s*(\S+)", combined)
        if cipher and cipher.group(1) not in ("0000", "(NONE)", "0"):
            if not result["cipher_suite"]:
                result["cipher_suite"] = cipher.group(1)

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass  # cert info is optional

    if not result["vulnerable"] and not result["error"]:
        result["error"] = "Server does not appear vulnerable to POODLE"

    return result


def _ber_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _build_ldap_bind(dn: str, password: str) -> bytes:
    """Build an LDAP Simple Bind Request in ASN.1 BER format."""
    dn_b = dn.encode("utf-8")
    pw_b = password.encode("utf-8")

    version = b"\x02\x01\x03"
    dn_tlv = b"\x04" + _ber_length(len(dn_b)) + dn_b
    pw_tlv = b"\x80" + _ber_length(len(pw_b)) + pw_b

    bind_content = version + dn_tlv + pw_tlv
    bind_req = b"\x60" + _ber_length(len(bind_content)) + bind_content

    msg_id = b"\x02\x01\x01"
    msg_content = msg_id + bind_req
    return b"\x30" + _ber_length(len(msg_content)) + msg_content


def _parse_ldap_bind_response(data: bytes) -> dict:
    """Parse an LDAP BindResponse from raw bytes."""
    try:
        if not data or data[0] != 0x30:
            return {"success": False, "error": "Not an LDAP response", "raw_hex": data.hex()}

        idx = 1
        if data[idx] & 0x80:
            len_bytes = data[idx] & 0x7F
            idx += 1 + len_bytes
        else:
            idx += 1

        if data[idx] == 0x02:
            idx += 1
            id_len = data[idx]
            idx += 1 + id_len

        if data[idx] == 0x61:
            idx += 1
            if data[idx] & 0x80:
                len_bytes = data[idx] & 0x7F
                idx += 1 + len_bytes
            else:
                idx += 1

            if data[idx] == 0x0A:
                idx += 1
                rc_len = data[idx]
                idx += 1
                result_code = int.from_bytes(data[idx:idx + rc_len], "big")
                return {
                    "success": result_code == 0,
                    "result_code": result_code,
                    "raw_hex": data[:40].hex(),
                }

        return {"success": False, "error": "Could not parse BindResponse", "raw_hex": data[:40].hex()}
    except (IndexError, ValueError) as e:
        return {"success": False, "error": str(e), "raw_hex": data[:40].hex() if data else ""}


def ldap_bind_ssl3(host: str, port: int, dn: str, password: str) -> dict:
    """Perform a real LDAP Simple Bind over SSL 3.0 against the target server.

    Uses ssl3_client.py directly — no OpenSSL CLI dependency, no certificate
    verification (matches real oracle behaviour).
    """
    from ssl3_client import SSL3Client

    result = {
        "host": host,
        "port": port,
        "dn": dn,
        "bind_success": False,
        "result_code": None,
        "request_hex": None,
        "response_hex": None,
        "error": None,
    }

    bind_req = _build_ldap_bind(dn, password)
    result["request_hex"] = bind_req.hex()

    try:
        client = SSL3Client(host, port)
        client.connect()
        client.send_appdata(bind_req)
        kind, data = client.read_response()
        client.close()

        if kind == "appdata" and data:
            result["response_hex"] = data[:60].hex()
            parsed = _parse_ldap_bind_response(data)
            result["bind_success"] = parsed.get("success", False)
            result["result_code"] = parsed.get("result_code")
            if not result["bind_success"] and "error" in parsed:
                result["error"] = parsed["error"]
        elif kind == "alert":
            result["error"] = f"SSL alert received (bad_record_mac or handshake_failure)"
        else:
            result["error"] = "No application data response from server"

    except ConnectionError as e:
        result["error"] = f"SSL 3.0 handshake failed: {e}"
    except OSError as e:
        result["error"] = f"Connection error: {e}"
    except Exception as e:
        result["error"] = str(e)

    return result
