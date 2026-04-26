const socket = io();

// DOM
const $ = id => document.getElementById(id);
const elHost = $('host'), elPort = $('port');
const elBindDn = $('bind-dn'), elBindPassword = $('bind-password');
const elSpeed = $('speed');

const btnVerify = $('btn-verify'), btnBind = $('btn-bind');
const btnAttack = $('btn-attack'), btnStop = $('btn-stop'), btnReset = $('btn-reset');

let totalBytes = 0, recoveredCount = 0, totalAttempts = 0;
let blockInfo = null, sslVerified = false, bindTested = false;

function ts() { return new Date().toLocaleTimeString('en-US', {hour12:false}); }
function esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
function log(msg, level='info') {
    const el = $('log-console');
    const e = document.createElement('div');
    e.className = 'log-entry log-' + level;
    e.innerHTML = `<span class="ts">${ts()}</span>${esc(msg)}`;
    el.appendChild(e);
    el.scrollTop = el.scrollHeight;
}

// --- Phase 1: Verify ---
btnVerify.onclick = () => {
    btnVerify.disabled = true;
    socket.emit('verify', {host: elHost.value, port: +elPort.value});
    setTimeout(() => { btnVerify.disabled = false; }, 3000);
};

socket.on('verify_result', data => {
    const r = $('verify-results');
    r.style.display = 'block';

    if (data.vulnerable) {
        $('ssl-status').textContent = 'VULNERABLE';
        $('ssl-status').className = 'rv status-vuln';
        sslVerified = true;
        btnBind.disabled = false;
    } else {
        $('ssl-status').textContent = data.error || 'Not vulnerable';
        $('ssl-status').className = 'rv status-safe';
        sslVerified = false;
        btnBind.disabled = true;
        btnAttack.disabled = true;
    }
    $('ssl-version').textContent = data.ssl_version || '—';
    $('ssl-cipher').textContent = data.cipher_suite || '—';
    $('ssl-cbc').textContent = data.cipher_is_cbc ? 'YES (required for POODLE)' : 'NO';
    $('ssl-cbc').className = 'rv ' + (data.cipher_is_cbc ? 'status-vuln' : 'status-safe');
    $('ssl-subject').textContent = data.cert_subject || '—';
    $('ssl-issuer').textContent = data.cert_issuer || '—';
});

// --- Phase 2: LDAP Bind ---
btnBind.onclick = () => {
    btnBind.disabled = true;
    socket.emit('ldap_bind', {
        host: elHost.value, port: +elPort.value,
        bind_dn: elBindDn.value, bind_password: elBindPassword.value
    });
    setTimeout(() => { btnBind.disabled = false; }, 3000);
};

socket.on('ldap_bind_result', data => {
    const r = $('bind-results');
    r.style.display = 'block';

    if (data.bind_success) {
        $('bind-status').textContent = 'SUCCESS — credentials accepted over SSL 3.0';
        $('bind-status').className = 'rv status-ok';
        bindTested = true;
        btnAttack.disabled = false;
    } else {
        $('bind-status').textContent = data.error || `FAILED (code ${data.result_code})`;
        $('bind-status').className = 'rv status-fail';
        // still allow attack even if bind fails (might be network issue)
        if (sslVerified) btnAttack.disabled = false;
    }
    $('bind-req-hex').textContent = data.request_hex || '—';
    $('bind-resp-hex').textContent = data.response_hex || '—';
});

// --- Phase 3: Attack ---
btnAttack.onclick = () => {
    if (!elBindPassword.value) { log('Password required', 'error'); return; }
    totalBytes = 0; recoveredCount = 0; totalAttempts = 0;
    btnAttack.disabled = true;
    btnStop.disabled = false;
    btnVerify.disabled = true;
    btnBind.disabled = true;
    // Hide password during attack
    elBindPassword.type = 'password';

    const realOracle = document.getElementById('chkRealOracle');
    socket.emit('start_attack', {
        host: elHost.value, port: +elPort.value,
        bind_dn: elBindDn.value, bind_password: elBindPassword.value,
        speed: elSpeed.value,
        real_oracle: realOracle ? realOracle.checked : false
    });
};

btnStop.onclick = () => {
    socket.emit('stop_attack');
    btnAttack.disabled = false;
    btnStop.disabled = true;
    btnVerify.disabled = false;
    btnBind.disabled = false;
};

btnReset.onclick = () => {
    socket.emit('stop_attack');
    totalBytes = 0; recoveredCount = 0; totalAttempts = 0;
    sslVerified = false; bindTested = false; blockInfo = null;
    btnAttack.disabled = true;
    btnStop.disabled = true;
    btnVerify.disabled = false;
    btnBind.disabled = true;
    $('verify-results').style.display = 'none';
    $('bind-results').style.display = 'none';
    $('attack-panel').style.display = 'none';
    elBindPassword.type = 'password';
    log('Reset', 'info');
};

$('btn-clear-log').onclick = () => { $('log-console').innerHTML = ''; };

socket.on('attack_aborted', data => {
    log('Attack aborted: ' + data.reason, 'error');
    btnAttack.disabled = false;
    btnStop.disabled = true;
    btnVerify.disabled = false;
    btnBind.disabled = false;
});

socket.on('attack_started', data => {
    totalBytes = data.total_bytes;
    blockInfo = data.block_info;
    $('attack-panel').style.display = 'block';
    initBlocks(data.block_info);
    initPassword(totalBytes);
});

function initBlocks(info) {
    const c = $('blocks-container');
    c.innerHTML = '';
    // IV
    const iv = document.createElement('div');
    iv.className = 'blk blk-iv'; iv.textContent = 'IV';
    c.appendChild(iv);
    for (let i = 0; i < info.n_blocks; i++) {
        const b = document.createElement('div');
        b.className = 'blk blk-data';
        b.id = 'blk-' + i;
        b.textContent = 'C' + i;
        if (i >= info.n_blocks - 2) { b.classList.remove('blk-data'); b.classList.add('blk-pad'); }
        c.appendChild(b);
    }
}

function initPassword(n) {
    const pr = $('password-row'), hr = $('hex-row');
    pr.innerHTML = ''; hr.innerHTML = '';
    for (let i = 0; i < n; i++) {
        const p = document.createElement('div');
        p.className = 'pcell'; p.id = 'pc-' + i; p.textContent = '?';
        pr.appendChild(p);
        const h = document.createElement('div');
        h.className = 'hcell'; h.id = 'hc-' + i; h.textContent = '??';
        hr.appendChild(h);
    }
}

// Oracle attempts — update UI
socket.on('attempt', data => {
    totalAttempts++;
    $('oracle-total').textContent = totalAttempts;
    $('oracle-current').textContent = data.attempt_num;

    const ind = $('oracle-indicator');
    if (data.oracle_hit) {
        ind.textContent = 'HIT!';
        ind.className = 'oracle-hit hit';
    } else {
        ind.textContent = 'MISS';
        ind.className = 'oracle-hit miss';
    }

    $('progress-text').textContent = `Byte ${data.byte_index + 1} / ${totalBytes}`;

    // Flash the target block red on miss
    if (!data.oracle_hit && blockInfo) {
        const abs = blockInfo.prefix_len +
                    (blockInfo.plaintext_len - elBindPassword.value.length) +
                    data.byte_index;
        const bi = Math.floor(abs / 16);
        const blk = $('blk-' + bi);
        if (blk && !blk.classList.contains('blk-ok')) {
            blk.classList.add('blk-miss');
            setTimeout(() => blk.classList.remove('blk-miss'), 120);
        }
    }

    // Set active cell
    const pc = $('pc-' + data.byte_index);
    if (pc && !pc.classList.contains('found')) pc.classList.add('active');
});

socket.on('byte_recovered', data => {
    recoveredCount = data.byte_index + 1;
    const pct = (data.progress * 100).toFixed(1);
    $('progress-bar').style.width = pct + '%';
    $('avg-attempts').textContent = (data.total_attempts / recoveredCount).toFixed(0);
    $('elapsed-time').textContent = (data.elapsed || 0) + 's';
    totalAttempts = data.total_attempts;
    $('oracle-total').textContent = totalAttempts;

    // Reveal byte
    const pc = $('pc-' + data.byte_index);
    if (pc) {
        pc.textContent = data.byte_char;
        pc.classList.remove('active');
        pc.classList.add('found');
    }
    const hc = $('hc-' + data.byte_index);
    if (hc) {
        hc.textContent = data.byte_value.toString(16).toUpperCase().padStart(2, '0');
        hc.classList.add('found');
    }

    // Mark block recovered
    if (blockInfo) {
        const abs = blockInfo.prefix_len +
                    (blockInfo.plaintext_len - elBindPassword.value.length) +
                    data.byte_index;
        const bi = Math.floor(abs / 16);
        const blk = $('blk-' + bi);
        if (blk) { blk.className = 'blk blk-ok'; }
    }
});

socket.on('attack_complete', data => {
    btnAttack.disabled = false;
    btnStop.disabled = true;
    btnVerify.disabled = false;
    btnBind.disabled = false;
    $('progress-bar').style.width = '100%';
    $('elapsed-time').textContent = (data.elapsed || 0) + 's';

    // Mark all cells complete
    for (let i = 0; i < totalBytes; i++) {
        const pc = $('pc-' + i);
        if (pc) pc.classList.add('complete');
    }
});

socket.on('attack_stopped', () => {
    btnAttack.disabled = false;
    btnStop.disabled = true;
    btnVerify.disabled = false;
    btnBind.disabled = false;
});

socket.on('log', data => log(data.msg, data.level));
socket.on('connect', () => log('Connected', 'info'));
socket.on('disconnect', () => { log('Disconnected', 'warn'); btnAttack.disabled = true; btnStop.disabled = true; });
