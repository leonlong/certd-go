let currentCertId = null;

const API_BASE = '/api/certs';

async function api(method, path, body) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(API_BASE + path, opts);
    if (!res.ok) {
        const err = await res.text();
        throw new Error(err);
    }
    if (res.status === 204) return null;
    return res.json();
}

async function loadCerts() {
    try {
        const certs = await api('GET', '');
        renderCertList(certs);
    } catch (e) {
        showToast('加载证书失败: ' + e.message, 'error');
    }
}

function renderCertList(certs) {
    const list = document.getElementById('certList');

    if (certs.length === 0) {
        list.innerHTML = '<div class="loading">暂无证书</div>';
        return;
    }

    list.innerHTML = certs.map(cert => {
        const status = cert.Status ? cert.Status() : getStatus(cert);
        const days = cert.ValidDays ? cert.ValidDays() : getValidDays(cert);
        const statusClass = status === 'expired' ? 'expired' : status === 'expiring' ? 'expiring' : 'valid';

        return `
            <div class="cert-item ${currentCertId === cert.id || currentCertId === cert.Domain ? 'active' : ''}"
                 onclick="showDetail('${cert.id || cert.Domain}')">
                <div class="cert-item-name">${cert.Domain}</div>
                <div class="cert-item-meta">${cert.Provider || cert.issuer || '-'}</div>
                <div class="cert-item-meta">${days} 天</div>
                <span class="cert-item-status ${statusClass}">${getStatusText(status)}</span>
            </div>
        `;
    }).join('');
}

function getStatus(cert) {
    const now = new Date();
    const notAfter = new Date(cert.notAfter || cert.NotAfter);
    if (now > notAfter) return 'expired';
    const days = (notAfter - now) / (1000 * 60 * 60 * 24);
    if (days <= 30) return 'expiring';
    return 'valid';
}

function getValidDays(cert) {
    const now = new Date();
    const notAfter = new Date(cert.notAfter || cert.NotAfter);
    if (now > notAfter) return 0;
    return Math.floor((notAfter - now) / (1000 * 60 * 60 * 24));
}

function getStatusText(status) {
    return { valid: '有效', expiring: '即将过期', expired: '已过期' }[status] || status;
}

function showAddForm() {
    currentCertId = null;
    document.getElementById('contentTitle').textContent = '添加证书';
    document.getElementById('addForm').classList.remove('hidden');
    document.getElementById('detailView').classList.add('hidden');
    document.getElementById('certForm').reset();

    document.querySelectorAll('.cert-item').forEach(el => el.classList.remove('active'));

    updateFormVisibility();
}

function updateFormVisibility() {
    const provider = document.getElementById('provider').value;
    const emailRow = document.getElementById('emailRow');
    const apiRow = document.getElementById('apiRow');

    if (provider === 'letsencrypt') {
        emailRow.classList.remove('hidden');
        apiRow.classList.add('hidden');
    } else if (provider === 'selfsigned') {
        emailRow.classList.add('hidden');
        apiRow.classList.add('hidden');
    } else {
        emailRow.classList.add('hidden');
        apiRow.classList.remove('hidden');
    }
}

document.getElementById('provider').addEventListener('change', updateFormVisibility);

document.getElementById('certForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const domain = document.getElementById('domain').value.trim();
    const certType = document.getElementById('certType').value;
    let altNames = document.getElementById('altNames').value
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);

    if (!domain) {
        showToast('请输入域名', 'error');
        return;
    }

    if (certType === 'wildcard') {
        if (!domain.startsWith('*.')) {
            showToast('通配符域名必须以 *. 开头', 'error');
            return;
        }
        const rootDomain = domain.substring(2);
        if (!altNames.includes(rootDomain)) {
            altNames = [rootDomain, ...altNames];
        }
    }
    try {
        const cert = await api('GET', '/' + encodeURIComponent(id));
        if (!cert) return;

        currentCertId = cert.id || cert.Domain;

        document.querySelectorAll('.cert-item').forEach(el => {
            el.classList.toggle('active', el.onclick.toString().includes(id));
        });

        document.getElementById('contentTitle').textContent = '证书详情';
        document.getElementById('addForm').classList.add('hidden');
        document.getElementById('detailView').classList.remove('hidden');

        const notBefore = new Date(cert.NotBefore || cert.notBefore);
        const notAfter = new Date(cert.NotAfter || cert.notAfter);
        const days = cert.ValidDays ? cert.ValidDays() : getValidDays(cert);
        const status = cert.Status ? cert.Status() : getStatus(cert);

        document.getElementById('detailDomain').textContent = cert.Domain;
        document.getElementById('detailStatus').textContent = getStatusText(status);
        document.getElementById('detailStatus').className = 'badge ' + status;
        document.getElementById('detailValidity').textContent =
            `${formatDate(notBefore)} ~ ${formatDate(notAfter)} (${days}天)`;
        document.getElementById('detailNotBefore').textContent = formatDate(notBefore);
        document.getElementById('detailNotAfter').textContent = formatDate(notAfter);
        document.getElementById('detailProvider').textContent = cert.Provider || cert.Issuer || '-';
        document.getElementById('detailDNSProvider').textContent = cert.DNSProvider || '-';
        document.getElementById('detailCertType').textContent = (cert.CertType || 'DV').toUpperCase();
        document.getElementById('detailSerial').textContent = cert.SerialNum || '-';
        document.getElementById('detailFingerprint').textContent = cert.Fingerprint || '-';
        document.getElementById('editProject').value = cert.Project || '';
        document.getElementById('editOwner').value = cert.Owner || '';
        document.getElementById('editNotes').value = cert.Notes || '';

    } catch (e) {
        showToast('加载失败: ' + e.message, 'error');
    }
}

function formatDate(d) {
    if (typeof d === 'string') d = new Date(d);
    return d.toLocaleDateString('zh-CN');
}

document.getElementById('certForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const domain = document.getElementById('domain').value.trim();
    const altNames = document.getElementById('altNames').value
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);

    if (!domain) {
        showToast('请输入域名', 'error');
        return;
    }

    const body = {
        domain,
        altNames,
        provider: document.getElementById('provider').value,
        dnsProvider: document.getElementById('dnsProvider').value,
        certType: document.getElementById('certType').value,
        email: document.getElementById('email').value,
        apiKey: document.getElementById('apiKey').value,
        apiSecret: document.getElementById('apiSecret').value
    };

    const btn = e.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = '生成中...';

    try {
        const cert = await api('POST', '', body);
        showToast('证书生成成功', 'success');
        loadCerts();
        showDetail(cert.id || cert.Domain);
    } catch (e) {
        showToast('生成失败: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = '生成证书';
    }
});

async function saveCert() {
    if (!currentCertId) return;

    try {
        const cert = await api('PUT', '/' + encodeURIComponent(currentCertId), {
            project: document.getElementById('editProject').value,
            owner: document.getElementById('editOwner').value,
            notes: document.getElementById('editNotes').value
        });
        showToast('保存成功', 'success');
    } catch (e) {
        showToast('保存失败: ' + e.message, 'error');
    }
}

async function deleteCert() {
    if (!currentCertId) return;
    if (!confirm('确定删除此证书?')) return;

    try {
        await api('DELETE', '/' + encodeURIComponent(currentCertId));
        showToast('已删除', 'success');
        showAddForm();
        loadCerts();
    } catch (e) {
        showToast('删除失败: ' + e.message, 'error');
    }
}

function downloadCert() {
    if (!currentCertId) return;
    window.open(API_BASE + '/' + encodeURIComponent(currentCertId) + '/download');
}

async function renewCert() {
    if (!currentCertId) return;
    showToast('续期功能开发中', 'error');
}

document.getElementById('searchInput').addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('.cert-item').forEach(el => {
        const name = el.querySelector('.cert-item-name').textContent.toLowerCase();
        el.style.display = name.includes(q) ? '' : 'none';
    });
});

function showToast(msg, type = '') {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = 'toast show ' + type;
    setTimeout(() => toast.classList.remove('show'), 3000);
}

document.addEventListener('DOMContentLoaded', () => {
    loadCerts();
    showAddForm();
});
