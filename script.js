// ═══════════════════════════════════════════════════════════════════════
//   Sızma Testi Otomasyon Aracı — Frontend Controller
// ═══════════════════════════════════════════════════════════════════════

const API = {
  stats:      ()      => fetch('/api/stats').then(r => r.json()),
  scans:      ()      => fetch('/api/scans').then(r => r.json()),
  scan:       (id)    => fetch(`/api/scans/${id}`).then(r => r.json()),
  startScan:  (data)  => fetch('/api/scans', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
  }).then(r => r.json()),
  deleteScan: (id)    => fetch(`/api/scans/${id}`, {method: 'DELETE'}).then(r => r.json()),
  scanners:   ()      => fetch('/api/scanners').then(r => r.json()),
  scenarios:  ()      => fetch('/api/scenarios').then(r => r.json()),
};

// ── Modül başına detaylı tooltip içeriği ────────────────────────────────
const MODULE_DETAILS = {
  ports: {
    title: 'Port Tarama',
    owasp: '',
    icon: 'ico-ports',
    tooltip: 'Hedefte hangi TCP portlarının dışarıya açık olduğunu tespit eder. ' +
             'Yaygın portları (FTP, SSH, MySQL, Redis, RDP vb.) tarar. Nmap ' +
             'kuruluysa kullanır, yoksa Python socket fallback. Açık MySQL veya ' +
             'Redis gibi servisler genelde kritik zafiyettir.',
    avgSeconds: 8,
  },
  sqli: {
    title: 'SQL Injection',
    owasp: 'A03',
    icon: 'ico-sqli',
    tooltip: 'URL parametrelerine kötü niyetli SQL sözdizimi enjekte ederek ' +
             'veritabanı hata mesajlarını veya zamanlama davranışını gözlemler. ' +
             'MySQL, PostgreSQL, MSSQL, Oracle ve SQLite DBMS imzalarını tanır.',
    avgSeconds: 6,
  },
  xss: {
    title: 'Cross-Site Scripting',
    owasp: 'A03',
    icon: 'ico-xss',
    tooltip: 'URL parametrelerine JavaScript kodu enjekte eder ve bu payload\'ın ' +
             'sayfada filtrelenmeden yansıtılıp yansıtılmadığını kontrol eder. ' +
             'Reflected XSS tespiti yapar.',
    avgSeconds: 5,
  },
  misconfig: {
    title: 'Yapılandırma Hataları',
    owasp: 'A05',
    icon: 'ico-misconfig',
    tooltip: 'Eksik güvenlik başlıkları (HSTS, CSP, X-Frame-Options), hassas ' +
             'dosyalar (.env, .git/config, wp-config.php), açık dizin listeleme ' +
             've riskli endpointler (/phpinfo, /server-status) tespit eder.',
    avgSeconds: 7,
  },
  sensitive_data: {
    title: 'Hassas Veri Sızıntısı',
    owasp: 'A02',
    icon: 'ico-sensitive_data',
    tooltip: 'Sayfa içeriğinde sızmış API anahtarları (AWS, Google), JWT token, ' +
             'e-posta, kredi kartı, dahili IP, private key ve şifre kalıpları ' +
             'arar. HTTPS kullanılmamasını da işaretler.',
    avgSeconds: 5,
  },
  access_control: {
    title: 'Erişim Kontrolü',
    owasp: 'A01',
    icon: 'ico-access_control',
    tooltip: 'Korumasız yönetici panellerini (/admin, /yonetim, /phpmyadmin gibi) ' +
             've IDOR zafiyetlerini (kimlik doğrulamasız /api/users/1 erişimi) ' +
             'tespit eder.',
    avgSeconds: 6,
  },
  scenarios: {
    title: 'Özel Senaryolar',
    owasp: '',
    icon: 'ico-scenarios',
    tooltip: 'YAML tabanlı özelleştirilebilir senaryolar. scenarios_data/ ' +
             'klasöründeki .yaml dosyalarını okur ve her senaryoyu hedefe karşı ' +
             'çalıştırır. Nuclei benzeri bir DSL kullanır. Kendi testlerinizi ' +
             'ekleyebilirsiniz.',
    avgSeconds: 4,
  },
  sqlmap: {
    title: 'SQLMap',
    owasp: 'A03',
    icon: 'ico-sqlmap',
    tooltip: 'SQLMap entegrasyonu (opsiyonel): Sistemde SQLMap binary\'si ' +
             'kuruluysa subprocess olarak çağırır ve sonuçları yorumlar. Yoksa ' +
             'pas geçer. Kendi SQLi tarayıcımızdan çok daha derin testler yapar ' +
             '(1-5 dakika).',
    avgSeconds: 120,
  },
};

// ── Sayfa Navigasyonu ──────────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => showPage(item.dataset.page));
});

function showPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(pageId).classList.remove('hidden');
  document.querySelector(`.nav-item[data-page="${pageId}"]`).classList.add('active');

  if (pageId === 'dashboard') loadDashboard();
  if (pageId === 'reports')   loadReports();
  if (pageId === 'scenarios') loadScenarios();
  if (pageId === 'newscan')   loadModules();
}

// ── Dashboard ───────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const stats = await API.stats();
    setText('stat-total-scans',  stats.total_scans || 0);
    setText('stat-total-vulns',  stats.total_vulnerabilities || 0);
    setText('stat-critical',     stats.critical_count || 0);
    setText('stat-high',         stats.high_count || 0);
  } catch (e) { console.error(e); }

  await loadRecentScans();
}

async function loadRecentScans() {
  const container = document.getElementById('recent-scans');
  try {
    const scans = await API.scans();
    if (!scans.length) {
      container.innerHTML = '<div class="loading">Henüz hiç tarama yapılmamış.</div>';
      return;
    }
    container.innerHTML = renderScansTable(scans.slice(0, 10));
  } catch (e) {
    container.innerHTML = '<div class="loading">Yüklenemedi.</div>';
  }
}

function renderScansTable(scans) {
  const header = `
    <div class="scan-row header">
      <div>ID</div>
      <div>HEDEF</div>
      <div>DURUM</div>
      <div>TARİH</div>
      <div>ZAFİYET</div>
      <div></div>
    </div>`;

  const rows = scans.map(s => {
    const date = s.started_at ? s.started_at.substring(0, 16).replace('T', ' ') : '-';
    const statusClass = `status-${s.status || 'pending'}`;
    return `
      <div class="scan-row">
        <div>#${s.id}</div>
        <div class="scan-target" title="${escapeHtml(s.target_url)}">${escapeHtml(s.target_url)}</div>
        <div><span class="status-pill ${statusClass}">${s.status || '-'}</span></div>
        <div class="scan-date">${date}</div>
        <div class="vuln-count">${s.vuln_count || 0}</div>
        <div class="scan-actions">
          <a class="btn-icon btn-html" href="/api/scans/${s.id}/report" target="_blank"
             title="HTML rapor görüntüle">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          </a>
          <a class="btn-icon btn-pdf" href="/api/scans/${s.id}/report.pdf" target="_blank"
             title="PDF olarak indir">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
          </a>
          <a class="btn-icon btn-json" href="/api/scans/${s.id}/report.json" target="_blank"
             title="JSON indir">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="16 18 22 12 16 6"/>
              <polyline points="8 6 2 12 8 18"/>
            </svg>
          </a>
          <button class="btn-icon btn-danger" onclick="deleteScan(${s.id})"
                  title="Sil">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
                 stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"/>
              <path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"/>
              <path d="M10 11v6M14 11v6"/>
            </svg>
          </button>
        </div>
      </div>`;
  }).join('');

  return header + rows;
}

async function deleteScan(id) {
  if (!confirm(`Tarama #${id}'i silmek istediğinize emin misiniz?`)) return;
  await API.deleteScan(id);
  loadDashboard();
  loadReports();
}

// ── Yeni Tarama: Modül Kartları ─────────────────────────────────────────
let availableModules = [];
let selectedModules = new Set();

async function loadModules() {
  if (availableModules.length) return;
  const container = document.getElementById('module-list');
  try {
    availableModules = await API.scanners();
    renderModuleCards();
  } catch (e) {
    container.innerHTML = '<div class="loading">Modüller yüklenemedi.</div>';
  }
}

function renderModuleCards() {
  const container = document.getElementById('module-list');

  // Default seçimleri uygula
  if (selectedModules.size === 0) {
    availableModules.filter(m => m.default).forEach(m => selectedModules.add(m.name));
  }

  container.innerHTML = availableModules.map(m => {
    const detail = MODULE_DETAILS[m.name] || {};
    const isSelected = selectedModules.has(m.name);
    const iconId = detail.icon || 'ico-misconfig';
    const owaspBadge = detail.owasp
      ? `<span class="module-owasp-badge">${detail.owasp}</span>`
      : '';

    return `
      <div class="module-card ${isSelected ? 'selected' : ''}"
           data-module="${m.name}" tabindex="0">
        <div class="module-card-header">
          <div class="module-card-icon">
            <svg width="22" height="22"><use href="#${iconId}"/></svg>
          </div>
          <div class="module-card-title">
            ${escapeHtml(detail.title || m.name)}
            ${owaspBadge}
          </div>
        </div>
        <div class="module-card-desc">
          ${escapeHtml(m.description)}
        </div>
        <button class="module-info-btn" tabindex="0"
                aria-label="Detaylı bilgi"
                onclick="event.stopPropagation()">i</button>
        <div class="module-tooltip" role="tooltip">
          <div class="tooltip-title">
            <svg width="16" height="16"><use href="#${iconId}"/></svg>
            ${escapeHtml(detail.title || m.name)}
            ${owaspBadge}
          </div>
          <div class="tooltip-body">
            ${escapeHtml(detail.tooltip || m.description)}
          </div>
        </div>
      </div>`;
  }).join('');

  // Kart tıklama mantığı
  container.querySelectorAll('.module-card').forEach(card => {
    card.addEventListener('click', e => {
      // Tooltip butonu tıklamasını yoksay
      if (e.target.closest('.module-info-btn')) return;
      const name = card.dataset.module;
      if (selectedModules.has(name)) {
        selectedModules.delete(name);
        card.classList.remove('selected');
      } else {
        selectedModules.add(name);
        card.classList.add('selected');
      }
    });
  });
}

// Quick action butonları
document.getElementById('select-all-btn').addEventListener('click', () => {
  selectedModules = new Set(availableModules.map(m => m.name));
  renderModuleCards();
});

document.getElementById('select-quick-btn').addEventListener('click', () => {
  selectedModules = new Set(['sqli', 'xss', 'misconfig']);
  renderModuleCards();
});

document.getElementById('select-none-btn').addEventListener('click', () => {
  selectedModules = new Set();
  renderModuleCards();
});

document.getElementById('start-scan-btn').addEventListener('click', startScan);

// ── Tarama Başlatma + Progress Bar ──────────────────────────────────────
async function startScan() {
  const target = document.getElementById('scan-target').value.trim();
  if (!target) return showResult('Lütfen hedef URL girin', 'error');
  if (selectedModules.size === 0)
    return showResult('En az bir modül seçmelisiniz', 'error');

  const modules = Array.from(selectedModules);
  const btn = document.getElementById('start-scan-btn');
  btn.disabled = true;

  hideResult();
  startProgressAnimation(modules);

  try {
    const result = await API.startScan({ target, modules, sync: true });
    stopProgressAnimation();

    if (result.error) {
      showResult(`Hata: ${result.error}`, 'error');
    } else {
      const vc = result.vulnerability_count || 0;
      const brk = result.severity_breakdown || {};
      const duration = result.duration_seconds
        ? `${result.duration_seconds.toFixed(1)} sn` : '-';
      showResult(
        `✅ Tarama tamamlandı!\n\n` +
        `Tarama ID: #${result.scan_id}\n` +
        `Toplam zafiyet: ${vc}\n` +
        `Kritik: ${brk.Critical || 0}  •  Yüksek: ${brk.High || 0}  •  ` +
        `Orta: ${brk.Medium || 0}  •  Düşük: ${brk.Low || 0}\n` +
        `Süre: ${duration}\n\n` +
        `→ "Raporlar" sekmesinden detaylı görüntüleyebilirsiniz.`,
        'success'
      );
    }
  } catch (e) {
    stopProgressAnimation();
    showResult(`Bağlantı hatası: ${e.message}`, 'error');
  } finally {
    btn.disabled = false;
  }
}

// Progress animasyonu — tahmini süreye göre ilerleme
let progressInterval = null;

function startProgressAnimation(modules) {
  const container = document.getElementById('scan-progress');
  container.classList.remove('hidden');

  // Her modülün ortalama süresini topla
  const totalEstimated = modules.reduce((sum, m) => {
    return sum + (MODULE_DETAILS[m]?.avgSeconds || 8);
  }, 0);

  let elapsed = 0;
  let currentModuleIdx = 0;
  let moduleElapsed = 0;

  const updateUI = () => {
    // Hangi modülde olduğumuzu hesapla
    let cumulative = 0;
    let currentModule = modules[0];
    for (let i = 0; i < modules.length; i++) {
      const t = MODULE_DETAILS[modules[i]]?.avgSeconds || 8;
      if (elapsed < cumulative + t) {
        currentModule = modules[i];
        currentModuleIdx = i;
        moduleElapsed = elapsed - cumulative;
        break;
      }
      cumulative += t;
    }

    // Yüzde — %95'i geçmesin (çünkü gerçek süre değişebilir)
    const pct = Math.min(95, Math.floor((elapsed / totalEstimated) * 100));
    const remaining = Math.max(0, totalEstimated - elapsed);

    setText('progress-percent', `${pct}%`);
    document.getElementById('progress-fill').style.width = `${pct}%`;

    const detail = MODULE_DETAILS[currentModule] || {};
    setText('progress-status', `${detail.title || currentModule} çalışıyor...`);
    setText('progress-current-module',
            `Modül ${currentModuleIdx + 1}/${modules.length} — ${currentModule}`);
    setText('progress-eta',
            remaining > 0
              ? `Tahmini kalan: ~${formatDuration(remaining)}`
              : 'Bitiriliyor...');

    elapsed += 0.5;
  };

  updateUI();
  progressInterval = setInterval(updateUI, 500);
}

function stopProgressAnimation() {
  if (progressInterval) {
    clearInterval(progressInterval);
    progressInterval = null;
  }
  // Final state: %100
  document.getElementById('progress-fill').style.width = '100%';
  setText('progress-percent', '100%');
  setText('progress-status', 'Tarama tamamlandı');
  setText('progress-eta', 'Bitti');
  // 1.5 saniye sonra gizle
  setTimeout(() => {
    document.getElementById('scan-progress').classList.add('hidden');
    document.getElementById('progress-fill').style.width = '0%';
  }, 1500);
}

function formatDuration(seconds) {
  if (seconds < 60) return `${Math.round(seconds)}sn`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}dk ${s}sn`;
}

function showResult(message, type) {
  const box = document.getElementById('scan-result');
  box.classList.remove('hidden', 'success', 'error');
  if (type) box.classList.add(type);
  box.style.whiteSpace = 'pre-wrap';
  box.textContent = message;
}

function hideResult() {
  document.getElementById('scan-result').classList.add('hidden');
}

// ── Raporlar ─────────────────────────────────────────────────────────────
async function loadReports() {
  const container = document.getElementById('reports-list');
  try {
    const scans = await API.scans();
    if (!scans.length) {
      container.innerHTML = '<div class="loading">Henüz hiç rapor yok.</div>';
      return;
    }
    container.innerHTML = renderScansTable(scans);
  } catch (e) {
    container.innerHTML = '<div class="loading">Yüklenemedi.</div>';
  }
}

// ── Senaryolar ───────────────────────────────────────────────────────────
async function loadScenarios() {
  const container = document.getElementById('scenarios-list');
  try {
    const scenarios = await API.scenarios();
    if (!scenarios.length) {
      container.innerHTML = `
        <div class="loading">
          Henüz YAML senaryo yok.<br>
          <code>scenarios_data/</code> klasörüne <code>.yaml</code> ekleyin.
        </div>`;
      return;
    }
    container.innerHTML = scenarios.map(s => `
      <div class="scenario-item">
        <div class="scenario-name">
          ${escapeHtml(s.name || s.id || s.filename)}
          ${s.severity ? `<span class="severity-tag severity-${s.severity}">${s.severity}</span>` : ''}
        </div>
        <div class="scenario-meta">
          📄 ${escapeHtml(s.filename)} ${s.author ? '• ✍️ ' + escapeHtml(s.author) : ''}
        </div>
        ${s.description ? `<div class="scenario-desc">${escapeHtml(s.description)}</div>` : ''}
      </div>
    `).join('');
  } catch (e) {
    container.innerHTML = '<div class="loading">Yüklenemedi.</div>';
  }
}

// ── Yardımcılar ─────────────────────────────────────────────────────────
function setText(id, txt) {
  const el = document.getElementById(id);
  if (el) el.textContent = txt;
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Başlangıç ──────────────────────────────────────────────────────────
loadDashboard();
