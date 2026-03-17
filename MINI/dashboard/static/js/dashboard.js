/* ════════════════════════════════════════════════════
   Mini SOC Log Analyzer — Dashboard JavaScript
   Charts, upload handling, data rendering
   ════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
    // ── DOM Elements ──
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const logTextarea = document.getElementById('logTextarea');
    const logType = document.getElementById('logType');
    const btnAnalyze = document.getElementById('btnAnalyze');
    const btnSampleApache = document.getElementById('btnSampleApache');
    const btnSampleWindows = document.getElementById('btnSampleWindows');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const btnClearFile = document.getElementById('btnClearFile');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const errorBanner = document.getElementById('errorBanner');
    const errorText = document.getElementById('errorText');
    const btnDismissError = document.getElementById('btnDismissError');
    const resultsContainer = document.getElementById('resultsContainer');
    const statusIndicator = document.getElementById('statusIndicator');

    let selectedFile = null;
    let analysisData = null;

    // ── Severity Colors ──
    const SEVERITY_COLORS = {
        CRITICAL: '#d946ef',
        HIGH: '#ef4444',
        MEDIUM: '#fbbf24',
        LOW: '#34d399',
        INFO: '#3b82f6',
        UNKNOWN: '#6b7280',
    };

    // ═══════════════════════════════
    //  File Upload / Drag & Drop
    // ═══════════════════════════════
    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        if (e.dataTransfer.files.length) {
            selectFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            selectFile(fileInput.files[0]);
        }
    });

    function selectFile(file) {
        selectedFile = file;
        fileName.textContent = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        fileInfo.style.display = 'flex';
        logTextarea.value = '';
    }

    btnClearFile.addEventListener('click', () => {
        selectedFile = null;
        fileInput.value = '';
        fileInfo.style.display = 'none';
    });

    // ═══════════════════════════════
    //  Sample Data Loading
    // ═══════════════════════════════
    btnSampleApache.addEventListener('click', () => loadSample('apache'));
    btnSampleWindows.addEventListener('click', () => loadSample('windows'));

    async function loadSample(type) {
        try {
            const resp = await fetch(`/sample/${type}`);
            const data = await resp.json();
            if (data.content) {
                logTextarea.value = data.content;
                logType.value = type;
                selectedFile = null;
                fileInput.value = '';
                fileInfo.style.display = 'none';
            }
        } catch (err) {
            showError('Failed to load sample data.');
        }
    }

    // ═══════════════════════════════
    //  Analysis
    // ═══════════════════════════════
    btnAnalyze.addEventListener('click', runAnalysis);

    async function runAnalysis() {
        hideError();
        const formData = new FormData();
        formData.append('log_type', logType.value);

        if (selectedFile) {
            formData.append('file', selectedFile);
        } else if (logTextarea.value.trim()) {
            formData.append('log_text', logTextarea.value);
        } else {
            showError('Please upload a log file or paste log text before analyzing.');
            return;
        }

        // Show loading
        loadingOverlay.style.display = 'flex';
        resultsContainer.style.display = 'none';
        setStatus('Analyzing...', true);

        try {
            const resp = await fetch('/analyze', { method: 'POST', body: formData });
            const data = await resp.json();

            if (!resp.ok) {
                showError(data.error || 'Analysis failed.');
                loadingOverlay.style.display = 'none';
                setStatus('Error', false);
                return;
            }

            analysisData = data;
            renderResults(data);
            loadingOverlay.style.display = 'none';
            resultsContainer.style.display = 'block';
            setStatus('Analysis Complete', false);

            // Scroll to results
            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

        } catch (err) {
            showError('Network error. Is the server running?');
            loadingOverlay.style.display = 'none';
            setStatus('Error', false);
        }
    }

    // ═══════════════════════════════
    //  Render Results
    // ═══════════════════════════════
    function renderResults(data) {
        // Dashboard cards with animation
        animateCounter('cardTotalEvents', data.total_events);
        animateCounter('cardThreats', data.total_alerts);
        animateCounter('cardCritical', data.critical_count);
        animateCounter('cardUniqueIPs', data.unique_ips);

        // Charts
        renderDoughnutChart(data.severity_distribution);
        renderTimelineChart(data.timeline);

        // IP Bars
        renderIPBars(data.top_ips);

        // Alerts Table
        renderAlertsTable(data.alerts);

        // Log Viewer
        renderLogViewer(data.logs);
    }

    // ═══════════════════════════════
    //  Animated Counter
    // ═══════════════════════════════
    function animateCounter(elementId, target) {
        const el = document.getElementById(elementId);
        const duration = 800;
        const start = performance.now();
        const initial = 0;

        function update(now) {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
            el.textContent = Math.round(initial + (target - initial) * eased);
            if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
    }

    // ═══════════════════════════════
    //  Doughnut Chart (Canvas)
    // ═══════════════════════════════
    function renderDoughnutChart(distribution) {
        const canvas = document.getElementById('severityChart');
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;

        canvas.width = 320 * dpr;
        canvas.height = 320 * dpr;
        canvas.style.width = '320px';
        canvas.style.height = '320px';
        ctx.scale(dpr, dpr);

        const cx = 160, cy = 160, outerR = 120, innerR = 72;
        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        const entries = order
            .filter(k => distribution[k])
            .map(k => ({ label: k, value: distribution[k], color: SEVERITY_COLORS[k] }));

        const total = entries.reduce((s, e) => s + e.value, 0);
        if (total === 0) return;

        // Animate
        const duration = 1000;
        const startTime = performance.now();

        function draw(now) {
            const progress = Math.min((now - startTime) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            const currentAngle = Math.PI * 2 * eased;

            ctx.clearRect(0, 0, 320, 320);

            let angle = -Math.PI / 2;
            entries.forEach(entry => {
                const slice = (entry.value / total) * currentAngle;

                ctx.beginPath();
                ctx.arc(cx, cy, outerR, angle, angle + slice);
                ctx.arc(cx, cy, innerR, angle + slice, angle, true);
                ctx.closePath();
                ctx.fillStyle = entry.color;
                ctx.fill();

                // Glow effect
                ctx.shadowColor = entry.color;
                ctx.shadowBlur = 8;
                ctx.fill();
                ctx.shadowBlur = 0;

                angle += slice;
            });

            // Center text
            ctx.fillStyle = '#e8edf5';
            ctx.font = 'bold 28px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(total, cx, cy - 8);

            ctx.fillStyle = '#5a6478';
            ctx.font = '500 11px Inter, sans-serif';
            ctx.fillText('TOTAL EVENTS', cx, cy + 16);

            if (progress < 1) requestAnimationFrame(draw);
        }
        requestAnimationFrame(draw);

        // Legend
        const legend = document.getElementById('severityLegend');
        legend.innerHTML = entries.map(e => `
            <div class="legend-item">
                <div class="legend-dot" style="background:${e.color}"></div>
                <span>${e.label} (${e.value})</span>
            </div>
        `).join('');
    }

    // ═══════════════════════════════
    //  Timeline Bar Chart (Canvas)
    // ═══════════════════════════════
    function renderTimelineChart(timeline) {
        const canvas = document.getElementById('timelineChart');
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;

        const W = 600, H = 320;
        canvas.width = W * dpr;
        canvas.height = H * dpr;
        canvas.style.width = W + 'px';
        canvas.style.height = H + 'px';
        ctx.scale(dpr, dpr);

        if (!timeline.length) return;

        const padL = 50, padR = 20, padT = 20, padB = 50;
        const chartW = W - padL - padR;
        const chartH = H - padT - padB;
        const maxVal = Math.max(...timeline.map(t => t.count));
        const barW = Math.max(4, (chartW / timeline.length) - 4);

        const duration = 800;
        const startTime = performance.now();

        function draw(now) {
            const progress = Math.min((now - startTime) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);

            ctx.clearRect(0, 0, W, H);

            // Grid lines
            ctx.strokeStyle = 'rgba(255,255,255,0.05)';
            ctx.lineWidth = 1;
            for (let i = 0; i <= 4; i++) {
                const y = padT + (chartH / 4) * i;
                ctx.beginPath();
                ctx.moveTo(padL, y);
                ctx.lineTo(W - padR, y);
                ctx.stroke();

                // Y-axis labels
                ctx.fillStyle = '#5a6478';
                ctx.font = '500 10px Inter, sans-serif';
                ctx.textAlign = 'right';
                ctx.fillText(Math.round(maxVal * (1 - i / 4)), padL - 8, y + 4);
            }

            // Bars
            timeline.forEach((item, i) => {
                const x = padL + (chartW / timeline.length) * i + 2;
                const barH = (item.count / maxVal) * chartH * eased;
                const y = padT + chartH - barH;

                // Gradient bar
                const gradient = ctx.createLinearGradient(x, y, x, padT + chartH);
                gradient.addColorStop(0, '#00e5ff');
                gradient.addColorStop(1, 'rgba(0, 229, 255, 0.15)');
                ctx.fillStyle = gradient;

                // Rounded top
                const r = Math.min(3, barW / 2);
                ctx.beginPath();
                ctx.moveTo(x, padT + chartH);
                ctx.lineTo(x, y + r);
                ctx.quadraticCurveTo(x, y, x + r, y);
                ctx.lineTo(x + barW - r, y);
                ctx.quadraticCurveTo(x + barW, y, x + barW, y + r);
                ctx.lineTo(x + barW, padT + chartH);
                ctx.closePath();
                ctx.fill();

                // Glow
                ctx.shadowColor = '#00e5ff';
                ctx.shadowBlur = 6;
                ctx.fill();
                ctx.shadowBlur = 0;

                // X-axis labels (show every few)
                if (timeline.length <= 15 || i % Math.ceil(timeline.length / 12) === 0) {
                    ctx.fillStyle = '#5a6478';
                    ctx.font = '500 9px Inter, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.save();
                    ctx.translate(x + barW / 2, H - padB + 14);
                    ctx.rotate(-0.5);
                    ctx.fillText(item.time, 0, 0);
                    ctx.restore();
                }
            });

            if (progress < 1) requestAnimationFrame(draw);
        }
        requestAnimationFrame(draw);
    }

    // ═══════════════════════════════
    //  IP Bar Chart
    // ═══════════════════════════════
    function renderIPBars(topIps) {
        const container = document.getElementById('ipBarsContainer');
        if (!topIps.length) {
            container.innerHTML = '<div class="empty-state">No IP data available.</div>';
            return;
        }

        const maxCount = topIps[0].count;
        container.innerHTML = topIps.map(item => `
            <div class="ip-bar-row">
                <span class="ip-bar-label">${item.ip}</span>
                <div class="ip-bar-track">
                    <div class="ip-bar-fill" style="width: 0%" data-target="${(item.count / maxCount * 100).toFixed(1)}"></div>
                </div>
                <span class="ip-bar-count">${item.count}</span>
            </div>
        `).join('');

        // Animate bars
        requestAnimationFrame(() => {
            container.querySelectorAll('.ip-bar-fill').forEach(bar => {
                bar.style.width = bar.dataset.target + '%';
            });
        });
    }

    // ═══════════════════════════════
    //  Alerts Table
    // ═══════════════════════════════
    function renderAlertsTable(alerts) {
        const tbody = document.getElementById('alertsBody');
        const noAlerts = document.getElementById('noAlerts');
        const badge = document.getElementById('alertCountBadge');

        badge.textContent = alerts.length;

        if (!alerts.length) {
            tbody.innerHTML = '';
            noAlerts.style.display = 'block';
            return;
        }

        noAlerts.style.display = 'none';
        tbody.innerHTML = alerts.map(a => `
            <tr>
                <td><span class="severity-badge severity-${a.severity}">${a.severity}</span></td>
                <td>${escapeHTML(a.type)}</td>
                <td style="font-family:var(--font-mono);font-size:0.78rem">${escapeHTML(a.source_ip || 'N/A')}</td>
                <td>${a.count || '—'}</td>
                <td>${escapeHTML(a.description || '')}</td>
            </tr>
        `).join('');
    }

    // ═══════════════════════════════
    //  Log Viewer
    // ═══════════════════════════════
    let allLogs = [];

    function renderLogViewer(logs) {
        allLogs = logs;
        document.getElementById('logCountBadge').textContent = logs.length;
        filterLogs();
    }

    function filterLogs() {
        const severity = document.getElementById('logFilterSeverity').value;
        const search = document.getElementById('logSearch').value.toLowerCase();
        const viewer = document.getElementById('logViewer');

        let filtered = allLogs;
        if (severity !== 'all') {
            filtered = filtered.filter(l => l.severity === severity);
        }
        if (search) {
            filtered = filtered.filter(l =>
                l.message.toLowerCase().includes(search) ||
                (l.ip && l.ip.toLowerCase().includes(search))
            );
        }

        viewer.innerHTML = filtered.map((log, i) => `
            <div class="log-line">
                <span class="log-line-num">${i + 1}</span>
                <span class="log-sev log-sev-${log.severity}">${log.severity}</span>
                <span>${escapeHTML(log.message)}</span>
            </div>
        `).join('');
    }

    document.getElementById('logFilterSeverity').addEventListener('change', filterLogs);
    document.getElementById('logSearch').addEventListener('input', filterLogs);

    // ═══════════════════════════════
    //  Helpers
    // ═══════════════════════════════
    function showError(msg) {
        errorText.textContent = msg;
        errorBanner.style.display = 'flex';
    }

    function hideError() {
        errorBanner.style.display = 'none';
    }

    btnDismissError.addEventListener('click', hideError);

    function setStatus(text, analyzing) {
        statusIndicator.querySelector('span:last-child').textContent = text;
        statusIndicator.classList.toggle('analyzing', analyzing);
    }

    function escapeHTML(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
});
