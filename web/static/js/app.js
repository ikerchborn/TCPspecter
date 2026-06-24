let protoChart = null;
        let procChart = null;
        let bandwidthChart = null;
        let entropyChart = null;
        let globeChart = null;
        let bandwidthData = { rx: [], tx: [], labels: [] };
        let entropyHistoryData = { labels: [], values: [] };
        let allConnections = [];
        let geoIpCache = {}; // ip -> geo data or 'fetching' or 'local'
        let tracerouteCache = {}; // ip -> array of IPs or 'fetching'
        let localGeo = null; // Store real origin

        // ── Logs SPA State ───────────────────────────────────────────────
        let allLogs = [];
        let logsStatusFilter = 'ALL';
        let logsSeverityFilter = 'ALL';
        let logsCurrentPage = 1;
        const LOGS_ITEMS_PER_PAGE = 100;
        let logsInterval = null;

        function escapeHTML(str) {
            if (str == null) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        async function initGlobe() {
            try {
                // Fetch self-geo first
                const selfRes = await fetch('/api/self_geo');
                localGeo = await selfRes.json();
                if(!localGeo || localGeo.error) {
                    localGeo = {lon: 0, lat: 0, city: 'Unknown', country: 'Local'};
                }

                const res = await fetch('https://cdn.jsdelivr.net/npm/echarts@4.9.0/map/json/world.json');
                const worldJson = await res.json();
                echarts.registerMap('world', worldJson);
                
                const chartDom = document.getElementById('globeChart');
                if (!chartDom) return;
                globeChart = echarts.init(chartDom);
                
                const option = {
                    backgroundColor: 'transparent',
                    geo: {
                        map: 'world',
                        roam: true,
                        zoom: 1.2,
                        scaleLimit: {
                            min: 1.0,
                            max: 8.0
                        },
                        itemStyle: {
                            areaColor: 'rgba(17, 24, 39, 0.8)',
                            borderColor: '#4a7a9d',
                            borderWidth: 1
                        },
                        emphasis: {
                            itemStyle: { areaColor: 'rgba(74, 122, 157, 0.4)' },
                            label: { show: false }
                        }
                    },
                    tooltip: {
                        trigger: 'item',
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        textStyle: { color: '#fff' },
                        formatter: function (params) {
                            if(params.seriesType === 'effectScatter') {
                                return `<strong>${params.data.name}</strong><br/>IP: ${params.data.ip}`;
                            }
                            return '';
                        }
                    },
                    series: [
                        {
                            type: 'lines',
                            coordinateSystem: 'geo',
                            zlevel: 1,
                            polyline: true, // IMPORTANT for drawing multiple hops
                            effect: {
                                show: true,
                                period: 4,
                                trailLength: 0.6,
                                symbolSize: 3
                            },
                            lineStyle: {
                                width: 0,
                                curveness: 0.2, // Still looks good with polylines
                                opacity: 0.5
                            },
                            data: []
                        },
                        {
                            type: 'effectScatter',
                            coordinateSystem: 'geo',
                            zlevel: 2,
                            rippleEffect: { brushType: 'stroke', scale: 4 },
                            symbolSize: 6,
                            itemStyle: { color: '#34d399' },
                            data: []
                        }
                    ]
                };
                globeChart.setOption(option);
            } catch (err) {
                console.error("Error updating dashboard UI:", err);
            }
        }

        function initWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const lang = localStorage.getItem('language') || 'en';
            const wsUrl = `${protocol}//${window.location.host}/api/ws?lang=${encodeURIComponent(lang)}`;
            const ws = new WebSocket(wsUrl);
            
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    updateDashboard(data);
                } catch(e) {
                    console.error("WS parse error:", e);
                }
            };
            
            ws.onerror = (error) => {
                console.warn("WebSocket error, falling back to REST poll");
            };
            
            ws.onclose = () => {
                console.warn("WebSocket closed. Reconnecting in 3s...");
                setTimeout(initWebSocket, 3000);
            };

            // Return ws so caller can reference it if needed
            return ws;
        }

        // Immediately fetch data via REST so views populate without waiting for first WS tick
        async function fetchAndUpdateNow() {
            try {
                const lang = localStorage.getItem('language') || 'en';
                const res = await fetch(`/api/data?lang=${lang}`);
                if (!res.ok) return;
                const data = await res.json();
                await updateDashboard(data);
            } catch (err) {
                console.error('Initial REST fetch failed:', err);
            }
        }

        // Alias used by firewall/snort action handlers
        const refreshData = fetchAndUpdateNow;

        function resetMapView() {
            if (globeChart) {
                globeChart.setOption({
                    geo: {
                        zoom: 1.2,
                        center: null
                    }
                });
            }
        }

        function initCharts() {
            // Protocol Chart
            const protoEl = document.getElementById('protoChart');
            if (protoEl) {
                const ctxProto = protoEl.getContext('2d');
                protoChart = new Chart(ctxProto, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'LISTEN'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: ['#4a7a9d', '#f2e8c9', '#888888'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 11 } } }
                    }
                }
            });
            }

            // Processes Chart
            const procEl = document.getElementById('procChart');
            if (procEl) {
                const ctxProc = procEl.getContext('2d');
                procChart = new Chart(ctxProc, {
                type: 'pie',
                data: {
                    labels: ['Ninguno'],
                    datasets: [{
                        data: [1],
                        backgroundColor: ['#4a7a9d', '#f2e8c9', '#888888', '#555555'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#9ca3af', font: { size: 10 } } }
                    }
                }
            });
            }

            // Bandwidth Chart
            const bandEl = document.getElementById('bandwidthChart');
            if (bandEl) {
                const ctxBand = bandEl.getContext('2d');
                bandwidthChart = new Chart(ctxBand, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Bajada (RX)',
                            data: [],
                            borderColor: '#34d399',
                            backgroundColor: 'rgba(52, 211, 153, 0.05)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        },
                        {
                            label: 'Subida (TX)',
                            data: [],
                            borderColor: '#4a7a9d',
                            backgroundColor: 'rgba(74, 122, 157, 0.05)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } },
                        y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#9ca3af' } }
                    }
                }
            });
            }

            // Entropy Chart
            const entropyEl = document.getElementById('entropyChart');
            if (entropyEl) {
                const ctxEntropy = entropyEl.getContext('2d');
                entropyChart = new Chart(ctxEntropy, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Entropía Promedio',
                        data: [],
                        borderColor: '#fbbf24',
                        backgroundColor: 'rgba(251, 191, 36, 0.05)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } },
                        y: { min: 0, max: 8, grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#888888' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#9ca3af' } }
                    }
                }
            });
            }
        }


        let currentFirewallBackend = 'none';

        function isDashboardRoute() {
            const path = window.location.pathname;
            return path === '/' || path === '';
        }

        async function updateDashboard(data) {
            if (!data) return;

            // Header stats — always available
            try {
                currentFirewallBackend = data.firewall?.backend || 'none';
                const cpuEl = document.getElementById('sys_cpu');
                const ramEl = document.getElementById('sys_ram');
                if (cpuEl) cpuEl.innerText = `${data.cpu.toFixed(1)}%`;
                if (ramEl) {
                    const usedGb = (data.used_ram / (1024 * 1024 * 1024)).toFixed(2);
                    const totalGb = (data.total_ram / (1024 * 1024 * 1024)).toFixed(2);
                    ramEl.innerText = `${data.ram.toFixed(1)}% (${usedGb} GB / ${totalGb} GB)`;
                }
                if (typeof data.security?.enabled === 'boolean') {
                    updateSecurityToggleBtn(data.security.enabled);
                }
            } catch (err) {
                console.error('Header stats update failed:', err);
            }

            // Dashboard-only widgets (security panel, charts, scapy)
            if (isDashboardRoute()) {
                try {
                    await updateDashboardPanels(data);
                } catch (err) {
                    console.error('Dashboard panels update failed:', err);
                }
            }

            // Firewall / Snort — available on dashboard and firewall routes
            try {
                await updateFirewallPanels(data);
            } catch (err) {
                console.error('Firewall panels update failed:', err);
            }

            // Threat intelligence — dashboard and intelligence routes
            try {
                updateIntelligencePanels(data);
            } catch (err) {
                console.error('Intelligence panels update failed:', err);
            }

            // Map + connections table — dashboard only
            if (isDashboardRoute()) {
                try {
                    await updateConnectionsAndMap(data);
                } catch (err) {
                    console.error('Connections/map update failed:', err);
                }
            }
        }

        async function updateDashboardPanels(data) {
                // 1. Update Security Panel
                const riskScoreEl = document.getElementById('risk_score');
                const circle = document.getElementById('risk_gradient');
                if (!riskScoreEl || !circle) return;

                riskScoreEl.innerText = data.security?.score ?? 0;
                
                let riskColor = '#34d399';
                let riskClass = 'sev-bajo';
                const score = data.security?.score ?? 0;
                const riskLevel = data.security?.risk_level ?? '-';
                const analyticsOff = data.security?.enabled === false || riskLevel === 'DESACTIVADO' || riskLevel === 'DISABLED';

                if (analyticsOff) {
                    riskColor = '#888888';
                    riskClass = 'sev-medio';
                    riskScoreEl.innerText = '—';
                } else if (score >= 60) {
                    riskColor = '#f87171';
                    riskClass = 'sev-critico';
                } else if (score >= 35) {
                    riskColor = '#fbbf24';
                    riskClass = 'sev-alto';
                } else if (score >= 15) {
                    riskColor = '#4a7a9d';
                    riskClass = 'sev-medio';
                }
                circle.style.background = analyticsOff
                    ? `conic-gradient(${riskColor} 100%, #1e293b 0%)`
                    : `conic-gradient(${riskColor} ${score}%, #1e293b 0%)`;
                
                const riskLevelEl = document.getElementById('risk_level');
                if (riskLevelEl) {
                    riskLevelEl.innerText = riskLevel;
                    riskLevelEl.className = `severity-badge ${riskClass}`;
                }

                const findingsCountEl = document.getElementById('findings_count');
                const findings = data.security?.findings || [];
                if (findingsCountEl) findingsCountEl.innerText = findings.length;

                // 2. Update Alerts list
                const alertsList = document.getElementById('alerts_list');
                if (alertsList) {
                if (findings.length === 0) {
                    alertsList.innerHTML = `<div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 40px;">No se han detectado alertas de seguridad activas.</div>`;
                } else {
                    alertsList.innerHTML = findings.map(f => {
                        let fclass = 'sev-bajo';
                        let borderColor = '#34d399';
                        if (f.severity === 'CRITICAL') { fclass = 'sev-critico'; borderColor = '#f87171'; }
                        else if (f.severity === 'HIGH') { fclass = 'sev-alto'; borderColor = '#fbbf24'; }
                        else if (f.severity === 'MEDIUM') { fclass = 'sev-medio'; borderColor = '#4a7a9d'; }
                        
                        const pidText = f.pid ? `PID ${escapeHTML(f.pid)}` : '';
                        const nameText = f.proc_name ? `(${escapeHTML(f.proc_name)})` : '';

                        return `
                            <div style="background: rgba(255,255,255,0.02); margin-bottom: 8px; padding: 10px; border-radius: 8px; border-left: 3px solid ${borderColor};">
                                <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                                    <span class="severity-badge ${fclass}" style="padding:1px 6px; font-size:10px;">${escapeHTML(f.severity)}</span>
                                    <span style="font-size:11px; color:var(--text-muted);">${pidText} ${nameText}</span>
                                </div>
                                <div style="font-size:13px; color:var(--text-main); font-weight: 500;">${escapeHTML(f.category)}</div>
                                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">${escapeHTML(f.description)}</div>
                            </div>
                        `;
                    }).join('');
                }
                }

                // 3. Update Charts
                // Protocol Pie Chart
                let tc = 0, uc = 0, lc = 0;
                (data.connections || []).forEach(c => {
                    if (c.status === 'LISTEN') lc++;
                    else if (c.proto === 'TCP') tc++;
                    else if (c.proto === 'UDP') uc++;
                });
                if (protoChart) {
                    protoChart.data.datasets[0].data = [tc, uc, lc];
                    protoChart.update();
                }

                // Process Pie Chart
                let procCpuMap = {};
                (data.processes || []).forEach(p => {
                    if (p.cpu > 0) {
                        procCpuMap[p.name] = (procCpuMap[p.name] || 0) + p.cpu;
                    }
                });
                const procLabels = Object.keys(procCpuMap);
                const procValues = Object.values(procCpuMap);
                if (procChart) {
                    if (procLabels.length > 0) {
                        procChart.data.labels = procLabels;
                        procChart.data.datasets[0].data = procValues;
                    } else {
                        procChart.data.labels = ['Sin actividad'];
                        procChart.data.datasets[0].data = [1];
                    }
                    procChart.update();
                }

                // Bandwidth History Chart
                const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                bandwidthData.labels.push(timeStr);
                bandwidthData.rx.push(data.rx_speed);
                bandwidthData.tx.push(data.tx_speed);

                if (bandwidthData.labels.length > 15) {
                    bandwidthData.labels.shift();
                    bandwidthData.rx.shift();
                    bandwidthData.tx.shift();
                }

                if (bandwidthChart) {
                    bandwidthChart.data.labels = bandwidthData.labels;
                    bandwidthChart.data.datasets[0].data = bandwidthData.rx;
                    bandwidthChart.data.datasets[1].data = bandwidthData.tx;
                    bandwidthChart.update();
                }

                // Entropy History Chart — use per-packet history from backend
                const scapy = data.scapy || {};
                if (scapy.entropy_history &&
                    scapy.entropy_history.labels &&
                    scapy.entropy_history.labels.length > 0) {
                    if (entropyChart) {
                        entropyChart.data.labels = scapy.entropy_history.labels;
                        entropyChart.data.datasets[0].data = scapy.entropy_history.values;
                        entropyChart.update();
                    }
                } else {
                    entropyHistoryData.labels.push(timeStr);
                    entropyHistoryData.values.push(scapy.avg_entropy || 0);
                    if (entropyHistoryData.labels.length > 15) {
                        entropyHistoryData.labels.shift();
                        entropyHistoryData.values.shift();
                    }
                    if (entropyChart) {
                        entropyChart.data.labels = entropyHistoryData.labels;
                        entropyChart.data.datasets[0].data = entropyHistoryData.values;
                        entropyChart.update();
                    }
                }

                // Scapy Metrics and Alerts (dashboard only)
                const scapyCountEl = document.getElementById('scapy_packet_count');
                const scapyEntropyEl = document.getElementById('scapy_avg_entropy');
                const dnsDlpAlerts = document.getElementById('dns_dlp_alerts');
                if (scapyCountEl && scapyEntropyEl && dnsDlpAlerts && data.scapy) {
                    const snifferUp = data.scapy.sniffer_running !== false;
                    if (!snifferUp && (data.scapy.stats?.packet_count ?? 0) === 0) {
                        scapyCountEl.innerText = '—';
                        scapyEntropyEl.innerText = '—';
                        dnsDlpAlerts.innerHTML = `<div style="color: var(--warning); font-style: italic; text-align: center; margin-top: 20px; font-size: 12px;">Sniffer Scapy inactivo. Ejecuta TCPspecter con sudo o CAP_NET_RAW para captura en vivo.</div>`;
                    } else {
                    scapyCountEl.innerText = data.scapy.stats?.packet_count ?? 0;
                    scapyEntropyEl.innerText = (data.scapy.avg_entropy ?? 0).toFixed(2);

                    const combinedAlerts = [
                        ...(data.scapy.dns_alerts || []),
                        ...(data.scapy.dlp_alerts || []),
                    ];
                    combinedAlerts.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

                    if (combinedAlerts.length === 0) {
                        dnsDlpAlerts.innerHTML = `<div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 20px; font-size: 12px;">No hay alertas en tiempo real de Scapy/DNS.</div>`;
                    } else {
                        dnsDlpAlerts.innerHTML = combinedAlerts.map(alert => {
                            let color = '#fbbf24';
                            let typeLabel = alert.category || 'ALERTA';

                            if (typeLabel.includes('TÚNEL') || typeLabel.includes('ENTROPÍA') || typeLabel.includes('Reverse Shell')) {
                                color = '#f87171';
                            }

                            const desc = alert.description;
                            const queryInfo = alert.query ? ` [Query: ${alert.query}]` : '';

                            return `
                                <div style="background: rgba(255,255,255,0.02); padding: 8px; border-radius: 6px; border-left: 3px solid ${color}; font-size: 11px;">
                                    <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                                        <span style="color: ${color}; font-weight: 600; text-transform: uppercase;">${escapeHTML(typeLabel)}</span>
                                        <span style="color: var(--text-muted);">${escapeHTML(alert.timestamp)}</span>
                                    </div>
                                    <div style="color: var(--text-main); font-size: 12px;">${escapeHTML(desc)}${escapeHTML(queryInfo)}</div>
                                </div>
                            `;
                        }).join('');
                    }
                    }
                }
        }

        function renderIntelAlertItem(alert) {
            let color = '#fbbf24';
            if (alert.severity === 'CRITICAL') color = '#f87171';
            else if (alert.severity === 'HIGH') color = '#fb923c';
            return `
                <div style="background: rgba(255,255,255,0.02); padding: 8px; border-radius: 6px; border-left: 3px solid ${color}; font-size: 11px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                        <span style="color: ${color}; font-weight: 600; text-transform: uppercase;">${escapeHTML(alert.category || 'INTEL')}</span>
                        <span style="color: var(--text-muted);">${escapeHTML(alert.timestamp || '')}</span>
                    </div>
                    <div style="color: var(--text-main); font-size: 12px;">${escapeHTML(alert.description || '')}</div>
                </div>
            `;
        }

        function updateIntelligencePanels(data) {
            const intel = data.intelligence;
            if (!intel) return;

            const feedsLoaded = (intel.feeds || []).filter(f => f.loaded).length;
            const noMatchHtml = `<div style="color: var(--text-muted); font-style: italic; text-align: center; margin-top: 20px; font-size: 12px;">${translations[localStorage.getItem('language') || 'en']['intel_no_matches'] || 'No matches yet.'}</div>`;
            const alerts = intel.live_alerts || intel.recent_matches || [];

            const totalEl = document.getElementById('intel_total_entries');
            const feedsEl = document.getElementById('intel_feeds_loaded');
            const matchEl = document.getElementById('intel_match_count');
            const statusEl = document.getElementById('intel_status_badge');
            const recentEl = document.getElementById('intel_recent_matches');

            if (totalEl) totalEl.innerText = intel.total_entries ?? 0;
            if (feedsEl) feedsEl.innerText = feedsLoaded;
            if (matchEl) matchEl.innerText = intel.match_count ?? 0;
            if (statusEl) {
                statusEl.innerText = intel.enabled ? 'ACTIVE' : 'DISABLED';
                statusEl.style.color = intel.enabled ? '#34d399' : '#888888';
            }
            if (recentEl) {
                recentEl.innerHTML = alerts.length === 0
                    ? noMatchHtml
                    : alerts.slice(-5).reverse().map(renderIntelAlertItem).join('');
            }

            const pageTotal = document.getElementById('intel_page_total');
            const pageMatches = document.getElementById('intel_page_matches');
            const pageReload = document.getElementById('intel_page_reload');
            const feedsTbody = document.getElementById('intel_feeds_tbody');
            const alertsList = document.getElementById('intel_alerts_list');
            const toggleBtn = document.getElementById('intel_toggle_btn');

            if (pageTotal) pageTotal.innerText = intel.total_entries ?? 0;
            if (pageMatches) pageMatches.innerText = intel.match_count ?? 0;
            if (pageReload) pageReload.innerText = intel.last_reload || '—';

            if (feedsTbody) {
                const feeds = intel.feeds || [];
                if (feeds.length === 0) {
                    feedsTbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:20px 0;">No feeds configured</td></tr>`;
                } else {
                    feedsTbody.innerHTML = feeds.map(f => `
                        <tr style="border-bottom: 1px solid var(--card-border);">
                            <td style="padding: 10px; color: var(--text-main);">${escapeHTML(f.name)}</td>
                            <td style="padding: 10px;">
                                <span class="severity-badge ${f.loaded ? 'sev-bajo' : 'sev-alto'}">${f.loaded ? 'LOADED' : 'MISSING'}</span>
                            </td>
                            <td style="padding: 10px; color: var(--text-main);">${f.entry_count ?? 0}</td>
                            <td style="padding: 10px; color: var(--text-muted); font-size: 12px;">${escapeHTML(f.error || '—')}</td>
                        </tr>
                    `).join('');
                }
            }

            if (alertsList) {
                alertsList.innerHTML = alerts.length === 0
                    ? noMatchHtml
                    : [...alerts].reverse().map(renderIntelAlertItem).join('');
            }

            if (toggleBtn) {
                const lang = localStorage.getItem('language') || 'en';
                toggleBtn.innerHTML = intel.enabled
                    ? (translations[lang]['intel_btn_active'] || '● ENGINE ACTIVE')
                    : (translations[lang]['intel_btn_inactive'] || '○ ENGINE DISABLED');
                toggleBtn.style.color = intel.enabled ? '#34d399' : '#888888';
                toggleBtn.style.borderColor = intel.enabled ? '#34d399' : '#888888';
                toggleBtn.style.background = intel.enabled ? 'rgba(52,211,153,0.15)' : 'rgba(255,255,255,0.05)';
            }
        }

        async function toggleIntelligence() {
            try {
                const res = await fetch('/api/intelligence/toggle', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': window.csrfToken || '' }
                });
                if (!res.ok) throw new Error('Toggle failed');
                await fetchAndUpdateNow();
            } catch (err) {
                console.error('Intelligence toggle error:', err);
            }
        }

        async function reloadIntelligenceFeeds() {
            try {
                const res = await fetch('/api/intelligence/reload', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': window.csrfToken || '' }
                });
                if (!res.ok) throw new Error('Reload failed');
                await fetchAndUpdateNow();
            } catch (err) {
                console.error('Intelligence reload error:', err);
            }
        }

        window.toggleIntelligence = toggleIntelligence;
        window.reloadIntelligenceFeeds = reloadIntelligenceFeeds;

        async function updateFirewallPanels(data) {
                const snortBadge = document.getElementById('snort_badge');
                const snortInfo = document.getElementById('snort_info');
                const toggleSnortBtn = document.getElementById('toggle_snort_btn');
                const installBtn = document.getElementById('install_snort_btn');

                if (snortBadge && snortInfo && toggleSnortBtn && installBtn && data.snort) {
                    if (!data.snort.installed) {
                        snortBadge.innerText = 'NO INSTALADO';
                        snortBadge.className = 'severity-badge sev-alto';
                        snortInfo.innerText = 'Snort IDS no está instalado en el sistema.';
                        installBtn.style.display = 'inline-block';
                        toggleSnortBtn.style.display = 'none';
                    } else {
                        installBtn.style.display = 'none';
                        toggleSnortBtn.style.display = 'inline-block';
                        if (data.snort.running) {
                            snortBadge.innerText = 'ACTIVO';
                            snortBadge.className = 'severity-badge sev-bajo';
                            snortInfo.innerText = 'Snort está ejecutándose en modo pasivo IDS.';
                            toggleSnortBtn.innerText = 'Detener Snort';
                            toggleSnortBtn.style.background = 'rgba(248, 113, 113, 0.1)';
                            toggleSnortBtn.style.borderColor = 'var(--danger)';
                            toggleSnortBtn.style.color = 'var(--danger)';
                        } else {
                            snortBadge.innerText = 'INACTIVO';
                            snortBadge.className = 'severity-badge sev-medio';
                            snortInfo.innerText = 'El servicio Snort está detenido.';
                            toggleSnortBtn.innerText = 'Iniciar Snort';
                            toggleSnortBtn.style.background = 'rgba(52, 211, 153, 0.1)';
                            toggleSnortBtn.style.borderColor = 'var(--success)';
                            toggleSnortBtn.style.color = 'var(--success)';
                        }
                    }
                }

                const fwTbody = document.getElementById('firewall_tbody');
                const blockedIps = data.firewall?.blocked_ips || [];
                if (fwTbody) {
                    if (blockedIps.length === 0) {
                        fwTbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 20px 0; border-bottom: 1px solid var(--card-border);">Ninguna IP bloqueada actualmente.</td></tr>`;
                    } else {
                        fwTbody.innerHTML = blockedIps.map(rule => {
                            return `
                                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
                                    <td style="padding: 12px; font-weight: 600; color: var(--danger);">${escapeHTML(rule.ip)}</td>
                                    <td style="padding: 12px; color: var(--text-main);">${escapeHTML(rule.backend || data.firewall.backend || '-')}</td>
                                    <td style="padding: 12px; color: var(--text-main);">
                                        <span style="background: rgba(248, 113, 113, 0.1); color: var(--danger); padding: 2px 6px; border-radius: 4px; font-size: 10px;">${escapeHTML(rule.target || 'INPUT')}</span>
                                    </td>
                                    <td style="padding: 12px;">
                                        <button onclick="unblockIP('${escapeHTML(rule.ip)}')" style="background: rgba(52, 211, 153, 0.1); border: 1px solid var(--success); color: var(--success); padding: 4px 8px; border-radius: 4px; font-size: 11px; cursor: pointer; transition: all 0.2s;">Desbloquear</button>
                                    </td>
                                </tr>
                            `;
                        }).join('');
                    }
                }
        }

        async function updateConnectionsAndMap(data) {
                const connections = data.connections || [];
                allConnections = connections;
                filterTable();

                const uniqueRemoteIPs = [...new Set(connections.map(c => c.raddr_ip).filter(ip => ip && ip !== '-' && ip !== '0.0.0.0' && ip !== '127.0.0.1'))];

                // Phase 1: fetch traceroutes
                await Promise.all(uniqueRemoteIPs.map(ip => {
                    if (tracerouteCache[ip] && tracerouteCache[ip] !== 'fetching') return Promise.resolve();
                    tracerouteCache[ip] = 'fetching';
                    return fetch(`/api/traceroute?ip=${encodeURIComponent(ip)}`)
                        .then(r => r.json())
                        .then(hops => { tracerouteCache[ip] = hops || [ip]; })
                        .catch(() => { tracerouteCache[ip] = [ip]; });
                }));

                // Phase 2: fetch geo for destinations and hops
                const ipsNeedingGeo = new Set(uniqueRemoteIPs);
                uniqueRemoteIPs.forEach(ip => {
                    const hops = tracerouteCache[ip];
                    if (Array.isArray(hops)) hops.forEach(h => ipsNeedingGeo.add(h));
                });

                await Promise.all([...ipsNeedingGeo].map(ip => {
                    if (geoIpCache[ip] && geoIpCache[ip] !== 'fetching') return Promise.resolve();
                    geoIpCache[ip] = 'fetching';
                    return fetch(`/api/geoip?ip=${encodeURIComponent(ip)}`)
                        .then(r => r.json())
                        .then(geo => { geoIpCache[ip] = (geo && !geo.is_local) ? geo : 'local'; })
                        .catch(() => { geoIpCache[ip] = 'local'; });
                }));

                if (!globeChart || !localGeo) return;

                const linesData = [];
                const scatterData = [];

                scatterData.push({ name: `${localGeo.city}, ${localGeo.country}`, ip: localGeo.ip || '127.0.0.1', value: [localGeo.lon, localGeo.lat], itemStyle: { color: '#4a7a9d' } });

                connections.forEach(c => {
                    const destIp = c.raddr_ip;
                    if (destIp === '-' || destIp === '0.0.0.0' || destIp === '127.0.0.1') return;

                    const destGeo = geoIpCache[destIp];
                    if (destGeo && destGeo !== 'local' && destGeo !== 'fetching') {
                        let color = '#34d399';
                        const assessment = (c.interpretation && c.interpretation.assessment) || '';
                        if (assessment.includes('CRÍTICO') || assessment.includes('CRITICAL')) {
                            color = '#f87171';
                        } else if (assessment.includes('REVISAR') || assessment.includes('SUSPICIOUS')) {
                            color = '#fbbf24';
                        }

                        scatterData.push({
                            name: `${destGeo.city}, ${destGeo.country}`,
                            ip: destIp,
                            value: [destGeo.lon, destGeo.lat],
                            itemStyle: { color: color }
                        });

                        const hops = tracerouteCache[destIp];
                        let coords = [[localGeo.lon, localGeo.lat]];

                        if (Array.isArray(hops)) {
                            hops.forEach(hop_ip => {
                                const hGeo = geoIpCache[hop_ip];
                                if (hGeo && hGeo !== 'local' && hGeo !== 'fetching') {
                                    coords.push([hGeo.lon, hGeo.lat]);
                                    if (hop_ip !== destIp) {
                                        scatterData.push({
                                            name: `${hGeo.city}, ${hGeo.country} (Hop)`,
                                            ip: hop_ip,
                                            value: [hGeo.lon, hGeo.lat],
                                            symbolSize: 3,
                                            itemStyle: { color: '#4a7a9d' }
                                        });
                                    }
                                }
                            });
                        }

                        const lastCoord = coords[coords.length - 1];
                        if (!lastCoord || lastCoord[0] !== destGeo.lon || lastCoord[1] !== destGeo.lat) {
                            coords.push([destGeo.lon, destGeo.lat]);
                        }

                        linesData.push({
                            coords: coords,
                            lineStyle: { color: color }
                        });
                    }
                });

                const uniqueScatter = [];
                const seenCoords = new Set();
                scatterData.forEach(pt => {
                    const key = `${pt.value[0]},${pt.value[1]}`;
                    if (!seenCoords.has(key)) {
                        seenCoords.add(key);
                        uniqueScatter.push(pt);
                    }
                });

                globeChart.setOption({
                    series: [
                        {
                            type: 'lines',
                            coordinateSystem: 'geo',
                            data: linesData
                        },
                        {
                            type: 'effectScatter',
                            coordinateSystem: 'geo',
                            data: uniqueScatter
                        }
                    ]
                });
        }

        function filterTable() {
            const searchBar = document.getElementById('search_bar');
            const tbody = document.getElementById('connections_tbody');
            if (!tbody) return;

            const query = searchBar ? searchBar.value.toLowerCase().trim() : '';
            
            const filtered = allConnections.filter(c => {
                if (!query) return true;
                return (
                    (c.name || '').toLowerCase().includes(query) ||
                    String(c.pid || '').includes(query) ||
                    (c.proto || '').toLowerCase().includes(query) ||
                    (c.laddr_ip || '').toLowerCase().includes(query) ||
                    String(c.laddr_port || '').includes(query) ||
                    (c.raddr_ip || '').toLowerCase().includes(query) ||
                    String(c.raddr_port || '').includes(query) ||
                    (c.status || '').toLowerCase().includes(query)
                );
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 40px 0;">No se encontraron conexiones que coincidan.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map((c, idx) => {
                let statusBadge = 'badge-other';
                if (c.status === 'ESTABLISHED') statusBadge = 'badge-established';
                else if (c.status === 'LISTEN') statusBadge = 'badge-listen';

                let evalClass = 'sev-bajo';
                const assessment = (c.interpretation && c.interpretation.assessment) || '';
                if (assessment.includes('CRÍTICO') || assessment.includes('CRITICAL')) evalClass = 'sev-critico';
                else if (assessment.includes('REVISAR') || assessment.includes('SUSPICIOUS')) evalClass = 'sev-alto';

                const nameText = c.name || '-';
                const pidText = c.pid || '-';
                const raddrColor = (assessment.includes('CRÍTICO') || assessment.includes('CRITICAL')) ? '#f87171' : '#fff';
                const isHighlighted = idx === 0 ? 'background: rgba(255, 255, 255, 0.03);' : '';

                return `
                    <tr style="${isHighlighted}" onclick="showConnectionModal('${encodeURIComponent(JSON.stringify(c))}')">
                        <td><strong>${escapeHTML(nameText)}</strong></td>
                        <td>${escapeHTML(pidText)}</td>
                        <td>${escapeHTML(c.proto)}</td>
                        <td>${escapeHTML(c.laddr_ip)}</td>
                        <td>${escapeHTML(String(c.laddr_port))}</td>
                        <td><span style="color: ${raddrColor};">${escapeHTML(c.raddr_ip)}</span></td>
                        <td>${escapeHTML(String(c.raddr_port))}</td>
                        <td><span class="badge-status ${statusBadge}">${escapeHTML(c.status)}</span></td>
                        <td><span class="severity-badge ${evalClass}" style="padding: 2px 6px; font-size: 11px;">${escapeHTML(assessment || '-')}</span></td>
                    </tr>
                `;
            }).join('');
        }

        function showConnectionModal(connDataObj) {
            let conn = null;
            if (typeof connDataObj === 'string') {
                try {
                    conn = JSON.parse(decodeURIComponent(connDataObj));
                } catch(e) {
                    try {
                        conn = JSON.parse(connDataObj);
                    } catch(e2) {
                        return;
                    }
                }
            } else {
                conn = connDataObj;
            }
            const lang = localStorage.getItem('language') || 'en';
            const interp = conn.interpretation || {};

            if (lang === 'es') {
                document.getElementById('modal_proc_title').innerText = `Interpretación de '${conn.name || '-'}'`;
                document.getElementById('modal_socket_title').innerText = `PID: ${conn.pid || '-'} | Protocolo: ${conn.proto || '-'} | IP Destino: ${conn.raddr_ip}:${conn.raddr_port}`;
            } else {
                document.getElementById('modal_proc_title').innerText = `Interpretation of '${conn.name || '-'}'`;
                document.getElementById('modal_socket_title').innerText = `PID: ${conn.pid || '-'} | Protocol: ${conn.proto || '-'} | Destination IP: ${conn.raddr_ip}:${conn.raddr_port}`;
            }
            
            const banner = document.getElementById('modal_banner');
            const assessment = interp.assessment || (lang === 'es' ? 'Sin evaluación' : 'No assessment');
            if (lang === 'es') {
                banner.innerText = `Evaluación: ${assessment}`;
            } else {
                banner.innerText = `Assessment: ${assessment}`;
            }
            
            let bannerBg = 'rgba(52, 211, 153, 0.15)';
            let bannerColor = 'var(--success)';
            if (assessment.includes('CRÍTICO') || assessment.includes('CRITICAL')) {
                bannerBg = 'rgba(248, 113, 113, 0.15)';
                bannerColor = 'var(--danger)';
            } else if (assessment.includes('REVISAR') || assessment.includes('SUSPICIOUS')) {
                bannerBg = 'rgba(251, 191, 36, 0.15)';
                bannerColor = 'var(--warning)';
            }
            banner.style.background = bannerBg;
            banner.style.color = bannerColor;

            document.getElementById('modal_ip_block').querySelector('p').innerText = interp.ip_desc || '-';
            document.getElementById('modal_port_block').querySelector('p').innerText = interp.port_desc || '-';
            document.getElementById('modal_status_block').querySelector('p').innerText = interp.status_desc || '-';
            document.getElementById('modal_danger_block').querySelector('p').innerText = interp.explanation || '-';
            
            const recs = interp.recommendations || [];
            if (recs.length > 0) {
                document.getElementById('modal_recommendation_block').querySelector('p').innerText = `• ${recs.join('\n• ')}`;
            } else {
                document.getElementById('modal_recommendation_block').querySelector('p').innerText = lang === 'es' ? "No hay recomendaciones específicas." : "No specific recommendations.";
            }
            
            document.getElementById('modal_educational_block').querySelector('p').innerText = interp.educational || "-";

            document.getElementById('interpret_modal').classList.add('active');
        }

        function updateSecurityToggleBtn(enabled) {
            const btn = document.getElementById('security_toggle_btn');
            if (!btn) return;
            const lang = localStorage.getItem('language') || 'en';
            const t = translations[lang] || translations.en;
            if (enabled) {
                btn.style.background = 'rgba(52,211,153,0.15)';
                btn.style.color = '#34d399';
                btn.style.border = '1px solid #34d399';
                btn.innerHTML = t.btn_sec_active;
            } else {
                btn.style.background = 'rgba(136,136,136,0.1)';
                btn.style.color = '#888888';
                btn.style.border = '1px solid #444444';
                btn.innerHTML = t.btn_sec_inactive;
            }
        }

        function closeModal() {
            document.getElementById('interpret_modal').classList.remove('active');
        }

        function showLogModal(connDataObj) {
            let entry = null;
            if (typeof connDataObj === 'string') {
                try {
                    entry = JSON.parse(decodeURIComponent(connDataObj));
                } catch(e) {
                    try {
                        entry = JSON.parse(connDataObj);
                    } catch(e2) {
                        return;
                    }
                }
            } else {
                entry = connDataObj;
            }
            if (!entry) return;
            document.getElementById('modal_cat').innerText = entry.category || '-';
            document.getElementById('modal_meta').innerText = `${entry.timestamp || '-'} | ${entry.severity || '-'} | ${entry.status || '-'}`;
            document.getElementById('modal_desc_val').innerText = entry.description || '-';
            const procParts = [];
            if (entry.pid)       procParts.push(`PID: ${entry.pid}`);
            if (entry.proc_name) procParts.push(`Process: ${entry.proc_name}`);
            if (entry.exe_path)  procParts.push(`Executable: ${entry.exe_path}`);
            if (entry.cmdline)   procParts.push(`Command: ${entry.cmdline}`);
            document.getElementById('modal_proc_val').innerText = procParts.length > 0 ? procParts.join('\n') : 'N/A';
            document.getElementById('modal_raw_val').innerText = JSON.stringify(entry, null, 2);
            const logModal = document.getElementById('log_modal');
            if (logModal) logModal.style.display = 'flex';
        }

        // Close log_modal when clicking outside the content box
        document.addEventListener('click', function(e) {
            const logModal = document.getElementById('log_modal');
            if (logModal && e.target === logModal) closeLogModal();
        });

        async function toggleSecurity() {
            const res = await fetch('/api/toggle_security', {
                method: 'POST',
                headers: { 'X-CSRF-Token': window.csrfToken }
            });
            const data = await res.json();
            updateSecurityToggleBtn(data.enabled);
        }

        async function installSnort() {
            const lang = localStorage.getItem('language') || 'en';
            let warnMsg = lang === 'es'
                ? '¿Estás seguro de que deseas instalar Snort? Se realizará de forma no interactiva (apt-get install -y snort).'
                : 'Are you sure you want to install Snort? It will be done non-interactively (apt-get install -y snort).';
            if (currentFirewallBackend !== 'none') {
                warnMsg = lang === 'es'
                    ? '⚠️ ADVERTENCIA: Se ha detectado un Firewall activo (' + currentFirewallBackend.toUpperCase() + ') en el sistema. La instalación de Snort puede interferir con la captura de paquetes o requerir reglas adicionales de filtrado para no bloquear tráfico legítimo.\\n\\n' + warnMsg
                    : '⚠️ WARNING: An active Firewall (' + currentFirewallBackend.toUpperCase() + ') has been detected on the system. Installing Snort may interfere with packet capture or require additional filtering rules to avoid blocking legitimate traffic.\\n\\n' + warnMsg;
            }
            if (!confirm(warnMsg)) {
                return;
            }
            const btn = document.getElementById('install_snort_btn');
            btn.innerText = lang === 'es' ? 'Instalando...' : 'Installing...';
            btn.disabled = true;
            try {
                const res = await fetch('/api/install_snort', {
                method: 'POST',
                headers: { 'X-CSRF-Token': window.csrfToken || '' }
            });
                const data = await res.json();
                alert(data.message);
            } catch(e) {
                alert((lang === 'es' ? 'Error al instalar Snort: ' : 'Error installing Snort: ') + e);
            } finally {
                refreshData();
            }
        }

        async function toggleSnort() {
            const lang = localStorage.getItem('language') || 'en';
            try {
                const res = await fetch('/api/toggle_snort', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': window.csrfToken || '' }
                });
                const data = await res.json();
                if (!data.success) {
                    alert(lang === 'es'
                        ? 'Operación fallida. Asegúrate de ejecutar tcpspecter con privilegios de root/sudo.'
                        : 'Operation failed. Make sure to run tcpspecter with root/sudo privileges.');
                }
            } catch(e) {
                alert((lang === 'es' ? 'Error al alternar Snort: ' : 'Error toggling Snort: ') + e);
            } finally {
                refreshData();
            }
        }

        async function blockIP(ip) {
            const lang = localStorage.getItem('language') || 'en';
            const ipToBlock = ip || document.getElementById('block_ip_input').value.trim();
            if (!ipToBlock) return;
            
            const confirmMsg = lang === 'es'
                ? `¿Bloquear tráfico de la IP ${ipToBlock}?`
                : `Block traffic from IP ${ipToBlock}?`;
            if (!confirm(confirmMsg)) return;
            
            try {
                const res = await fetch('/api/block_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.csrfToken || '' },
                    body: JSON.stringify({ ip: ipToBlock })
                });
                const data = await res.json();
                if (data.success) {
                    if (!ip) document.getElementById('block_ip_input').value = '';
                } else {
                    alert(lang === 'es'
                        ? 'Error al bloquear la IP. ¿Tienes permisos sudo?'
                        : 'Error blocking IP. Do you have sudo privileges?');
                }
            } catch(e) {
                alert('Error: ' + e);
            } finally {
                refreshData();
            }
        }

        async function unblockIP(ip) {
            const lang = localStorage.getItem('language') || 'en';
            if (!ip) return;
            const confirmMsg = lang === 'es'
                ? `¿Desbloquear tráfico de la IP ${ip}?`
                : `Unblock traffic from IP ${ip}?`;
            if (!confirm(confirmMsg)) return;
            
            try {
                const res = await fetch('/api/unblock_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.csrfToken || '' },
                    body: JSON.stringify({ ip: ip })
                });
                const data = await res.json();
                if (!data.success) {
                    alert(lang === 'es'
                        ? 'Error al desbloquear la IP. ¿Tienes permisos sudo?'
                        : 'Error unblocking IP. Do you have sudo privileges?');
                }
            } catch(e) {
                alert('Error: ' + e);
            } finally {
                refreshData();
            }
        }

        async function addCustomRule() {
            const lang = localStorage.getItem('language') || 'en';
            const action = document.getElementById('rb_action').value;
            const protocol = document.getElementById('rb_protocol').value;
            const src_ip = document.getElementById('rb_src_ip').value.trim();
            const dst_ip = document.getElementById('rb_dst_ip').value.trim();
            const port = document.getElementById('rb_port').value.trim();
            
            const confirmMsg = lang === 'es'
                ? `¿Aplicar nueva regla de firewall?\nAcción: ${action}\nProtocolo: ${protocol}\nOrigen: ${src_ip || 'Cualquiera'}\nDestino: ${dst_ip || 'Cualquiera'}\nPuerto: ${port || 'Todos'}`
                : `Apply new firewall rule?\nAction: ${action}\nProtocol: ${protocol}\nSource: ${src_ip || 'Any'}\nDestination: ${dst_ip || 'Any'}\nPort: ${port || 'All'}`;
            if (!confirm(confirmMsg)) return;
            
            try {
                const res = await fetch('/api/firewall/rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.csrfToken || '' },
                    body: JSON.stringify({ action, protocol, src_ip, dst_ip, port })
                });
                const data = await res.json();
                if (data.success) {
                    document.getElementById('rb_src_ip').value = '';
                    document.getElementById('rb_dst_ip').value = '';
                    document.getElementById('rb_port').value = '';
                    alert(lang === 'es'
                        ? 'Regla de firewall aplicada correctamente.'
                        : 'Firewall rule applied successfully.');
                } else {
                    const fallbackError = lang === 'es' ? 'Operación fallida. ¿Tienes permisos sudo?' : 'Operation failed. Do you have sudo privileges?';
                    alert('Error: ' + (data.error || fallbackError));
                }
            } catch(e) {
                alert('Error: ' + e);
            } finally {
                refreshData();
            }
        }

        const translations = {
            es: {
                subtitle: "Network Security Analytics — DLP + NDR + NTA + Engine de Explicación",
                nav_tutorial: "📖 Tutorial",
                nav_logs: "📄 Logs de Seguridad",
                btn_sec_active: "● ANALÍTICA ACTIVA",
                btn_sec_inactive: "○ ANALÍTICA DESACTIVADA",
                status_live: "Monitoreo en Vivo",
                sec_analysis: "Análisis de Seguridad de Red (C2 / Máquina Zombie)",
                score_lbl: "Riesgo",
                sec_threat_level: "Nivel de Amenaza:",
                active_alerts_lbl: "Alertas Activas:",
                risk_formula: "<strong>Fórmula Heurística de Riesgo:</strong><br>• Crítico (+40): Reverse Shell, C2, binario borrado<br>• Alto (+25): Ejecución en /tmp, SUID con red<br>• Medio (+10): Puerto abierto no confiable<br>• Riesgo Máximo acotado a 100.",
                chart_proto_dist: "Distribución de Protocolos",
                chart_top_cpu: "Top Procesos CPU (%)",
                chart_bandwidth: "Tráfico de Red Histórico (Mbps)",
                sec_alerts_active: "Alertas C2 / Comportamientos Zombie",
                no_alerts: "No se han detectado alertas de seguridad activas.",
                no_conns: "No se encontraron conexiones que coincidan.",
                nav_dashboard: "Dashboard",
                nav_firewall: "Cortafuegos e IDS",
                nav_intelligence: "Inteligencia de Amenazas",
                nav_logs: "📄 Logs de Seguridad",
                nav_config: "Configuración",
                config_title: "Configuración del Sistema",
                config_lang: "Idioma / Language",
                config_lang_desc: "Selecciona el idioma de la interfaz gráfica.",
                config_tutorial: "Tutoriales y Documentación",
                config_tutorial_desc: "Aprende cómo usar TCPspecter y explorar sus capacidades.",
                config_tutorial_btn: "Ver Tutorial Interactivo",
                // Firewall view keys
                fw_title: "Políticas de Seguridad de Red (Firewall e IDS)",
                fw_subtitle: "Configuración avanzada de interfaces, IPS y filtrado de red",
                fw_snort_lbl: "Servicio Snort:",
                fw_install_btn: "Instalar Snort",
                fw_toggle_btn: "Iniciar/Detener",
                fw_builder_title: "+ Nueva Regla de Cortafuegos (Rule Builder)",
                fw_drop_btn: "Bloquear (Quick)",
                fw_action_lbl: "Acción *",
                fw_opt_deny: "Bloquear (DENY)",
                fw_opt_allow: "Permitir (ALLOW)",
                fw_proto_lbl: "Protocolo",
                fw_src_lbl: "IP Origen",
                fw_dst_lbl: "IP Destino",
                fw_port_lbl: "Puerto",
                fw_apply_btn: "Aplicar Regla",
                fw_active_rules_lbl: "Reglas Cortafuegos Activas:",
                fw_tbl_rule: "Regla / IP Afectada",
                fw_tbl_backend: "Gestor (Backend)",
                fw_tbl_policy: "Política (Target)",
                fw_tbl_action: "Acción",
                fw_tbl_loading: "Cargando reglas...",
                // Map view keys
                map_title: "Mapa Global de Conexiones",
                map_desc: "Análisis de Nodos de Tráfico en Tiempo Real",
                map_recenter_btn: "Recentrar Mapa",
                // Connections view keys
                conns_title: "Conexiones del Sistema Activas",
                conns_desc: "Selecciona cualquier fila para traducir e interpretar lo que está pasando en la red.",
                conns_loading: "Cargando conexiones del sistema...",
                hdr_proc: "Proceso",
                hdr_pid: "PID",
                hdr_proto: "Proto",
                hdr_src_ip: "IP Origen",
                hdr_src_port: "Pto Orig.",
                hdr_dst_ip: "IP Destino",
                hdr_dst_port: "Pto Dest.",
                hdr_status: "Estado",
                hdr_eval: "Evaluación",
                // Modal translation keys
                modal_title: "Interpretación de Conexión",
                modal_ip_scope: "Ámbito de la IP Destino",
                modal_port_purpose: "Propósito del Puerto",
                modal_conn_state: "Estado de la Conexión",
                modal_sec_analysis: "Análisis de Seguridad Detallado",
                modal_recs: "Recomendaciones",
                modal_edu: "Contexto Educativo",
                intel_dashboard_title: "Correlación de Inteligencia de Amenazas",
                intel_feed_entries: "Entradas Indexadas",
                intel_feeds_loaded: "Feeds Activos",
                intel_match_count: "Coincidencias",
                intel_status: "Estado del Motor",
                intel_no_matches: "Sin coincidencias de inteligencia todavía.",
                intel_title: "Motor de Inteligencia de Amenazas",
                intel_subtitle: "Correlación local de puertos, IPs, dominios y TLDs",
                intel_btn_active: "● MOTOR ACTIVO",
                intel_btn_inactive: "○ MOTOR DESACTIVADO",
                intel_reload_btn: "Recargar Feeds",
                intel_last_reload: "Última Recarga",
                intel_feeds_title: "Feeds Cargados",
                intel_col_feed: "Feed",
                intel_col_status: "Estado",
                intel_col_entries: "Entradas",
                intel_col_error: "Notas",
                intel_alerts_title: "Alertas de Inteligencia en Vivo",
                intel_loading: "Cargando feeds...",
                intel_feed_hint: "Coloca feeds CSV o texto en <code>data/feeds/</code>. Copia <code>custom_blacklist.example.txt</code> a <code>custom_blacklist.txt</code> para bloques IP personalizados."
            },
            en: {
                subtitle: "Network Security Analytics — DLP + NDR + NTA + Explanation Engine",
                nav_tutorial: "📖 Tutorial",
                nav_logs: "📄 Security Logs",
                btn_sec_active: "● SECURITY ANALYTICS ACTIVE",
                btn_sec_inactive: "○ SECURITY ANALYTICS INACTIVE",
                status_live: "Live Monitoring",
                sec_analysis: "Network Security Analysis (C2 / Botnet)",
                score_lbl: "Risk",
                sec_threat_level: "Threat Level:",
                active_alerts_lbl: "Active Alerts:",
                risk_formula: "<strong>Risk Heuristic Formula:</strong><br>• Critical (+40): Reverse Shell, C2, deleted binary<br>• High (+25): Execution in /tmp, SUID with network<br>• Medium (+10): Untrusted open listening port<br>• Max Risk capped at 100.",
                chart_proto_dist: "Protocol Distribution",
                chart_top_cpu: "Top CPU Processes (%)",
                chart_bandwidth: "Historical Network Traffic (Mbps)",
                sec_alerts_active: "C2 Alerts / Botnet Behaviors",
                no_alerts: "No active security alerts detected.",
                no_conns: "No matching connections found.",
                nav_dashboard: "Dashboard",
                nav_firewall: "Firewall & IDS",
                nav_intelligence: "Threat Intelligence",
                nav_logs: "📄 Security Logs",
                nav_config: "Settings",
                config_title: "System Configuration",
                config_lang: "Language / Idioma",
                config_lang_desc: "Select the graphical interface language.",
                config_tutorial: "Tutorials & Documentation",
                config_tutorial_desc: "Learn how to use TCPspecter and explore its capabilities.",
                config_tutorial_btn: "View Interactive Tutorial",
                // Firewall view keys
                fw_title: "Network Security Policies (Firewall & IDS)",
                fw_subtitle: "Advanced interface, IPS and network filtering configuration",
                fw_snort_lbl: "Snort Service:",
                fw_install_btn: "Install Snort",
                fw_toggle_btn: "Start/Stop",
                fw_builder_title: "+ New Firewall Rule (Rule Builder)",
                fw_drop_btn: "Drop (Quick)",
                fw_action_lbl: "Action *",
                fw_opt_deny: "Block (DENY)",
                fw_opt_allow: "Allow (ALLOW)",
                fw_proto_lbl: "Protocol",
                fw_src_lbl: "Source IP",
                fw_dst_lbl: "Destination IP",
                fw_port_lbl: "Port",
                fw_apply_btn: "Apply Rule",
                fw_active_rules_lbl: "Active Firewall Rules:",
                fw_tbl_rule: "Rule / Affected IP",
                fw_tbl_backend: "Manager (Backend)",
                fw_tbl_policy: "Policy (Target)",
                fw_tbl_action: "Action",
                fw_tbl_loading: "Loading rules...",
                // Map view keys
                map_title: "Global Connection Map",
                map_desc: "Real-Time Traffic Node Analysis",
                map_recenter_btn: "Recenter Map",
                // Connections view keys
                conns_title: "Active System Connections",
                conns_desc: "Select any row to translate and interpret what is happening in the network.",
                conns_loading: "Loading system connections...",
                hdr_proc: "Process",
                hdr_pid: "PID",
                hdr_proto: "Proto",
                hdr_src_ip: "Source IP",
                hdr_src_port: "Src Port",
                hdr_dst_ip: "Dest IP",
                hdr_dst_port: "Dst Port",
                hdr_status: "State",
                hdr_eval: "Assessment",
                // Modal translation keys
                modal_title: "Connection Interpretation",
                modal_ip_scope: "Destination IP Scope",
                modal_port_purpose: "Port Purpose",
                modal_conn_state: "Connection State",
                modal_sec_analysis: "Detailed Security Analysis",
                modal_recs: "Recommendations",
                modal_edu: "Educational Context",
                intel_dashboard_title: "Threat Intelligence Correlation",
                intel_feed_entries: "Indexed Entries",
                intel_feeds_loaded: "Active Feeds",
                intel_match_count: "Matches",
                intel_status: "Engine Status",
                intel_no_matches: "No threat intelligence matches yet.",
                intel_title: "Threat Intelligence Engine",
                intel_subtitle: "Local feed correlation for ports, IPs, domains, and TLDs",
                intel_btn_active: "● ENGINE ACTIVE",
                intel_btn_inactive: "○ ENGINE DISABLED",
                intel_reload_btn: "Reload Feeds",
                intel_last_reload: "Last Reload",
                intel_feeds_title: "Loaded Feeds",
                intel_col_feed: "Feed",
                intel_col_status: "Status",
                intel_col_entries: "Entries",
                intel_col_error: "Notes",
                intel_alerts_title: "Live Intelligence Alerts",
                intel_loading: "Loading feeds...",
                intel_feed_hint: "Place CSV or text feeds under <code>data/feeds/</code>. Copy <code>custom_blacklist.example.txt</code> to <code>custom_blacklist.txt</code> for operator-defined IP blocks."
            }
        };

        function changeLanguage(lang) {
            localStorage.setItem('language', lang);
            applyLanguage();
        }

        function applyLanguage() {
            const lang = localStorage.getItem('language') || 'en';
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (translations[lang][key]) {
                    el.innerHTML = translations[lang][key];
                }
            });
            const searchBar = document.getElementById('search_bar');
            if (searchBar) {
                searchBar.placeholder = lang === 'es' ? "Buscar por proceso, PID, IP, puerto..." : "Search by process, PID, IP, port...";
            }
            const blockIpInput = document.getElementById('block_ip_input');
            if (blockIpInput) {
                blockIpInput.placeholder = lang === 'es' ? "Quick Block: IP a bloquear" : "Quick Block: IP to block";
            }
            const rbSrc = document.getElementById('rb_src_ip');
            if (rbSrc) rbSrc.placeholder = lang === 'es' ? "Cualquiera" : "Any";
            const rbDst = document.getElementById('rb_dst_ip');
            if (rbDst) rbDst.placeholder = lang === 'es' ? "Cualquiera" : "Any";
            const rbPort = document.getElementById('rb_port');
            if (rbPort) rbPort.placeholder = lang === 'es' ? "Todos" : "All";
            
            // Re-label security toggle button text based on state and language
            const btn = document.getElementById('security_toggle_btn');
            if (btn) {
                const isActive = btn.innerHTML.includes('●') || btn.innerHTML.includes('ACTIVE') || btn.innerHTML.includes('ACTIVA');
                btn.innerHTML = isActive ? translations[lang]['btn_sec_active'] : translations[lang]['btn_sec_inactive'];
            }

            // Style active language button
            document.querySelectorAll('.lang-btn').forEach(b => {
                const isCurrent = b.getAttribute('data-lang') === lang;
                b.style.background = isCurrent ? 'rgba(74, 122, 157, 0.3)' : 'rgba(255,255,255,0.03)';
                b.style.borderColor = isCurrent ? 'var(--primary)' : 'var(--card-border)';
                b.style.color = isCurrent ? 'var(--text-main)' : 'var(--text-muted)';
            });
        }

        // Called by language buttons in /configuration view (inline onclick handlers)
        // NOTE: single declaration only — first one at line ~1059 is removed to avoid re-definition
        window.changeLanguage = changeLanguage; // expose globally

        const helpTranslations = {
            es: {
                security: {
                    title: "Análisis de Seguridad (C2 / Zombie)",
                    desc: "Este panel muestra el cálculo del puntaje de riesgo del host basado en heurísticas del Zombie Detector. Evalúa patrones de beaconing C2, conexiones reversas de shell activas, binarios ejecutándose desde archivos eliminados del disco, binarios SUID con actividad de red y ejecutables ubicados en rutas volátiles como /tmp."
                },
                proto: {
                    title: "Distribución de Protocolos",
                    desc: "Este gráfico muestra la distribución de sockets de red abiertos en tu máquina. Clasifica en conexiones TCP activas, UDP de datagramas y puertos LISTEN que están a la escucha de nuevas conexiones entrantes."
                },
                cpu: {
                    title: "Top Procesos por CPU",
                    desc: "Muestra en tiempo real los procesos del sistema operativo que están consumiendo mayor porcentaje de CPU, permitiendo identificar picos de carga o hilos de malware de minería (cryptominers) en ejecución."
                },
                bandwidth: {
                    title: "Tráfico de Red Histórico",
                    desc: "Mide y grafica la velocidad de entrada (RX) y salida (TX) de paquetes en Mbps en todas tus interfaces de red. Útil para capturar picos de exfiltración o de tráfico inusual."
                },
                entropy: {
                    title: "Entropía de Payload Histórica",
                    desc: "Gráfico de la entropía de Shannon promedio detectada en las cargas de red TCP. Valores altos (> 7.3) sugieren que se están enviando datos cifrados o archivos altamente comprimidos, lo cual podría indicar canales cifrados C2 o exfiltración encubierta de backups."
                },
                alerts: {
                    title: "Alertas C2 / Comportamientos Zombie",
                    desc: "Registra incidentes graves detectados por el motor heurístico local. Ejemplos incluyen llamadas a Reverse Shell, masquarading de procesos (ejecutables con nombres comunes corriendo desde rutas no estándar) y persistencia del sistema."
                },
                ids_fw: {
                    title: "IDS Snort & Firewall",
                    desc: "Permite gestionar el cortafuegos local (iptables/ufw) e iniciar/detener el servicio pasivo de detección de intrusos Snort. Puedes ver la lista de IPs bloqueadas y agregar nuevas reglas de bloqueo o aislamiento."
                },
                dlp_ndr: {
                    title: "Alertas DLP & NDR (Scapy/DNS)",
                    desc: "Muestra alertas en tiempo real extraídas por el sniffer de red de Scapy y DNS: detección de exfiltración de archivos críticos por firmas de Magic Bytes (DLP), consultas de dominios aleatorios (DGA) y túneles DNS en el puerto 53."
                },
                map: {
                    title: "Mapa Global de Conexiones",
                    desc: "Visualiza geográficamente las direcciones IP públicas de tus sockets activos. Utiliza el módulo Traceroute asíncrono para mapear los saltos intermedios en un globo interactivo Apache ECharts."
                },
                connections: {
                    title: "Conexiones del Sistema Activas",
                    desc: "Tabla interactiva de flujos y sockets de red en tiempo real. Al hacer clic en cualquier fila, el Explanation Engine de TCPspecter traduce las variables de red (como puertos conocidos, DNS o ASN) a descripciones comprensibles para humanos."
                },
                intelligence: {
                    title: "Inteligencia de Amenazas",
                    desc: "Correlaciona conexiones y consultas DNS contra feeds locales: puertos maliciosos, nodos Tor, dominios sinkhole, proveedores DynDNS, TLDs de alto abuso y listas negras personalizadas del operador."
                }
            },
            en: {
                security: {
                    title: "Security Analysis (C2 / Botnet)",
                    desc: "This card shows the heuristic risk score calculated by the Zombie Detector. It monitors active reverse shells, process name masquerading, execution from deleted binaries, SUID binaries communicating over the network, and scripts running from volatile paths like /tmp."
                },
                proto: {
                    title: "Protocol Distribution",
                    desc: "Displays the relative percentage of open sockets categorized into active TCP connections, UDP datagrams, and LISTEN ports waiting for inbound traffic."
                },
                cpu: {
                    title: "Top CPU Processes",
                    desc: "Shows running system processes that consume the highest amount of processor resources, helpful for pinpointing system spikes or silent mining malware."
                },
                bandwidth: {
                    title: "Historical Network Traffic",
                    desc: "Graphs the inbound (RX) and outbound (TX) transfer rates in Mbps across all system network interfaces to help you detect network exfiltration spikes."
                },
                entropy: {
                    title: "Historical Payload Entropy",
                    desc: "Tracks the average Shannon entropy of TCP packet payloads. High values (> 7.3) signify encrypted channels (like AES) or compressed files, which are common signatures of C2 channels or database exfiltration."
                },
                alerts: {
                    title: "C2 Alerts / Zombie Behaviors",
                    desc: "Lists critical security events captured by the host heuristics agent, such as reverse shell calls, process masquerading, system persistence setups, and orphaned C2 processes."
                },
                ids_fw: {
                    title: "IDS Snort & Firewall",
                    desc: "Provides centralized firewall control (iptables/ufw) and lifecycle management of the Snort Intrusion Detection System. Allows you to block suspect IPs and manage quarantine rules."
                },
                dlp_ndr: {
                    title: "DLP & NDR Alerts (Scapy/DNS)",
                    desc: "Real-time network alerts processed by the passive sniffer: Data Loss Prevention (DLP) magic byte detection, Domain Generation Algorithms (DGA), and DNS Tunneling exfiltration over port 53."
                },
                map: {
                    title: "Global Connection Map",
                    desc: "Geographically visualizes public IP addresses of active connections. Uses asynchronous traceroute routines to plot network hops on an interactive Apache ECharts globe."
                },
                connections: {
                    title: "Active Network Connections",
                    desc: "Real-time interactive sockets table. Clicking any row triggers TCPspecter's Explanation Engine to translate network attributes (such as ports, DNS, and ASN) into plain human-readable text."
                },
                intelligence: {
                    title: "Threat Intelligence",
                    desc: "Correlates live connections and DNS queries against local feeds: malicious ports, Tor exit nodes, sinkholed domains, dynamic DNS providers, high-abuse TLDs, and operator-defined blacklists."
                }
            }
        };

        function showModuleHelp(moduleKey, event) {
            // Prevent triggering modal when clicking interactive controls (buttons, links, inputs, canvas)
            if (event && (
                event.target.tagName === 'BUTTON' || 
                event.target.tagName === 'A' || 
                event.target.tagName === 'INPUT' || 
                event.target.tagName === 'CANVAS' ||
                event.target.closest('button') ||
                event.target.closest('a') ||
                event.target.closest('input')
            )) {
                return;
            }
            const lang = localStorage.getItem('language') || 'en';
            const info = helpTranslations[lang][moduleKey];
            if (info) {
                document.getElementById('help_title').innerText = info.title;
                document.getElementById('help_desc').innerHTML = info.desc;
                document.getElementById('help_modal').style.display = 'flex';
            }
        }

        function closeHelpModal() {
            document.getElementById('help_modal').style.display = 'none';
        }

        // ── Logs SPA Functions ────────────────────────────────────────────
        async function fetchLogs() {
            try {
                const lang = localStorage.getItem('language') || 'en';
                const res = await fetch(`/api/logs?lang=${encodeURIComponent(lang)}`);
                allLogs = await res.json();
                renderLogs();
            } catch (err) {
                console.error('Error loading logs:', err);
            }
        }

        function setFilter(type, val, btn) {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            if (type === 'status') {
                logsStatusFilter = val;
                logsSeverityFilter = 'ALL';
            } else if (type === 'severity') {
                logsSeverityFilter = val;
                logsStatusFilter = 'ALL';
            }
            logsCurrentPage = 1;
            renderLogs();
        }

        function filterLogs() {
            logsCurrentPage = 1;
            renderLogs();
        }

        function changePage(delta) {
            logsCurrentPage += delta;
            renderLogs();
        }

        function renderLogs() {
            const tbody = document.getElementById('logs_tbody');
            if (!tbody) return;
            const searchEl = document.getElementById('search_log');
            const searchVal = searchEl ? searchEl.value.toLowerCase().trim() : '';

            const filtered = allLogs.filter(entry => {
                if (logsStatusFilter !== 'ALL' && entry.status !== logsStatusFilter) return false;
                if (logsSeverityFilter !== 'ALL' && entry.severity !== logsSeverityFilter) return false;
                if (searchVal) {
                    return (
                        (entry.proc_name || '').toLowerCase().includes(searchVal) ||
                        String(entry.pid || '').includes(searchVal) ||
                        (entry.description || '').toLowerCase().includes(searchVal) ||
                        (entry.category || '').toLowerCase().includes(searchVal)
                    );
                }
                return true;
            });

            const paginationEl = document.getElementById('pagination_controls');

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px 0;">No logs found in the audit trail.</td></tr>`;
                if (paginationEl) paginationEl.style.display = 'none';
                return;
            }

            const totalPages = Math.ceil(filtered.length / LOGS_ITEMS_PER_PAGE);
            if (logsCurrentPage > totalPages) logsCurrentPage = totalPages;
            if (logsCurrentPage < 1) logsCurrentPage = 1;

            if (paginationEl) {
                paginationEl.style.display = 'flex';
                document.getElementById('page_info').innerText = `Page ${logsCurrentPage} of ${totalPages}`;
                document.getElementById('btn_prev_page').disabled = (logsCurrentPage === 1);
                document.getElementById('btn_next_page').disabled = (logsCurrentPage === totalPages);
            }

            const startIndex = (logsCurrentPage - 1) * LOGS_ITEMS_PER_PAGE;
            const paginated = filtered.slice(startIndex, startIndex + LOGS_ITEMS_PER_PAGE);
            window._logsFiltered = filtered;

            tbody.innerHTML = paginated.map((entry, idx) => {
                const globalIdx = startIndex + idx;
                const statusBadge = entry.status === 'DETECTED' ? 'badge-detected' : 'badge-resolved';
                const statusLabel = entry.status === 'DETECTED' ? '⚠️ DETECTED' : '✅ RESOLVED';
                let sevClass = 'sev-bajo';
                if (entry.severity === 'CRITICAL') sevClass = 'sev-critico';
                else if (entry.severity === 'HIGH') sevClass = 'sev-alto';
                else if (entry.severity === 'MEDIUM') sevClass = 'sev-medio';
                return `
                    <tr onclick="showLogDetails(${globalIdx})" style="cursor:pointer;transition:background 0.2s;border-bottom:1px solid var(--card-border);">
                        <td style="padding:12px;font-family:monospace;color:var(--text-muted);">${entry.timestamp}</td>
                        <td style="padding:12px;"><span class="badge ${statusBadge}">${statusLabel}</span></td>
                        <td style="padding:12px;"><span class="badge ${sevClass}">${entry.severity}</span></td>
                        <td style="padding:12px;"><strong>${entry.category}</strong></td>
                        <td style="padding:12px;">${entry.pid || '-'}</td>
                        <td style="padding:12px;"><code>${entry.proc_name || '-'}</code></td>
                        <td style="padding:12px;">${entry.description}</td>
                    </tr>`;
            }).join('');
        }

        function showLogDetails(index) {
            const logs = window._logsFiltered;
            if (!logs || !logs[index]) return;
            const entry = logs[index];
            document.getElementById('modal_cat').innerText = entry.category;
            document.getElementById('modal_meta').innerText = `${entry.timestamp} | ${entry.severity} | ${entry.status}`;
            document.getElementById('modal_desc_val').innerText = entry.description;
            const procParts = [];
            if (entry.pid)       procParts.push(`PID: ${entry.pid}`);
            if (entry.proc_name) procParts.push(`Process: ${entry.proc_name}`);
            if (entry.exe_path)  procParts.push(`Executable: ${entry.exe_path}`);
            if (entry.cmdline)   procParts.push(`Command: ${entry.cmdline}`);
            document.getElementById('modal_proc_val').innerText = procParts.length > 0 ? procParts.join('\n') : 'N/A';
            document.getElementById('modal_raw_val').innerText = JSON.stringify(entry, null, 2);
            const logModal = document.getElementById('log_modal');
            if (logModal) logModal.style.display = 'flex';
        }

        function closeLogModal() {
            const logModal = document.getElementById('log_modal');
            if (logModal) {
                logModal.style.display = 'none';
            }
        }

        function handleRouting() {
            const path = window.location.pathname;
            document.querySelectorAll('.spa-view').forEach(v => v.style.display = 'none');

            document.querySelectorAll('nav a').forEach(a => {
                a.style.color = 'var(--text-main)';
                if (a.getAttribute('href') === path) {
                    a.style.color = 'var(--primary)';
                }
            });

            if (path === '/firewall') {
                document.getElementById('view_firewall').style.display = 'block';
                if (logsInterval) { clearInterval(logsInterval); logsInterval = null; }
                fetchAndUpdateNow();
            } else if (path === '/intelligence') {
                document.getElementById('view_intelligence').style.display = 'block';
                if (logsInterval) { clearInterval(logsInterval); logsInterval = null; }
                fetchAndUpdateNow();
            } else if (path === '/configuration') {
                document.getElementById('view_configuration').style.display = 'block';
                if (logsInterval) { clearInterval(logsInterval); logsInterval = null; }
            } else if (path === '/logs') {
                const viewLogs = document.getElementById('view_logs');
                if (viewLogs) viewLogs.style.display = 'block';
                fetchLogs();
                if (!logsInterval) logsInterval = setInterval(fetchLogs, 3000);
            } else {
                document.getElementById('view_dashboard').style.display = 'block';
                if (globeChart) globeChart.resize();
                if (logsInterval) { clearInterval(logsInterval); logsInterval = null; }
            }
        }

        window.onload = async () => {
            initCharts();
            await initGlobe();
            initWebSocket();
            applyLanguage();
            handleRouting(); // Render the correct SPA view based on URL
            // Immediately populate all views without waiting for first WS message
            await fetchAndUpdateNow();
        };