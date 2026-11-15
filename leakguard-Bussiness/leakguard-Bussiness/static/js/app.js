/*
 * LeakGuard - Frontend Application Logic
 * Handles dashboard data, simulator, incident management, and charts
 */

// API base (same origin)
const API = {
    stats: '/api/stats',
    events: '/api/events',
    incidents: '/api/incidents',
    simulateLogin: '/api/simulate_login',
    demoSimulate: '/api/demo_simulate',
    runDetection: '/api/run_detection',
    updateIncidentStatus: (id) => `/api/incidents/${id}/status`,
    incidentDetail: (id) => `/api/incidents/${id}`,
    reset: '/api/reset',
};

// State
let currentFilter = 'all';
let selectedIncidentId = null;

// ============================================
// Initialization
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    refreshData();
    initCharts();
    setInterval(refreshData, 10000); // Auto-refresh every 10 seconds
});

// ============================================
// Navigation
// ============================================
function navigateTo(sectionId) {
    // Update sidebar
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    event.currentTarget.classList.add('active');

    // Update sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(`section-${sectionId}`).classList.add('active');

    // Update page title
    const titles = {
        dashboard: 'Dashboard',
        simulator: 'Event Simulator',
        incidents: 'Incident Management',
    };
    document.getElementById('page-title').textContent = titles[sectionId] || 'Dashboard';

    // Load relevant data
    if (sectionId === 'incidents') {
        loadIncidentsTable();
    }
}

// ============================================
// Data Fetching
// ============================================
async function refreshData() {
    try {
        await Promise.all([loadStats(), loadEvents(), loadIncidentsTable()]);
    } catch (err) {
        console.error('Failed to refresh data:', err);
    }
}

async function loadStats() {
    const res = await fetch(API.stats);
    const data = await res.json();

    document.getElementById('stat-total-events').textContent = data.total_events || 0;
    document.getElementById('stat-total-incidents').textContent = data.total_incidents || 0;
    document.getElementById('stat-open-incidents').textContent = data.open_incidents || 0;
    document.getElementById('stat-investigating-incidents').textContent = data.investigating_incidents || 0;
    document.getElementById('stat-closed-incidents').textContent = data.closed_incidents || 0;
    document.getElementById('stat-high-severity').textContent = data.high_severity || 0;

    updateCharts(data);
}

async function loadEvents() {
    const res = await fetch(API.events);
    const events = await res.json();

    const tbody = document.getElementById('events-table-body');
    tbody.innerHTML = '';

    if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 2rem;">No security events recorded yet.</td></tr>`;
        return;
    }

    events.forEach(evt => {
        const isFailed = evt.event_type === 'login_failed';
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${formatTime(evt.timestamp)}</code></td>
            <td><strong>${escapeHtml(evt.username)}</strong></td>
            <td><span class="badge ${isFailed ? 'badge-danger' : 'badge-success'}">${escapeHtml(evt.event_type)}</span></td>
            <td><code>${escapeHtml(evt.source_ip || '-')}</code></td>
            <td>${isFailed ? '<span style="color: var(--danger);">● Failed</span>' : '<span style="color: var(--success);">● Success</span>'}</td>
        `;
        tbody.appendChild(row);
    });
}

async function loadIncidentsTable() {
    const res = await fetch(API.incidents);
    const incidents = await res.json();

    const tbody = document.getElementById('incidents-detail-body');
    tbody.innerHTML = '';

    // Also update dashboard incidents table
    const dashTbody = document.getElementById('incidents-table-body');
    dashTbody.innerHTML = '';

    const filtered = currentFilter === 'all'
        ? incidents
        : incidents.filter(inc => inc.status === currentFilter);

    if (filtered.length === 0) {
        const emptyRow = `<tr><td colspan="8" style="text-align:center; color: var(--text-muted); padding: 2rem;">No incidents found.</td></tr>`;
        tbody.innerHTML = emptyRow;
        dashTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 2rem;">No active incidents.</td></tr>`;
        return;
    }

    filtered.forEach(inc => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${escapeHtml(inc.incident_id)}</code></td>
            <td><strong>${escapeHtml(inc.title)}</strong></td>
            <td>${escapeHtml(inc.username)}</td>
            <td><span class="severity-badge severity-${inc.severity.toLowerCase()}">${escapeHtml(inc.severity)}</span></td>
            <td><span class="status-badge status-${inc.status.toLowerCase()}">${escapeHtml(inc.status)}</span></td>
            <td>${inc.event_count}</td>
            <td><code>${formatTime(inc.detection_timestamp)}</code></td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="openIncidentModal('${escapeHtml(inc.incident_id)}')">View</button>
            </td>
        `;
        tbody.appendChild(row);

        // Dashboard table (only open/investigating)
        if (inc.status === 'Open' || inc.status === 'Investigating') {
            const dashRow = document.createElement('tr');
            dashRow.innerHTML = `
                <td><code>${escapeHtml(inc.incident_id)}</code></td>
                <td><strong>${escapeHtml(inc.title)}</strong></td>
                <td><span class="severity-badge severity-${inc.severity.toLowerCase()}">${escapeHtml(inc.severity)}</span></td>
                <td><span class="status-badge status-${inc.status.toLowerCase()}">${escapeHtml(inc.status)}</span></td>
                <td><button class="btn btn-sm btn-primary" onclick="openIncidentModal('${escapeHtml(inc.incident_id)}')">View</button></td>
            `;
            dashTbody.appendChild(dashRow);
        }
    });
}

// ============================================
// Simulator
// ============================================
async function simulateLogin() {
    const username = document.getElementById('sim-username').value.trim() || 'demo_user';
    const result = document.getElementById('sim-result').value;

    const output = document.getElementById('sim-result-output');
    output.innerHTML = `<div class="output-line">Simulating ${result} login for <span class="highlight">${escapeHtml(username)}</span>...</div>`;

    try {
        const res = await fetch(API.simulateLogin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, result }),
        });
        const data = await res.json();

        let html = '';
        html += `<div class="output-line">✓ Event recorded: <span class="highlight">${data.event_type}</span> at ${formatTime(data.timestamp)}</div>`;
        if (data.incidents_created > 0) {
            html += `<div class="output-line"><span class="alert">⚠ ALERT: Detection engine triggered!</span> ${data.incidents_created} new incident(s) created.</div>`;
        } else if (result === 'failed') {
            html += `<div class="output-line">No detection threshold met yet. Continue simulating failed logins to trigger an incident.</div>`;
        }
        output.innerHTML = html;

        // Refresh data after simulation
        setTimeout(refreshData, 500);
    } catch (err) {
        output.innerHTML = `<div class="output-line"><span class="alert">Error:</span> ${err.message}</div>`;
        console.error(err);
    }
}

async function runDetection() {
    try {
        const res = await fetch(API.runDetection, { method: 'POST' });
        const data = await res.json();
        alert(`Detection engine scan complete. Potential incidents identified: ${data.potential_incidents}`);
        refreshData();
    } catch (err) {
        alert('Error running detection engine.');
        console.error(err);
    }
}

async function runDemoSimulation() {
    const username = document.getElementById('sim-username').value.trim() || 'demo_user';
    const output = document.getElementById('sim-result-output');

    // Show demo in progress
    output.innerHTML = `
        <div class="output-line"><span class="highlight">🎓 FACULTY DEMO MODE</span></div>
        <div class="output-line">Step 1/4: Resetting demo data...</div>
    `;

    try {
        // Step 1: Reset
        await fetch(API.reset, { method: 'POST' });

        output.innerHTML += `<div class="output-line">✓ Demo data cleared.</div>
<div class="output-line">Step 2/4: Simulating 5 rapid failed logins for <span class="highlight">${escapeHtml(username)}</span>...</div>`;

        // Step 2: Demo simulate
        const res = await fetch(API.demoSimulate, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, count: 5 }),
        });
        const data = await res.json();

        output.innerHTML += `<div class="output-line">✓ ${data.failed_logins_simulated} failed login events recorded.</div>
<div class="output-line"><span class="alert">⚠ ALERT: Detection engine triggered!</span> ${data.incidents_created} High severity incident(s) auto-created.</div>
<div class="output-line">Step 3/4: Refreshing dashboard...</div>`;

        // Step 3: Refresh data
        await refreshData();

        output.innerHTML += `<div class="output-line">✓ Dashboard updated with live incident.</div>
<div class="output-line">Step 4/4: Demo complete!</div>
<div class="output-line"><span class="highlight">📋 Next: Open the incident → review evidence → set status to Investigating → Closed.</span></div>`;

    } catch (err) {
        output.innerHTML = `<div class="output-line"><span class="alert">Demo error:</span> ${err.message}</div>`;
        console.error(err);
    }
}

async function resetDemo() {
    if (!confirm('Reset all demo data? This will clear all events and incidents.')) return;

    try {
        const res = await fetch(API.reset, { method: 'POST' });
        await res.json();
        alert('Demo data reset. Ready for fresh demonstration.');
        refreshData();
    } catch (err) {
        alert('Error resetting demo data.');
        console.error(err);
    }
}

// ============================================
// Incident Management
// ============================================
async function openIncidentModal(incidentId) {
    selectedIncidentId = incidentId;
    const modal = document.getElementById('incident-modal');

    try {
        const res = await fetch(API.incidentDetail(incidentId));
        const inc = await res.json();

        document.getElementById('modal-title').textContent = `Incident ${inc.incident_id}`;
        document.getElementById('detail-incident-id').textContent = inc.incident_id;
        document.getElementById('detail-title').textContent = inc.title;
        document.getElementById('detail-username').textContent = inc.username;
        document.getElementById('detail-severity').textContent = inc.severity;
        document.getElementById('detail-severity').className = `severity-badge severity-${inc.severity.toLowerCase()}`;
        document.getElementById('detail-status').textContent = inc.status;
        document.getElementById('detail-status').className = `status-badge status-${inc.status.toLowerCase()}`;
        document.getElementById('detail-event-count').textContent = inc.event_count;
        document.getElementById('detail-detection-time').textContent = formatTime(inc.detection_timestamp);
        document.getElementById('detail-evidence').textContent = inc.evidence || 'No evidence recorded.';
        document.getElementById('modal-new-status').value = inc.status;

        // Status history
        const historyBody = document.getElementById('history-table-body');
        historyBody.innerHTML = '';
        (inc.status_history || []).forEach(h => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${escapeHtml(h.old_status || '—')}</td>
                <td>${escapeHtml(h.new_status)}</td>
                <td><code>${formatTime(h.changed_at)}</code></td>
                <td>${escapeHtml(h.changed_by)}</td>
            `;
            historyBody.appendChild(row);
        });

        modal.classList.add('active');
    } catch (err) {
        alert('Failed to load incident details.');
        console.error(err);
    }
}

function closeIncidentModal() {
    document.getElementById('incident-modal').classList.remove('active');
    selectedIncidentId = null;
}

// Close modal when clicking outside
document.getElementById('incident-modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('incident-modal')) {
        closeIncidentModal();
    }
});

async function updateIncidentStatus() {
    if (!selectedIncidentId) return;

    const newStatus = document.getElementById('modal-new-status').value;

    try {
        const res = await fetch(API.updateIncidentStatus(selectedIncidentId), {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus }),
        });
        const data = await res.json();

        alert(`Incident status updated: ${data.old_status} → ${data.new_status}`);
        closeIncidentModal();
        refreshData();
    } catch (err) {
        alert('Failed to update incident status.');
        console.error(err);
    }
}

function filterIncidents(status) {
    currentFilter = status;
    document.querySelectorAll('.filter-chip').forEach(chip => {
        chip.classList.remove('active');
    });
    event.currentTarget.classList.add('active');
    loadIncidentsTable();
}

// ============================================
// Charts
// ============================================
let severityChartInstance = null;
let statusChartInstance = null;

function initCharts() {
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    const statusCtx = document.getElementById('statusChart').getContext('2d');

    severityChartInstance = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                borderWidth: 0,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Inter' } } },
                title: { display: true, text: 'Incidents by Severity', color: '#94a3b8', font: { size: 13, weight: 600 } }
            }
        }
    });

    statusChartInstance = new Chart(statusCtx, {
        type: 'bar',
        data: {
            labels: ['Open', 'Investigating', 'Closed'],
            datasets: [{
                label: 'Incidents',
                data: [0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                borderWidth: 0,
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Incidents by Status', color: '#94a3b8', font: { size: 13, weight: 600 } }
            },
            scales: {
                y: { beginAtZero: true, ticks: { color: '#94a3b8', font: { family: 'Inter' } }, grid: { color: '#1e293b' } },
                x: { ticks: { color: '#94a3b8', font: { family: 'Inter' } }, grid: { display: false } }
            }
        }
    });
}

function updateCharts(stats) {
    if (!severityChartInstance || !statusChartInstance) return;

    // We don't have per-severity counts from stats endpoint, so approximate
    // Using total incidents and high severity count
    const high = stats.high_severity || 0;
    const total = stats.total_incidents || 0;
    const other = Math.max(0, total - high);

    severityChartInstance.data.datasets[0].data = [high, Math.floor(other / 2), Math.ceil(other / 2)];
    severityChartInstance.update();

    statusChartInstance.data.datasets[0].data = [
        stats.open_incidents || 0,
        stats.investigating_incidents || 0,
        stats.closed_incidents || 0,
    ];
    statusChartInstance.update();
}

// ============================================
// Utilities
// ============================================
function formatTime(isoString) {
    if (!isoString) return '—';
    try {
        const date = new Date(isoString);
        return date.toLocaleString('en-IN', {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        });
    } catch (e) {
        return isoString;
    }
}

function escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
