/**
 * AegisScan Dashboard JavaScript Application
 *
 * Handles:
 * - Data fetching and API communication
 * - Dashboard statistics updates
 * - Form submission and validation
 * - Real-time data refresh
 * - User notifications
 * - Report and scan management
 */

// ====================================================================
// Configuration and Constants
// ====================================================================

const API_CONFIG = {
    BASE_URL: '/api',
    TIMEOUT: 10000,
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 1000,
};

const REFRESH_CONFIG = {
    STATS_INTERVAL: 30000,      // 30 seconds
    ACTIVE_SCANS_INTERVAL: 10000, // 10 seconds
    AUTO_REFRESH_ENABLED: true,
};

const CACHE = {
    stats: null,
    hosts: null,
    scans: null,
    findings: null,
    lastUpdate: {},
};

// ====================================================================
// API Communication
// ====================================================================

/**
 * Make an API request with retry logic and timeout handling.
 *
 * @param {string} endpoint - API endpoint path
 * @param {Object} options - Fetch options
 * @returns {Promise<any>} - Parsed response data
 * @throws {Error} - On failure after retries
 */
async function apiRequest(endpoint, options = {}) {
    const url = `${API_CONFIG.BASE_URL}${endpoint}`;
    let lastError;

    for (let attempt = 0; attempt < API_CONFIG.RETRY_ATTEMPTS; attempt++) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT);

            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                },
                ...options,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            // Return response based on content type
            const contentType = response.headers.get('content-type');
            if (contentType?.includes('application/json')) {
                return await response.json();
            } else if (contentType?.includes('text/html')) {
                return await response.text();
            } else if (contentType?.includes('application/octet-stream')) {
                return await response.blob();
            }

            return response;
        } catch (error) {
            lastError = error;

            if (attempt < API_CONFIG.RETRY_ATTEMPTS - 1) {
                // Wait before retrying with exponential backoff
                await sleep(API_CONFIG.RETRY_DELAY * Math.pow(2, attempt));
            }
        }
    }

    throw new Error(`API request failed: ${lastError?.message || 'Unknown error'}`);
}

/**
 * Sleep for a specified duration.
 *
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise<void>}
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Format a date string to human-readable format.
 *
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    if (date.toDateString() === today.toDateString()) {
        return 'Today ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (date.toDateString() === yesterday.toDateString()) {
        return 'Yesterday ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Format bytes to human-readable format.
 *
 * @param {number} bytes - Number of bytes
 * @returns {string} - Formatted size
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Escape HTML special characters.
 *
 * @param {string} text - Text to escape
 * @returns {string} - Escaped text
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

// ====================================================================
// Notification System
// ====================================================================

/**
 * Show a notification message to the user.
 *
 * @param {string} message - Notification message
 * @param {string} type - Type: success, error, warning, info
 * @param {number} duration - Duration in milliseconds
 */
function showNotification(message, type = 'success', duration = 4000) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.setAttribute('role', 'alert');
    notification.setAttribute('aria-live', 'polite');

    document.body.appendChild(notification);

    // Animation
    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease';
    }, 0);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, duration);
}

// ====================================================================
// Data Fetching and Caching
// ====================================================================

/**
 * Fetch and update dashboard statistics.
 *
 * @returns {Promise<void>}
 */
async function fetchStats() {
    try {
        const stats = await apiRequest('/stats');

        // Update UI
        updateElement('totalHosts', stats.total_hosts);
        updateElement('openPorts', stats.total_open_ports);
        updateElement('criticalFindings', stats.critical_findings);
        updateElement('scanRuns', stats.total_scan_runs);

        // Update cache
        CACHE.stats = stats;
        CACHE.lastUpdate.stats = Date.now();

        console.debug('Stats updated:', stats);
    } catch (error) {
        console.error('Failed to fetch statistics:', error);
    }
}

/**
 * Fetch scan runs from the API.
 *
 * @param {Object} params - Query parameters
 * @returns {Promise<Array>} - List of scan runs
 */
async function fetchScans(params = {}) {
    try {
        const queryString = new URLSearchParams(params).toString();
        const endpoint = `/scan-runs${queryString ? '?' + queryString : ''}`;
        const scans = await apiRequest(endpoint);

        CACHE.scans = scans;
        CACHE.lastUpdate.scans = Date.now();

        return scans;
    } catch (error) {
        console.error('Failed to fetch scans:', error);
        return CACHE.scans || [];
    }
}

/**
 * Fetch hosts from the API.
 *
 * @param {Object} params - Query parameters
 * @returns {Promise<Array>} - List of hosts
 */
async function fetchHosts(params = {}) {
    try {
        const queryString = new URLSearchParams(params).toString();
        const endpoint = `/hosts${queryString ? '?' + queryString : ''}`;
        const hosts = await apiRequest(endpoint);

        CACHE.hosts = hosts;
        CACHE.lastUpdate.hosts = Date.now();

        return hosts;
    } catch (error) {
        console.error('Failed to fetch hosts:', error);
        return CACHE.hosts || [];
    }
}

/**
 * Fetch findings from the API.
 *
 * @param {Object} params - Query parameters
 * @returns {Promise<Array>} - List of findings
 */
async function fetchFindings(params = {}) {
    try {
        const queryString = new URLSearchParams(params).toString();
        const endpoint = `/findings${queryString ? '?' + queryString : ''}`;
        const findings = await apiRequest(endpoint);

        CACHE.findings = findings;
        CACHE.lastUpdate.findings = Date.now();

        return findings;
    } catch (error) {
        console.error('Failed to fetch findings:', error);
        return CACHE.findings || [];
    }
}

// ====================================================================
// UI Manipulation Helpers
// ====================================================================

/**
 * Update text content of an element.
 *
 * @param {string} elementId - Element ID
 * @param {any} content - Content to set
 */
function updateElement(elementId, content) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = content;
    }
}

/**
 * Show a loading spinner in an element.
 *
 * @param {HTMLElement} element - Target element
 */
function showLoading(element) {
    element.innerHTML = '<div class="loading"></div>';
}

/**
 * Show an empty state message.
 *
 * @param {HTMLElement} element - Target element
 * @param {string} message - Empty state message
 * @param {string} icon - Icon character
 */
function showEmptyState(element, message, icon = '○') {
    element.innerHTML = `
        <div class="empty-state">
            <div class="empty-state-icon">${icon}</div>
            <div>${escapeHtml(message)}</div>
        </div>
    `;
}

// ====================================================================
// Form Handling
// ====================================================================

/**
 * Handle scan form submission.
 *
 * @param {Event} event - Form submission event
 */
async function handleStartScan(event) {
    event.preventDefault();

    const formData = {
        name: document.getElementById('scanName').value.trim(),
        targets: document.getElementById('targets').value.trim(),
        port_range: document.getElementById('portRange').value.trim(),
        scan_type: document.getElementById('scanType').value,
        intensity: parseInt(document.getElementById('intensity').value),
    };

    // Validation
    if (!formData.name || !formData.targets) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }

    try {
        const result = await apiRequest('/scan', {
            method: 'POST',
            body: JSON.stringify(formData),
        });

        showNotification(`Scan "${result.name}" started successfully!`, 'success');
        document.getElementById('scanForm').reset();

        // Refresh data
        await fetchScans();
        await fetchStats();
    } catch (error) {
        showNotification(`Failed to start scan: ${error.message}`, 'error');
    }
}

/**
 * Handle Nmap XML file import.
 *
 * @param {Event} event - File input change event
 */
async function handleNmapImport(event) {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.name.endsWith('.xml')) {
        showNotification('File must be XML format', 'error');
        return;
    }

    const statusDiv = document.getElementById('importStatus');
    statusDiv.textContent = 'Uploading...';

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(`${API_CONFIG.BASE_URL}/import/nmap`, {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) throw new Error('Import failed');

        const result = await response.json();
        statusDiv.textContent = `Successfully imported: ${result.hosts_imported} hosts, ${result.ports_discovered} ports`;
        showNotification('Nmap import completed!', 'success');

        // Refresh data
        await fetchHosts();
        await fetchStats();
    } catch (error) {
        statusDiv.textContent = 'Import failed. Check file format.';
        showNotification(`Import failed: ${error.message}`, 'error');
    }
}

/**
 * Handle report generation.
 */
async function handleGenerateReport() {
    const scanId = document.getElementById('reportScanId').value;

    if (!scanId) {
        showNotification('Please select a scan', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_CONFIG.BASE_URL}/reports/${scanId}/html`);
        if (!response.ok) throw new Error('Report generation failed');

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `aegisscan-report-${scanId}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        showNotification('Report generated and downloaded!', 'success');
    } catch (error) {
        showNotification(`Report generation failed: ${error.message}`, 'error');
    }
}

/**
 * Handle scan comparison.
 *
 * @param {string} comparisonType - Type of comparison
 */
async function handleCompare(comparisonType) {
    const scanId = document.getElementById('comparisonScanId').value;

    if (!scanId) {
        showNotification('Please select a scan', 'error');
        return;
    }

    try {
        let endpoint = '';
        let title = '';

        if (comparisonType === 'connect-vs-syn') {
            endpoint = `/diff/connect-vs-syn/${scanId}`;
            title = 'Connect vs SYN Comparison';
        } else if (comparisonType === 'internal-vs-external') {
            endpoint = `/diff/internal-vs-external/${scanId}`;
            title = 'Internal vs External Comparison';
        }

        const result = await apiRequest(endpoint);
        displayComparisonResults(title, comparisonType, result);
        showNotification('Comparison completed', 'success');
    } catch (error) {
        showNotification(`Comparison failed: ${error.message}`, 'error');
    }
}

/**
 * Display comparison results.
 *
 * @param {string} title - Results title
 * @param {string} type - Comparison type
 * @param {Object} data - Result data
 */
function displayComparisonResults(title, type, data) {
    let html = `<h3 style="color: #00d4ff; margin-bottom: 16px;">${escapeHtml(title)}</h3>`;

    if (type === 'connect-vs-syn') {
        html += `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h4 style="color: #a0a0b0; margin-bottom: 8px;">Connect Ports (${data.connect_ports.length})</h4>
                    <p>${data.connect_ports.join(', ') || 'None'}</p>
                </div>
                <div>
                    <h4 style="color: #a0a0b0; margin-bottom: 8px;">SYN Ports (${data.syn_ports.length})</h4>
                    <p>${data.syn_ports.join(', ') || 'None'}</p>
                </div>
            </div>
            <div style="margin-top: 16px;">
                <h4 style="color: #a0a0b0; margin-bottom: 8px;">Discrepancies</h4>
                <p><strong>${data.discrepancies}</strong> port(s) detected differently</p>
            </div>
        `;
    } else if (type === 'internal-vs-external') {
        html += `
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px;">
                <div>
                    <h4 style="color: #ff9800; margin-bottom: 8px;">Internal Only (${data.internal_only.length})</h4>
                    ${data.internal_only.map(item => `<p style="font-size: 12px;">${item.host}:${item.port}</p>`).join('') || '<p>None</p>'}
                </div>
                <div>
                    <h4 style="color: #f44336; margin-bottom: 8px;">External Only (${data.external_only.length})</h4>
                    ${data.external_only.map(item => `<p style="font-size: 12px;">${item.host}:${item.port}</p>`).join('') || '<p>None</p>'}
                </div>
                <div>
                    <h4 style="color: #4caf50; margin-bottom: 8px;">Both (${data.both.length})</h4>
                    ${data.both.map(item => `<p style="font-size: 12px;">${item.host}:${item.port}</p>`).join('') || '<p>None</p>'}
                </div>
            </div>
        `;
    }

    document.getElementById('comparisonResults').innerHTML = html;
}

// ====================================================================
// Search and Filtering
// ====================================================================

/**
 * Handle host search.
 *
 * @param {Event} event - Input change event
 */
function handleHostSearch(event) {
    const query = event.target.value.toLowerCase();
    const rows = document.getElementById('hostsBody')?.querySelectorAll('tr') || [];

    rows.forEach(row => {
        if (row.querySelector('.empty-state')) return;
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    });
}

/**
 * Handle host filtering.
 */
function handleHostFilter() {
    const tag = document.getElementById('hostTagFilter').value;
    const rows = document.getElementById('hostsBody')?.querySelectorAll('tr') || [];

    rows.forEach(row => {
        if (row.querySelector('.empty-state')) return;
        const text = row.textContent.toLowerCase();
        row.style.display = !tag || text.includes(tag) ? '' : 'none';
    });
}

/**
 * Filter findings by severity.
 *
 * @param {string} severity - Severity level to filter
 */
function filterFindings(severity) {
    const rows = document.getElementById('findingsBody')?.querySelectorAll('tr') || [];

    rows.forEach(row => {
        if (row.querySelector('.empty-state')) return;
        const text = row.textContent.toLowerCase();
        row.style.display = !severity || text.includes(severity) ? '' : 'none';
    });
}

// ====================================================================
// Tab Management
// ====================================================================

/**
 * Switch to a different tab.
 *
 * @param {string} tabName - Tab name/ID to switch to
 */
function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from all buttons
    document.querySelectorAll('.tab').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    const selectedTab = document.getElementById(tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Add active class to clicked button
    if (event?.target) {
        event.target.classList.add('active');
    }
}

// ====================================================================
// Dropdown Population
// ====================================================================

/**
 * Populate report scan dropdown.
 *
 * @returns {Promise<void>}
 */
async function populateReportScans() {
    try {
        const scans = await fetchScans({ limit: 50 });
        const select = document.getElementById('reportScanId');

        select.innerHTML = '<option value="">Choose a scan...</option>' +
            scans.map(scan => `<option value="${scan.id}">${escapeHtml(scan.name)}</option>`).join('');
    } catch (error) {
        console.error('Failed to populate report scans:', error);
    }
}

/**
 * Populate comparison scan dropdown.
 *
 * @returns {Promise<void>}
 */
async function populateComparisonScans() {
    try {
        const scans = await fetchScans({ limit: 50 });
        const select = document.getElementById('comparisonScanId');

        select.innerHTML = '<option value="">Choose a scan...</option>' +
            scans.map(scan => `<option value="${scan.id}">${escapeHtml(scan.name)}</option>`).join('');
    } catch (error) {
        console.error('Failed to populate comparison scans:', error);
    }
}

// ====================================================================
// Initialization
// ====================================================================

/**
 * Initialize the dashboard on page load.
 *
 * @returns {Promise<void>}
 */
async function initializeDashboard() {
    console.log('Initializing AegisScan dashboard...');

    // Load initial data
    await fetchStats();
    await fetchScans();

    // Setup auto-refresh intervals
    if (REFRESH_CONFIG.AUTO_REFRESH_ENABLED) {
        // Refresh stats every 30 seconds
        setInterval(fetchStats, REFRESH_CONFIG.STATS_INTERVAL);

        // Refresh active scans every 10 seconds
        setInterval(async () => {
            const activeTab = document.querySelector('.tab-content.active');
            if (activeTab?.id === 'scans') {
                await fetchScans();
            }
        }, REFRESH_CONFIG.ACTIVE_SCANS_INTERVAL);
    }

    console.log('Dashboard initialized');
}

// Initialize when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDashboard);
} else {
    initializeDashboard();
}
