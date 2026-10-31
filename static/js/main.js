/* MailGuard - Main JavaScript File */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize scanner functionality
    initScanner();
    initLandingPage();
});

const HISTORY_PAGE_SIZE = 10;
let scanHistory = [];
let historyPage = 1;
let historyTotal = 0;

/**
 * Initialize scanner functionality
 */
function initScanner() {
    // Toggle scanning methods
    const methodPaste = document.getElementById('method-paste');
    const methodUpload = document.getElementById('method-upload');
    const methodGmail = document.getElementById('method-gmail');
    
    // Set initial active method
    if (methodPaste) methodPaste.classList.add('active');
    
    // Method click handlers
    if (methodPaste) {
        methodPaste.addEventListener('click', function() {
            showMethod('paste');
        });
    }
    
    if (methodUpload) {
        methodUpload.addEventListener('click', function() {
            showMethod('upload');
        });
    }
    
    if (methodGmail) {
        methodGmail.addEventListener('click', function() {
            showMethod('gmail');
        });
    }
    
    // Initialize Gmail connection status
    initGmailStatus();

    document.getElementById('historySearch')?.addEventListener('input', function() {
        historyPage = 1;
        renderScanHistory();
    });
    document.getElementById('historyRiskFilter')?.addEventListener('change', function() {
        historyPage = 1;
        renderScanHistory();
    });

    loadScanHistory();
    loadScannerAnalytics();

    if (new URLSearchParams(window.location.search).get('demo') === '1') {
        document.getElementById('senderEmail').value = 'security@example.test';
        document.getElementById('emailSubject').value = 'Urgent: verify your account';
        document.getElementById('emailBody').value = 'A sample message for trying MailGuard. Click here to verify: http://192.0.2.1/account';
        document.getElementById('emailBody').focus();
    }
}

async function initLandingPage() {
    const status = document.getElementById('engine-status');
    const total = document.getElementById('site-stats-emails');
    if (!status || !total) return;

    try {
        const response = await fetch('/api/analytics');
        const data = await response.json();
        if (!response.ok || !data.success || !data.analytics) {
            throw new Error(data.error || 'Scan statistics are unavailable');
        }

        const analytics = data.analytics;
        const values = [
            ['site-stats-emails', analytics.total_scanned],
            ['site-stats-phishing', analytics.potential_phishing],
            ['site-stats-low', analytics.low_risk],
            ['site-stats-high', analytics.high_risk]
        ];

        values.forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) animateStatValue(element, Number(value) || 0);
        });

        status.classList.add('engine-status-ready');
        status.innerHTML = '<span class="status-pulse"></span> SCAN ENGINE ONLINE';
        document.getElementById('stats-updated').textContent =
            `Live totals from this MailGuard instance · Updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
        status.classList.add('engine-status-error');
        status.innerHTML = '<span class="status-pulse"></span> SCAN ENGINE UNAVAILABLE';
        document.getElementById('stats-updated').textContent = 'Could not load scan statistics. Please refresh to try again.';
        console.error('Error loading landing page statistics:', error);
    }
}

function animateStatValue(element, target) {
    const duration = 700;
    const startTime = performance.now();

    function update(now) {
        const progress = Math.min((now - startTime) / duration, 1);
        element.textContent = Math.round(target * progress).toLocaleString();
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

async function loadScanHistory() {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    try {
        const response = await fetch('/api/history?limit=1000');
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || 'Could not load scan history');
        }

        scanHistory = data.history || [];
        historyTotal = data.total_count ?? scanHistory.length;
        renderScanHistory();
    } catch (error) {
        historyList.innerHTML = '<div class="history-empty">Unable to load scan history. Try refreshing.</div>';
        const count = document.getElementById('historyCount');
        if (count) count.textContent = 'History could not be loaded';
        console.error('Error loading scan history:', error);
    }
}

function getFilteredScanHistory() {
    const query = document.getElementById('historySearch')?.value.trim().toLowerCase() || '';
    const risk = document.getElementById('historyRiskFilter')?.value || '';

    return scanHistory.filter(scan => {
        const matchesQuery = !query || [scan.sender_email, scan.email_subject]
            .some(value => String(value || '').toLowerCase().includes(query));
        const matchesRisk = !risk || scan.risk_level === risk;
        return matchesQuery && matchesRisk;
    });
}

function escapeHistoryText(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);
}

function renderScanHistory() {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    const filtered = getFilteredScanHistory();
    const pageCount = Math.max(1, Math.ceil(filtered.length / HISTORY_PAGE_SIZE));
    historyPage = Math.min(historyPage, pageCount);
    const start = (historyPage - 1) * HISTORY_PAGE_SIZE;
    const pageRows = filtered.slice(start, start + HISTORY_PAGE_SIZE);
    const count = document.getElementById('historyCount');
    const pageInfo = document.getElementById('historyPageInfo');
    const previous = document.getElementById('historyPrev');
    const next = document.getElementById('historyNext');

    if (count) {
        const showing = scanHistory.length < historyTotal
            ? `Showing latest ${scanHistory.length} of ${historyTotal} scans`
            : `${historyTotal} scan${historyTotal === 1 ? '' : 's'} available`;
        count.textContent = `${filtered.length} match${filtered.length === 1 ? '' : 'es'} · ${showing}`;
    }

    if (filtered.length === 0) {
        historyList.innerHTML = `<div class="history-empty">${scanHistory.length ? 'No scans match your search.' : 'No scans yet. Scan an email to get started.'}</div>`;
    } else {
        const rows = pageRows.map(scan => {
            const level = String(scan.risk_level || 'Low Risk');
            const riskClass = {
                'Low Risk': 'low',
                'Moderate Risk': 'moderate',
                'High Risk': 'high',
                'Critical Risk': 'critical'
            }[level] || 'low';
            const date = scan.detected_at ? new Date(scan.detected_at.replace(' ', 'T')).toLocaleString() : '—';

            return `<tr>
                <td class="history-date">${escapeHistoryText(date)}</td>
                <td><span class="history-sender">${escapeHistoryText(scan.sender_email || 'Unknown sender')}</span>
                    <span class="history-subject">${escapeHistoryText(scan.email_subject || 'No subject')}</span></td>
                <td><span class="history-risk history-risk-${riskClass}">${escapeHistoryText(level)}</span></td>
                <td class="history-score">${escapeHistoryText(scan.risk_score ?? 0)}<span>/100</span></td>
                <td><a class="history-view" href="/results?id=${encodeURIComponent(scan.id)}" aria-label="View scan ${escapeHistoryText(scan.id)}">View</a></td>
            </tr>`;
        }).join('');

        historyList.innerHTML = `<table class="history-table">
            <thead><tr><th scope="col">Scanned</th><th scope="col">Email</th><th scope="col">Risk</th><th scope="col">Score</th><th scope="col"></th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    if (pageInfo) {
        pageInfo.textContent = filtered.length ? `Page ${historyPage} of ${pageCount}` : '';
    }
    if (previous) previous.disabled = historyPage <= 1;
    if (next) next.disabled = historyPage >= pageCount;
}

function changeHistoryPage(direction) {
    historyPage += direction;
    renderScanHistory();
}

function exportScanHistory() {
    const filtered = getFilteredScanHistory();
    if (filtered.length === 0) {
        showToast('There are no scans to export', 'warning');
        return;
    }

    const fields = [
        ['Scan ID', 'id'],
        ['Sender', 'sender_email'],
        ['Subject', 'email_subject'],
        ['Risk level', 'risk_level'],
        ['Risk score', 'risk_score'],
        ['Classification', 'classification'],
        ['Scanned at', 'detected_at']
    ];
    const escapeCsv = value => {
        let text = String(value ?? '');
        if (/^[\s]*[=+\-@]/.test(text)) text = `'${text}`;
        return `"${text.replace(/"/g, '""')}"`;
    };
    const csv = [
        fields.map(([label]) => escapeCsv(label)).join(','),
        ...filtered.map(scan => fields.map(([, key]) => escapeCsv(scan[key])).join(','))
    ].join('\r\n');
    const blob = new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `mailguard-scan-history-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast(`Exported ${filtered.length} scan${filtered.length === 1 ? '' : 's'}`, 'success');
}

async function loadScannerAnalytics() {
    try {
        const response = await fetch('/api/analytics');
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || 'Could not load scan statistics');
        }

        const analytics = data.analytics;
        const total = analytics.total_scanned || 0;
        const phishing = analytics.potential_phishing || 0;
        const low = analytics.low_risk || 0;
        const high = analytics.high_risk || 0;
        const values = [
            ['analytics-total', 'analytics-total-bar', total],
            ['analytics-phishing', 'analytics-phishing-bar', phishing],
            ['analytics-low', 'analytics-low-bar', low],
            ['analytics-high', 'analytics-high-bar', high]
        ];

        values.forEach(([valueId, barId, value]) => {
            const valueElement = document.getElementById(valueId);
            const bar = document.getElementById(barId);
            if (valueElement) valueElement.textContent = value;
            if (bar) {
                bar.style.width = `${total ? Math.round((value / total) * 100) : 0}%`;
                bar.setAttribute('aria-valuenow', String(total ? Math.round((value / total) * 100) : 0));
            }
        });
    } catch (error) {
        console.error('Error loading scan statistics:', error);
    }
}

function clearScannerForm() {
    document.getElementById('senderEmail').value = '';
    document.getElementById('emailSubject').value = '';
    document.getElementById('emailBody').value = '';
    document.getElementById('emlFile').value = '';
    document.getElementById('uploadStatus').textContent = '';
    clearResults();
    showToast('Scanner form cleared', 'info');
}

/**
 * Show the specified scanning method
 * @param {string} method - 'paste', 'upload', or 'gmail'
 */
function showMethod(method) {
    // Hide all method cards
    const methods = ['method-paste', 'method-upload', 'method-gmail'];
    methods.forEach(m => {
        const card = document.getElementById(m);
        if (card) {
            card.classList.remove('active');
            card.style.borderColor = 'var(--border-color)';
        }
    });
    
    // Show selected method
    const selected = document.getElementById(`method-${method}`);
    if (selected) {
        selected.classList.add('active');
        selected.style.borderColor = 'var(--accent-electric)';
    }
    
    // Hide all result areas
    const resultAreas = ['scanningOverlay', 'resultsArea', 'historyList', 'analytics'];
    resultAreas.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });
    
    // Show appropriate form based on method
    const forms = ['pasteForm', 'uploadForm', 'gmailForm'];
    forms.forEach(f => {
        const el = document.getElementById(f);
        if (el) el.style.display = 'none';
    });
    
    const form = document.getElementById(`form-${method}`);
    if (form) {
        form.style.display = 'block';
    }
    
    // Clear previous results
    clearResults();
}

/**
 * Initialize Gmail connection status
 */
function initGmailStatus() {
    const gmailConnectBtn = document.getElementById('gmailConnectBtn');
    const gmailStatus = document.getElementById('gmailStatus');
    
    if (!gmailConnectBtn || !gmailStatus) return;
    
    // Check if user is already connected (via session)
    // In a real implementation, this would check the backend
    const isConnected = false; // Placeholder
    
    if (isConnected) {
        gmailStatus.classList.remove('disconnected');
        gmailStatus.classList.add('connected');
        gmailStatus.querySelector('small').textContent = 'Connected';
        gmailConnectBtn.textContent = 'Connected';
        gmailConnectBtn.style.background = 'var(--risk-low)';
    } else {
        gmailStatus.classList.remove('connected');
        gmailStatus.classList.add('disconnected');
        gmailStatus.querySelector('small').textContent = 'Not connected';
        gmailConnectBtn.textContent = 'Connect Account';
        gmailConnectBtn.style.background = 'linear-gradient(135deg, var(--accent-electric), var(--accent-purple))';
    }
}

/**
 * Scan email by pasting content
 */
async function scanPasteEmail() {
    const sender = document.getElementById('senderEmail').value.trim();
    const subject = document.getElementById('emailSubject').value.trim();
    const body = document.getElementById('emailBody').value.trim();
    
    if (!sender && !subject && !body) {
        showToast('Please enter email content to scan', 'warning');
        return;
    }
    
    // Show loading state
    showScanningOverlay();
    
    // Send to backend
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                method: 'paste',
                sender: sender,
                subject: subject,
                body: body
            })
        });
        
        const result = await response.json();
        hideScanningOverlay();
        
        if (result.success) {
            displayPasteResults(result);
            loadScanHistory();
            loadScannerAnalytics();
        } else {
            showToast(result.error || 'Scan failed', 'error');
        }
    } catch (error) {
        hideScanningOverlay();
        showToast('Error communicating with server', 'error');
        console.error('Scan error:', error);
    }
}

/**
 * Scan uploaded email file
 */
async function scanUploadEmail() {
    const fileInput = document.getElementById('emlFile');
    const uploadStatus = document.getElementById('uploadStatus');
    
    if (!fileInput.files || fileInput.files.length === 0) {
        showToast('Please select an .eml file to upload', 'warning');
        return;
    }
    
    const file = fileInput.files[0];
    
    // Validate file type
    if (!file.name.toLowerCase().endsWith('.eml')) {
        showToast('Please upload a valid .eml file', 'error');
        return;
    }
    
    // Validate file size (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
        showToast('File size exceeds 10MB limit', 'error');
        return;
    }
    
    // Show loading state
    showScanningOverlay();
    
    // Read file as text
    const reader = new FileReader();
    
    reader.onload = async function(e) {
        const content = e.target.result;
        
        // Extract basic info from .eml file
        const parsed = parseEmlFile(content);
        
        // Send to backend
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    method: 'upload',
                    filename: file.name,
                    content: content
                })
            });
            
            const result = await response.json();
            hideScanningOverlay();
            
            if (result.success) {
                displayUploadResults(result, parsed);
                loadScanHistory();
                loadScannerAnalytics();
            } else {
                hideScanningOverlay();
                showToast(result.error || 'Scan failed', 'error');
            }
        } catch (error) {
            hideScanningOverlay();
            showToast('Error communicating with server', 'error');
            console.error('Upload scan error:', error);
        }
    };
    
    reader.readAsText(file);
}

/**
 * Parse .eml file to extract sender, subject, and body
 * @param {string} content - Raw .eml file content
 * @returns {object} - Parsed email data
 */
function parseEmlFile(content) {
    const result = {
        sender: '',
        subject: '',
        body: ''
    };
    
    if (!content) return result;
    
    // Split headers and body
    const parts = content.split(/\r?\n\r?\n/);
    const headers = parts[0] || '';
    const body = parts.slice(1).join('\n\n') || '';
    
    // Parse headers
    const headerLines = headers.split('\n');
    for (const line of headerLines) {
        if (line.toLowerCase().startsWith('from:')) {
            result.sender = line.substring(5).trim();
        } else if (line.toLowerCase().startsWith('subject:')) {
            result.subject = line.substring(8).trim();
        }
    }
    
    // Body is the last part
    result.body = body;
    
    return result;
}

/**
 * Display uploaded email scan results
 * @param {object} result - Scan result from backend
 * @param {object} parsed - Parsed email data
 */
function displayUploadResults(result, parsed) {
    const riskScore = result.risk_score;
    const riskLevel = result.risk_level;
    const classification = result.classification;
    const indicators = result.indicators || [];
    
    // Update UI
    document.getElementById('riskDisplay').innerHTML = `
        <div class="risk-score-value ${getRiskClass(riskLevel)}">
            ${riskScore}<span>/100</span>
        </div>
    `;
    
    document.getElementById('riskLabel').textContent = riskLevel;
    document.getElementById('classificationBadge').textContent = classification;
    document.getElementById('classificationBadge').style.background = getRiskBackground(riskLevel);
    
    // Show indicators
    const indicatorsContent = document.getElementById('indicatorsList');
    if (indicators.length > 0) {
        let html = '';
        indicators.forEach(ind => {
            const typeClass = ind.risk?.toLowerCase() === 'high' ? 'high' : 
                             ind.risk?.toLowerCase() === 'medium' ? 'medium' : 'low';
            html += `
                <span class="indicator-badge ${typeClass}" style="background: rgba(${getRiskColor(riskLevel)}, 0.2); color: ${getRiskColor(riskLevel)};">
                    ${ind.type.replace(/_/g, ' ')}
                </span>
            `;
        });
        indicatorsContent.innerHTML = html;
    } else {
        indicatorsContent.innerHTML = '<p class="small text-secondary">No significant phishing indicators detected</p>';
    }
    
    // Show URLs
    const urlsContent = document.getElementById('urlsContent');
    if (result.analysis && result.analysis.link_analysis && result.analysis.link_analysis.length > 0) {
        urlsContent.innerHTML = '';
        result.analysis.link_analysis.forEach(link => {
            urlsContent.innerHTML += `<code class="url-item">${link.description || 'Suspicious link'}</code>`;
        });
    } else {
        urlsContent.innerHTML = '<p class="small text-secondary">No suspicious URLs found</p>';
    }
    
    // Show authentication
    const authContent = document.getElementById('authContent');
    const auth = result.authentication || {};
    let authHtml = '';
    
    if (auth.spf) {
        authHtml += `<div class="auth-method ${auth.spf.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>SPF: ${auth.spf.description || 'N/A'}</span>
            <span>${auth.spf.risk || 'N/A'}</span>
        </div>`;
    }
    if (auth.dkim) {
        authHtml += `<div class="auth-method ${auth.dkim.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>DKIM: ${auth.dkim.description || 'N/A'}</span>
            <span>${auth.dkim.risk || 'N/A'}</span>
        </div>`;
    }
    if (auth.dmarc) {
        authHtml += `<div class="auth-method ${auth.dmarc.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>DMARC: ${auth.dmarc.description || 'N/A'}</span>
            <span>${auth.dmarc.risk || 'N/A'}</span>
        </div>`;
    }
    
    if (!authHtml) {
        authHtml = '<p class="small text-secondary">No authentication data available</p>';
    }
    authContent.innerHTML = authHtml;
    
    // Show sender info
    document.getElementById('senderEmailField').textContent = parsed.sender || result.sender || 'Unknown';
    document.getElementById('domainField').textContent = result.sender ? result.sender.split('@')[1] || 'Unknown' : 'Unknown';
    
    // Show recommendations
    const recContent = document.getElementById('recommendationsContent');
    const riskLevelLower = riskLevel.toLowerCase();
    
    let recommendations = [];
    if (riskLevelLower.includes('critical') || riskLevelLower.includes('high')) {
        recommendations = [
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Do not click any links in this email',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Do not download or open attachments',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Report this email as phishing to your email provider',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Change passwords if you clicked any links or entered credentials',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Enable two-factor authentication on your accounts'
        ];
    } else if (riskLevelLower === 'moderate') {
        recommendations = [
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Be cautious with any links or attachments',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Verify sender identity through official channels',
            '<i class="fas fa-info-circle recommendation-icon"></i> Review the email carefully for signs of phishing'
        ];
    } else {
        recommendations = [
            '<i class="fas fa-check-circle recommendation-icon"></i> Email appears safe but remain vigilant',
            '<i class="fas fa-info-circle recommendation-icon"></i> Report any suspicious emails to your IT department'
        ];
    }
    
    recContent.innerHTML = recommendations.join('<br>');
    
    // Show the results area
    document.getElementById('resultCard').style.display = 'block';
    document.getElementById('resultsArea').style.display = 'block';
}

/**
 * Analyze Gmail email
 * @param {string} emailId - Gmail message ID
 */
async function scanGmailEmail(emailId) {
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                method: 'gmail',
                email_id: emailId
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayGmailResults(result);
            loadScanHistory();
            loadScannerAnalytics();
        } else {
            showToast(result.error || 'Scan failed', 'error');
        }
    } catch (error) {
        showToast('Error communicating with server', 'error');
        console.error('Gmail scan error:', error);
    }
}

/**
 * Display Gmail scan results
 * @param {object} result - Scan result from backend
 */
function displayGmailResults(result) {
    const riskScore = result.risk_score;
    const riskLevel = result.risk_level;
    const classification = result.classification;
    const indicators = result.indicators || [];
    
    // Update risk display
    document.getElementById('riskDisplay').innerHTML = `
        <div class="risk-score-value ${getRiskClass(riskLevel)}">
            ${riskScore}<span>/100</span>
        </div>
    `;
    
    document.getElementById('riskLabel').textContent = riskLevel;
    document.getElementById('classificationBadge').textContent = classification;
    document.getElementById('classificationBadge').style.background = getRiskBackground(riskLevel);
    
    // Show indicators
    const indicatorsContent = document.getElementById('indicatorsList');
    if (indicators.length > 0) {
        let html = '';
        indicators.forEach(ind => {
            const typeClass = ind.risk?.toLowerCase() === 'high' ? 'high' : 
                             ind.risk?.toLowerCase() === 'medium' ? 'medium' : 'low';
            html += `
                <span class="indicator-badge ${typeClass}" style="background: rgba(${getRiskColor(riskLevel)}, 0.2); color: ${getRiskColor(riskLevel)};">
                    ${ind.type.replace(/_/g, ' ')}
                </span>
            `;
        });
        indicatorsContent.innerHTML = html;
    } else {
        indicatorsContent.innerHTML = '<p class="small text-secondary">No significant phishing indicators detected</p>';
    }
    
    // Show URLs
    const urlsContent = document.getElementById('urlsContent');
    if (result.analysis && result.analysis.link_analysis && result.analysis.link_analysis.length > 0) {
        urlsContent.innerHTML = '';
        result.analysis.link_analysis.forEach(link => {
            urlsContent.innerHTML += `<code class="url-item">${link.url || link.description || 'Suspicious link'}</code>`;
        });
    } else {
        urlsContent.innerHTML = '<p class="small text-secondary">No suspicious URLs found</p>';
    }
    
    // Show authentication
    const authContent = document.getElementById('authContent');
    const auth = result.authentication || {};
    let authHtml = '';
    
    if (auth.spf) {
        authHtml += `<div class="auth-method ${auth.spf.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>SPF: ${auth.spf.description || 'N/A'}</span>
            <span>${auth.spf.risk || 'N/A'}</span>
        </div>`;
    }
    if (auth.dkim) {
        authHtml += `<div class="auth-method ${auth.dkim.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>DKIM: ${auth.dkim.description || 'N/A'}</span>
            <span>${auth.dkim.risk || 'N/A'}</span>
        </div>`;
    }
    if (auth.dmarc) {
        authHtml += `<div class="auth-method ${auth.dmarc.risk?.toLowerCode() === 'high' ? 'fail' : 'pass'}">
            <span>DMARC: ${auth.dmarc.description || 'N/A'}</span>
            <span>${auth.dmarc.risk || 'N/A'}</span>
        </div>`;
    }
    
    if (!authHtml) {
        authHtml = '<p class="small text-secondary">No authentication data available</p>';
    }
    authContent.innerHTML = authHtml;
    
    // Show sender info
    document.getElementById('senderEmailField').textContent = result.sender || 'Unknown';
    document.getElementById('domainField').textContent = result.sender ? result.sender.split('@')[1] || 'Unknown' : 'Unknown';
    
    // Show recommendations
    const recContent = document.getElementById('recommendationsContent');
    const riskLevelLower = riskLevel.toLowerCase();
    
    let recommendations = [];
    if (riskLevelLower.includes('critical') || riskLevelLower.includes('high')) {
        recommendations = [
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Do not click any links in this email',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Do not download or open attachments',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Report this email as phishing to your email provider',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Change passwords if you clicked any links or entered credentials',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Enable two-factor authentication on your accounts'
        ];
    } else if (riskLevelLower === 'moderate') {
        recommendations = [
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Be cautious with any links or attachments',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Verify sender identity through official channels',
            '<i class="fas fa-info-circle recommendation-icon"></i> Review the email carefully for signs of phishing'
        ];
    } else {
        recommendations = [
            '<i class="fas fa-check-circle recommendation-icon"></i> Email appears safe but remain vigilant',
            '<i class="fas fa-info-circle recommendation-icon"></i> Report any suspicious emails to your IT department'
        ];
    }
    
    recContent.innerHTML = recommendations.join('<br>');
    
    // Show the results area
    document.getElementById('resultCard').style.display = 'block';
    document.getElementById('resultsArea').style.display = 'block';
}

/**
 * Get risk class string for CSS
 * @param {string} riskLevel - Risk level string
 * @returns {string} - CSS class name
 */
function getRiskClass(riskLevel) {
    const classes = {
        'Low Risk': 'risk-low',
        'Moderate Risk': 'risk-moderate',
        'High Risk': 'risk-high',
        'Critical Risk': 'risk-critical'
    };
    return classes[riskLevel] || 'risk-low';
}

/**
 * Get risk color RGB value
 * @param {string} riskLevel - Risk level string
 * @returns {string} - RGB color string
 */
function getRiskColor(riskLevel) {
    const colors = {
        'Low Risk': '34, 197, 94',
        'Moderate Risk': '245, 158, 11',
        'High Risk': '239, 68, 68',
        'Critical Risk': '220, 38, 38'
    };
    return colors[riskLevel] || '34, 197, 94';
}

/**
 * Get risk background CSS
 * @param {string} riskLevel - Risk level string
 * @returns {string} - Background CSS
 */
function getRiskBackground(riskLevel) {
    const backgrounds = {
        'Low Risk': 'rgba(34, 197, 94, 0.2)',
        'Moderate Risk': 'rgba(245, 158, 11, 0.2)',
        'High Risk': 'rgba(239, 68, 68, 0.2)',
        'Critical Risk': 'rgba(220, 38, 38, 0.2)'
    };
    return backgrounds[riskLevel] || 'rgba(34, 197, 94, 0.2)';
}

/**
 * Show scanning overlay
 */
function showScanningOverlay() {
    const overlay = document.getElementById('scanningOverlay');
    if (overlay) {
        overlay.style.display = 'flex';
    }
}

/**
 * Hide scanning overlay
 */
function hideScanningOverlay() {
    const overlay = document.getElementById('scanningOverlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

/**
 * Clear previous results
 */
function clearResults() {
    document.getElementById('resultsArea').style.display = 'none';
    document.getElementById('resultCard').style.display = 'none';
}

/**
 * Display results from pasted email
 * @param {object} result - Scan result
 */
function displayPasteResults(result) {
    const riskScore = result.risk_score;
    const riskLevel = result.risk_level;
    const classification = result.classification;
    const indicators = result.indicators || [];
    
    // Update risk display
    document.getElementById('riskDisplay').innerHTML = `
        <div class="risk-score-value ${getRiskClass(riskLevel)}">
            ${riskScore}<span>/100</span>
        </div>
    `;
    
    document.getElementById('riskLabel').textContent = riskLevel;
    document.getElementById('classificationBadge').textContent = classification;
    document.getElementById('classificationBadge').style.background = getRiskBackground(riskLevel);
    
    // Show indicators
    const indicatorsContent = document.getElementById('indicatorsList');
    if (indicators.length > 0) {
        let html = '';
        indicators.forEach(ind => {
            const typeClass = ind.risk?.toLowerCase() === 'high' ? 'high' : 
                             ind.risk?.toLowerCase() === 'medium' ? 'medium' : 'low';
            html += `
                <span class="indicator-badge ${typeClass}" style="background: rgba(${getRiskColor(riskLevel)}, 0.2); color: ${getRiskColor(riskLevel)};">
                    ${ind.type.replace(/_/g, ' ')}
                </span>
            `;
        });
        indicatorsContent.innerHTML = html;
    } else {
        indicatorsContent.innerHTML = '<p class="small text-secondary">No significant phishing indicators detected</p>';
    }
    
    // Show URLs
    const urlsContent = document.getElementById('urlsContent');
    if (result.analysis && result.analysis.link_analysis && result.analysis.link_analysis.length > 0) {
        urlsContent.innerHTML = '';
        result.analysis.link_analysis.forEach(link => {
            urlsContent.innerHTML += `<code class="url-item">${link.url || 'Suspicious link'}</code>`;
        });
    } else {
        urlsContent.innerHTML = '<p class="small text-secondary">No suspicious URLs found</p>';
    }
    
    // Show authentication
    const authContent = document.getElementById('authContent');
    const auth = result.authentication || {};
    let authHtml = '';
    
    if (auth.spf) {
        authHtml += `<div class="auth-method ${auth.spf.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>SPF: ${auth.spf.description || 'N/A'}</span>
            <span>${auth.spf.risk || 'N/A'}</span>
        </div>`;
    }
    if (auth.dkim) {
        authHtml += `<div class="auth-method ${auth.dkim.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>DKIM: ${auth.dkim.description || 'N/A'}</span>
            <span>${auth.dkim.risk || 'N/A'}</span>
        </div>`;
    }
    if (auth.dmarc) {
        authHtml += `<div class="auth-method ${auth.dmarc.risk?.toLowerCase() === 'high' ? 'fail' : 'pass'}">
            <span>DMARC: ${auth.dmarc.description || 'N/A'}</span>
            <span>${auth.dmarc.risk || 'N/A'}</span>
        </div>`;
    }
    
    if (!authHtml) {
        authHtml = '<p class="small text-secondary">No authentication data available</p>';
    }
    authContent.innerHTML = authHtml;
    
    // Show sender info
    document.getElementById('senderEmailField').textContent = result.sender || 'Unknown';
    document.getElementById('domainField').textContent = result.sender ? result.sender.split('@')[1] || 'Unknown' : 'Unknown';
    
    // Show recommendations
    const recContent = document.getElementById('recommendationsContent');
    const riskLevelLower = riskLevel.toLowerCase();
    
    let recommendations = [];
    if (riskLevelLower.includes('critical') || riskLevelLower.includes('high')) {
        recommendations = [
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Do not click any links in this email',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Do not download or open attachments',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Report this email as phishing to your email provider',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Change passwords if you clicked any links or entered credentials',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Enable two-factor authentication on your accounts'
        ];
    } else if (riskLevelLower === 'moderate') {
        recommendations = [
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Be cautious with any links or attachments',
            '<i class="fas fa-exclamation-triangle recommendation-icon"></i> Verify sender identity through official channels',
            '<i class="fas fa-info-circle recommendation-icon"></i> Review the email carefully for signs of phishing'
        ];
    } else {
        recommendations = [
            '<i class="fas fa-check-circle recommendation-icon"></i> Email appears safe but remain vigilant',
            '<i class="fas fa-info-circle recommendation-icon"></i> Report any suspicious emails to your IT department'
        ];
    }
    
    recContent.innerHTML = recommendations.join('<br>');
    
    // Show the results area
    document.getElementById('resultCard').style.display = 'block';
    document.getElementById('resultsArea').style.display = 'block';
}

/**
 * Show toast notification
 * @param {string} message - Message to display
 * @param {string} type - Type ('success', 'error', 'warning')
 */
function showToast(message, type = 'info') {
    // Create toast element
    const toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        const container = document.createElement('div');
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '1050';
        document.body.appendChild(container);
    }
    
    const toastId = 'mailguardToast';
    const existing = document.getElementById(toastId);
    if (existing) {
        existing.remove();
    }
    
    const colors = {
        success: { bg: 'var(--risk-low)', text: '#fff' },
        error: { bg: 'var(--risk-high)', text: '#fff' },
        warning: { bg: '#f59e0b', text: '#000' }
    };
    
    const color = colors[type] || colors.info;
    
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = 'toast align-items-center text-white bg-primary border-0';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-exclamation-triangle'} me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    const container = document.querySelector('.toast-container') || document.body;
    container.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

/**
 * Connect Gmail account
 */
async function connectGmail() {
    // In a real implementation, this would initiate the OAuth flow
    // For now, we'll simulate the connection
    const gmailConnectBtn = document.getElementById('gmailConnectBtn');
    const gmailStatus = document.getElementById('gmailStatus');
    
    if (!gmailConnectBtn || !gmailStatus) return;
    
    // Show loading state
    gmailConnectBtn.disabled = true;
    gmailConnectBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Connecting...';
    
    // Simulate OAuth flow - in production this would redirect to Google
    setTimeout(() => {
        // Mock successful connection
        gmailStatus.classList.remove('disconnected');
        gmailStatus.classList.add('connected');
        gmailStatus.querySelector('small').textContent = 'Connected';
        gmailConnectBtn.textContent = 'Connected';
        gmailConnectBtn.style.background = 'var(--risk-low)';
        gmailConnectBtn.disabled = false;
        
        showToast('Gmail account connected successfully!', 'success');
    }, 2000);
}

/**
 * Disconnect Gmail account
 */
function disconnectGmail() {
    if (confirm('Are you sure you want to disconnect your Gmail account?')) {
        // In a real implementation, this would revoke the token
        const gmailStatus = document.getElementById('gmailStatus');
        const gmailConnectBtn = document.getElementById('gmailConnectBtn');
        
        if (gmailStatus && gmailConnectBtn) {
            gmailStatus.classList.remove('connected');
            gmailStatus.classList.add('disconnected');
            gmailStatus.querySelector('small').textContent = 'Not connected';
            gmailConnectBtn.textContent = 'Connect Account';
            gmailConnectBtn.style.background = 'linear-gradient(135deg, var(--accent-electric), var(--accent-purple))';
            
            showToast('Gmail account disconnected', 'info');
        }
    }
}