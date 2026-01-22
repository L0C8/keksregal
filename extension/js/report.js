// Report page script
import { analyzeCookies } from './cookie-analysis.js';
let analysisData = null;
let aiAnalysisData = null;
let allCookies = [];
let allDomains = [];
let currentScanDomain = null;
let selectedCookies = new Set();
const issuesState = {
    page: 1,
    pageSize: 100,
    category: 'all',
    query: ''
};
// Load analysis data when page loads
document.addEventListener('DOMContentLoaded', async () => {
    const data = await chrome.storage.local.get(['cookieAnalysis', 'aiAnalysis', 'scanTime', 'scanContext']);
    aiAnalysisData = data.aiAnalysis;
    if (data.cookieAnalysis && data.cookieAnalysis.cookies && data.cookieAnalysis.cookies.length > 0) {
        analysisData = data.cookieAnalysis;
    }
    else {
        const scanContext = data.scanContext;
        const isCurrentScope = scanContext?.scope === 'current' && !!scanContext.domain;
        const domainFilter = isCurrentScope ? scanContext.domain : null;
        currentScanDomain = domainFilter;
        try {
            const cookies = await chrome.cookies.getAll(isCurrentScope ? { domain: domainFilter } : {});
            analysisData = analyzeCookies(cookies, domainFilter);
        }
        catch (error) {
            console.error('Failed to load cookies for report:', error);
            showEmptyState();
            return;
        }
    }
    if (!analysisData) {
        showEmptyState();
        return;
    }
    // Display scan time
    if (data.scanTime) {
        const scanDate = new Date(data.scanTime);
        document.getElementById('scanTime').textContent =
            `Scanned on ${scanDate.toLocaleString()}` +
                (aiAnalysisData ? ' • AI Analysis Enabled ✨' : '');
    }
    // Display summary
    displaySummary(analysisData);
    // Display AI insights first if available
    if (aiAnalysisData) {
        displayAIInsights(aiAnalysisData);
    }
    // Display abnormalities
    displayAbnormalities(analysisData.abnormalities);
    // Display domains
    displayDomains(analysisData.domains);
    // Display all cookies
    displayAllCookies(analysisData.cookies);
    // Setup filter tabs
    setupFilterTabs();
    setupIssuesSearch();
    // Setup view switcher
    setupViewSwitcher();
    setupCookieSelectionToolbar();
});
function displaySummary(data) {
    document.getElementById('totalCookies').textContent = data.totalCookies.toString();
    document.getElementById('thirdParty').textContent = data.thirdPartyCount.toString();
    document.getElementById('securityIssues').textContent = data.securityIssues.toString();
    document.getElementById('privacyConcerns').textContent = data.privacyConcerns.toString();
    document.getElementById('totalIssues').textContent = data.abnormalities.length.toString();
}
let allAbnormalities = [];
function displayAbnormalities(abnormalities) {
    const container = document.getElementById('abnormalities');
    // Store all abnormalities globally for filtering
    allAbnormalities = abnormalities;
    if (abnormalities.length === 0) {
        container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">✅</div>
        <p>No security or privacy issues detected!</p>
        <p style="font-size: 14px; margin-top: 10px; color: var(--muted);">
          Your cookies appear to be properly configured.
        </p>
      </div>
    `;
        return;
    }
    // Sort by severity
    const severityOrder = { high: 0, medium: 1, low: 2 };
    abnormalities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    // Categorize abnormalities and count them
    const categoryCounts = {
        all: abnormalities.length,
        security: 0,
        privacy: 0,
        tracking: 0,
        suspicious: 0,
        high: 0
    };
    abnormalities.forEach(abn => {
        if (abn.severity === 'high')
            categoryCounts.high++;
        if (abn.type === 'MISSING_HTTPONLY' || abn.type === 'MISSING_SECURE' || abn.type === 'LONG_SESSION_COOKIE') {
            categoryCounts.security++;
        }
        if (abn.type === 'THIRD_PARTY_TRACKER') {
            categoryCounts.tracking++;
            categoryCounts.privacy++;
        }
        if (abn.type === 'EXCESSIVE_LIFETIME' || abn.type === 'LARGE_PAYLOAD') {
            categoryCounts.privacy++;
        }
        if (abn.type === 'SUSPICIOUS_ENCODING' || abn.type === 'UNUSUAL_TLD' || abn.type === 'DUPLICATE_COOKIE') {
            categoryCounts.suspicious++;
        }
    });
    // Update counts in filter tabs
    Object.entries(categoryCounts).forEach(([category, count]) => {
        const countEl = document.getElementById(`count${category.charAt(0).toUpperCase() + category.slice(1)}`);
        if (countEl)
            countEl.textContent = count.toString();
    });
    issuesState.page = 1;
    updateIssuesView();
}
let selectedDomains = new Set();
async function displayDomains(domains) {
    const sortedDomains = Object.entries(domains)
        .sort((a, b) => b[1] - a[1]);
    allDomains = sortedDomains;
    renderDomainsList(sortedDomains, true);
    setupDomainSearch();
}
function displayAllCookies(cookies) {
    const container = document.getElementById('cookiesView');
    const listContainer = document.getElementById('cookiesList');
    if (!container || !listContainer)
        return;
    const sortedCookies = [...cookies].sort((a, b) => a.name.localeCompare(b.name));
    allCookies = sortedCookies;
    renderCookiesList(sortedCookies, allCookies.length);
    setupCookieSearch();
}

function renderCookiesList(cookies, totalCount) {
    const listContainer = document.getElementById('cookiesList');
    if (!listContainer)
        return;
    if (cookies.length === 0) {
        listContainer.innerHTML = `
    <div style="margin-bottom: 12px;">
      <p style="font-size: 14px; color: var(--muted); margin-bottom: 0;">
        No cookies match your search.
      </p>
    </div>
  `;
        return;
    }
    listContainer.innerHTML = `
    <div style="margin-bottom: 20px;">
      <p style="font-size: 14px; color: var(--muted); margin-bottom: 15px;">
        Showing ${cookies.length} of ${totalCount} cookie${totalCount === 1 ? '' : 's'}.
      </p>
    </div>
    <div style="display: grid; gap: 15px;">
      ${cookies.map(cookie => {
        const expiresDate = cookie.expirationDate
          ? new Date(cookie.expirationDate * 1000).toLocaleString()
          : 'Session';
        const cookieKey = buildCookieKey(cookie.name, cookie.domain, cookie.path, cookie.secure);
        return `
          <div data-cookie-name="${escapeHtml(cookie.name)}" data-cookie-domain="${escapeHtml(cookie.domain)}" style="background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 15px; border-left: 4px solid var(--accent);">
            <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
              <div style="flex: 1;">
                <div style="font-weight: 600; font-size: 16px; color: var(--text); margin-bottom: 4px;">${escapeHtml(cookie.name)}</div>
                <div style="font-size: 12px; color: var(--muted-strong);">${escapeHtml(cookie.domain)}</div>
              </div>
              <div style="display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" class="cookie-checkbox" data-cookie-key="${escapeHtml(cookieKey)}" ${selectedCookies.has(cookieKey) ? 'checked' : ''} style="width: 16px; height: 16px;">
                <button class="issue-delete-btn cookie-delete-btn" data-cookie-name="${escapeHtml(cookie.name)}" data-cookie-domain="${escapeHtml(cookie.domain)}" data-cookie-path="${escapeHtml(cookie.path)}" data-cookie-secure="${cookie.secure ? '1' : '0'}" title="Delete this cookie">❌</button>
              </div>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; font-size: 13px;">
              <div>
                <span style="color: var(--muted);">Expires:</span> 
                <span style="color: var(--text); font-weight: 500;">${escapeHtml(expiresDate)}</span>
              </div>
              <div>
                <span style="color: var(--muted);">Size:</span> 
                <span style="color: var(--text); font-weight: 500;">${cookie.value ? cookie.value.length : 0} bytes</span>
              </div>
              <div>
                <span style="color: var(--muted);">Secure:</span> 
                <span style="padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; ${cookie.secure ? 'background: color-mix(in srgb, var(--success) 18%, var(--panel)); color: var(--success);' : 'background: color-mix(in srgb, var(--danger) 18%, var(--panel)); color: var(--danger);'}">${cookie.secure ? '✓ Yes' : '✗ No'}</span>
              </div>
              <div>
                <span style="color: var(--muted);">HttpOnly:</span> 
                <span style="padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; ${cookie.httpOnly ? 'background: color-mix(in srgb, var(--success) 18%, var(--panel)); color: var(--success);' : 'background: color-mix(in srgb, var(--danger) 18%, var(--panel)); color: var(--danger);'}">${cookie.httpOnly ? '✓ Yes' : '✗ No'}</span>
              </div>
              <div>
                <span style="color: var(--muted);">SameSite:</span> 
                <span style="color: var(--text); font-weight: 500;">${escapeHtml(cookie.sameSite || 'None')}</span>
              </div>
              <div>
                <span style="color: var(--muted);">Path:</span> 
                <span style="color: var(--text); font-weight: 500;">${escapeHtml(cookie.path)}</span>
              </div>
            </div>
          </div>
        `;
    }).join('')}
    </div>
  `;
    attachCookieSelectionHandlers();
    attachCookieDeleteHandlers();
}

function setupCookieSearch() {
    const input = document.getElementById('cookieSearch');
    if (!input)
        return;
    input.addEventListener('input', () => {
        applyCookieSearch();
    });
}

function applyCookieSearch() {
    const input = document.getElementById('cookieSearch');
    const query = input ? input.value.trim() : '';
    if (!query) {
        renderCookiesList(allCookies, allCookies.length);
        return;
    }
    const filtered = allCookies.filter(cookie => {
        return matchesAnyPattern(cookie.name, query) ||
            matchesAnyPattern(cookie.domain, query) ||
            (cookie.value && matchesAnyPattern(cookie.value, query));
    });
    renderCookiesList(filtered, allCookies.length);
}

function setupIssuesSearch() {
    const input = document.getElementById('issuesSearch');
    if (!input)
        return;
    input.addEventListener('input', () => {
        issuesState.query = input.value.trim();
        issuesState.page = 1;
        updateIssuesView();
    });
}

function setupDomainSearch() {
    const input = document.getElementById('domainSearch');
    if (!input)
        return;
    input.addEventListener('input', () => {
        const query = input.value.trim();
        if (!query) {
            renderDomainsList(allDomains, true);
            return;
        }
        const filtered = allDomains.filter(([domain]) => matchesAnyPattern(domain, query));
        renderDomainsList(filtered, false);
    });
}

function renderDomainsList(domains, useLimit) {
    const container = document.getElementById('domains');
    if (!container)
        return;
    if (domains.length === 0) {
        container.innerHTML = '<p>No domains found</p>';
        return;
    }
    const initialDisplayCount = 30;
    const hasMore = useLimit && domains.length > initialDisplayCount;
    const visibleDomains = useLimit ? domains.slice(0, initialDisplayCount) : domains;
    container.innerHTML = visibleDomains.map(([domain, count]) => `
    <div class="domain-item" data-domain="${escapeHtml(domain)}">
      <input type="checkbox" class="domain-checkbox" data-domain="${escapeHtml(domain)}">
      <div class="domain-info">
        <div class="domain-name" title="${escapeHtml(domain)}">${escapeHtml(domain)}</div>
        <div class="domain-count">${count}</div>
      </div>
      <div class="domain-actions">
        <button class="info-domain-btn" data-domain="${escapeHtml(domain)}" title="View cookies from ${escapeHtml(domain)}">
          ❓
        </button>
        <button class="delete-domain-btn" data-domain="${escapeHtml(domain)}" title="Delete all cookies from ${escapeHtml(domain)}">
          ❌
        </button>
      </div>
    </div>
  `).join('');
    if (hasMore) {
        const showMoreBtn = document.createElement('button');
        showMoreBtn.textContent = `Show ${domains.length - initialDisplayCount} More Domains`;
        showMoreBtn.style.cssText = 'width: 100%; padding: 15px; margin-top: 15px; background: var(--panel-muted); color: var(--accent); border: 2px dashed var(--accent); border-radius: 8px; cursor: pointer; font-weight: 600;';
        showMoreBtn.addEventListener('click', () => {
            renderDomainsList(domains, false);
        });
        container.appendChild(showMoreBtn);
    }
    attachDomainEventListeners(container);
}

function matchesAnyPattern(value, query) {
    const normalizedValue = value.toLowerCase();
    const patterns = query.split(',').map(part => part.trim()).filter(Boolean);
    if (patterns.length === 0) {
        return normalizedValue.includes(query.toLowerCase());
    }
    return patterns.some(pattern => {
        const normalizedPattern = pattern.toLowerCase();
        if (normalizedPattern.includes('*') || normalizedPattern.includes('?')) {
            const regex = new RegExp('^' + escapeRegex(normalizedPattern).replace(/\\\*/g, '.*').replace(/\\\?/g, '.') + '$', 'i');
            return regex.test(normalizedValue);
        }
        return normalizedValue.includes(normalizedPattern);
    });
}

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function attachCookieDeleteHandlers() {
    document.querySelectorAll('.cookie-delete-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const target = e.currentTarget;
            const cookieName = target.getAttribute('data-cookie-name');
            const cookieDomain = target.getAttribute('data-cookie-domain');
            const cookiePath = target.getAttribute('data-cookie-path');
            const cookieSecure = target.getAttribute('data-cookie-secure') === '1';
            if (!cookieName || !cookieDomain || !cookiePath)
                return;
            if (!confirm(`Delete cookie "${cookieName}" on ${cookieDomain}? This cannot be undone.`)) {
                return;
            }
            try {
                const url = `http${cookieSecure ? 's' : ''}://${cookieDomain}${cookiePath}`;
                await chrome.cookies.remove({
                    url: url,
                    name: cookieName
                });
                if (analysisData) {
                    analysisData.cookies = analysisData.cookies.filter(cookie => !(cookie.name === cookieName && cookie.domain === cookieDomain && cookie.path === cookiePath && cookie.secure === cookieSecure));
                    analysisData = analyzeCookies(analysisData.cookies, currentScanDomain);
                    await chrome.storage.local.set({ cookieAnalysis: analysisData });
                    allAbnormalities = analysisData.abnormalities;
                    allCookies = analysisData.cookies ? [...analysisData.cookies].sort((a, b) => a.name.localeCompare(b.name)) : [];
                    displaySummary(analysisData);
                    displayDomains(analysisData.domains);
                    updateIssuesView();
                    applyCookieSearch();
                }
            }
            catch (error) {
                console.error('Error deleting cookie:', error);
                alert('Failed to delete the cookie. Please try again.');
            }
        });
    });
}

function setupCookieSelectionToolbar() {
    const deleteBtn = document.getElementById('deleteSelectedCookiesBtn');
    const clearBtn = document.getElementById('clearCookieSelectionBtn');
    if (!deleteBtn || !clearBtn)
        return;
    deleteBtn.addEventListener('click', deleteSelectedCookies);
    clearBtn.addEventListener('click', clearCookieSelection);
    // Setup date range deletion
    const deleteDateRangeBtn = document.getElementById('deleteDateRangeAllCookiesBtn');
    if (deleteDateRangeBtn) {
        deleteDateRangeBtn.addEventListener('click', deleteCookiesByDateRange);
    }
}

function attachCookieSelectionHandlers() {
    document.querySelectorAll('.cookie-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            e.stopPropagation();
            const target = e.currentTarget;
            const key = target.getAttribute('data-cookie-key');
            if (!key)
                return;
            if (target.checked) {
                selectedCookies.add(key);
            }
            else {
                selectedCookies.delete(key);
            }
            updateCookieSelectionToolbar();
        });
    });
}

function updateCookieSelectionToolbar() {
    const toolbar = document.getElementById('cookieSelectionToolbar');
    const countEl = document.getElementById('selectedCookieCount');
    if (!toolbar || !countEl)
        return;
    if (selectedCookies.size > 0) {
        toolbar.style.display = 'flex';
        countEl.textContent = selectedCookies.size.toString();
    }
    else {
        toolbar.style.display = 'none';
    }
}

function clearCookieSelection() {
    selectedCookies.clear();
    document.querySelectorAll('.cookie-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    updateCookieSelectionToolbar();
}

async function deleteSelectedCookies() {
    if (selectedCookies.size === 0) {
        alert('No cookies selected');
        return;
    }
    if (!confirm(`Delete ${selectedCookies.size} selected cookie${selectedCookies.size === 1 ? '' : 's'}? This cannot be undone.`)) {
        return;
    }
    let deletedCount = 0;
    try {
        for (const key of selectedCookies) {
            const cookieInfo = parseCookieKey(key);
            if (!cookieInfo)
                continue;
            const { name, domain, path, secure } = cookieInfo;
            const url = `http${secure ? 's' : ''}://${domain}${path}`;
            await chrome.cookies.remove({ url: url, name: name });
            deletedCount++;
        }
        if (analysisData) {
            analysisData.cookies = analysisData.cookies.filter(cookie => !selectedCookies.has(buildCookieKey(cookie.name, cookie.domain, cookie.path, cookie.secure)));
            analysisData = analyzeCookies(analysisData.cookies, currentScanDomain);
            await chrome.storage.local.set({ cookieAnalysis: analysisData });
            allAbnormalities = analysisData.abnormalities;
            allCookies = analysisData.cookies ? [...analysisData.cookies].sort((a, b) => a.name.localeCompare(b.name)) : [];
            displaySummary(analysisData);
            displayDomains(analysisData.domains);
            updateIssuesView();
            clearCookieSelection();
            applyCookieSearch();
        }
        alert(`Deleted ${deletedCount} cookie${deletedCount === 1 ? '' : 's'}.`);
    }
    catch (error) {
        console.error('Error deleting selected cookies:', error);
        alert('Failed to delete selected cookies. Please try again.');
    }
}

async function deleteCookiesByDateRange() {
    const beforeDateInput = document.getElementById('beforeDateAllCookies').value;
    const afterDateInput = document.getElementById('afterDateAllCookies').value;

    if (!beforeDateInput && !afterDateInput) {
        alert('Please select at least one date (before or after) to filter cookies.');
        return;
    }

    if (!analysisData || !analysisData.cookies) {
        alert('No cookies available to delete.');
        return;
    }

    const beforeDate = beforeDateInput ? new Date(beforeDateInput).getTime() / 1000 : null;
    const afterDate = afterDateInput ? new Date(afterDateInput).getTime() / 1000 : null;

    // Filter cookies based on expiration date
    const cookiesToDelete = analysisData.cookies.filter(cookie => {
        // Session cookies (no expiration date)
        if (!cookie.expirationDate) {
            return false;
        }

        const expirationTime = cookie.expirationDate;

        // If both dates are specified, cookie must expire between them
        if (beforeDate && afterDate) {
            return expirationTime <= beforeDate && expirationTime >= afterDate;
        }

        // If only before date is specified, cookie must expire before it
        if (beforeDate) {
            return expirationTime <= beforeDate;
        }

        // If only after date is specified, cookie must expire after it
        if (afterDate) {
            return expirationTime >= afterDate;
        }

        return false;
    });

    if (cookiesToDelete.length === 0) {
        alert('No cookies found matching the specified date range.');
        return;
    }

    const dateRangeText = beforeDateInput && afterDateInput
        ? `between ${afterDateInput} and ${beforeDateInput}`
        : beforeDateInput
        ? `expiring before ${beforeDateInput}`
        : `expiring after ${afterDateInput}`;

    if (!confirm(`Delete ${cookiesToDelete.length} cookie${cookiesToDelete.length !== 1 ? 's' : ''} ${dateRangeText}? This cannot be undone.`)) {
        return;
    }

    let deletedCount = 0;
    try {
        for (const cookie of cookiesToDelete) {
            const url = `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`;
            await chrome.cookies.remove({ url: url, name: cookie.name });
            deletedCount++;
        }

        // Update analysis data
        if (analysisData) {
            const deletedKeys = new Set(cookiesToDelete.map(c => buildCookieKey(c.name, c.domain, c.path, c.secure)));
            analysisData.cookies = analysisData.cookies.filter(cookie => !deletedKeys.has(buildCookieKey(cookie.name, cookie.domain, cookie.path, cookie.secure)));
            analysisData = analyzeCookies(analysisData.cookies, currentScanDomain);
            await chrome.storage.local.set({ cookieAnalysis: analysisData });
            allAbnormalities = analysisData.abnormalities;
            allCookies = analysisData.cookies ? [...analysisData.cookies].sort((a, b) => a.name.localeCompare(b.name)) : [];
            displaySummary(analysisData);
            displayDomains(analysisData.domains);
            updateIssuesView();
            applyCookieSearch();
        }

        alert(`Successfully deleted ${deletedCount} cookie${deletedCount !== 1 ? 's' : ''}`);

        // Clear date inputs
        document.getElementById('beforeDateAllCookies').value = '';
        document.getElementById('afterDateAllCookies').value = '';
    }
    catch (error) {
        console.error('Error deleting cookies:', error);
        alert(`Deleted ${deletedCount} cookies before error occurred.`);
    }
}

function buildCookieKey(name, domain, path, secure) {
    return `${name}||${domain}||${path}||${secure ? '1' : '0'}`;
}

function parseCookieKey(key) {
    const parts = key.split('||');
    if (parts.length !== 4)
        return null;
    return {
        name: parts[0],
        domain: parts[1],
        path: parts[2],
        secure: parts[3] === '1'
    };
}

function updateIssuesView() {
    const container = document.getElementById('abnormalities');
    const pagination = document.getElementById('issuesPagination');
    const prevBtn = document.getElementById('issuesPrev');
    const nextBtn = document.getElementById('issuesNext');
    const pageInfo = document.getElementById('issuesPageInfo');
    if (!container || !pagination || !prevBtn || !nextBtn || !pageInfo)
        return;
    const filtered = getFilteredAbnormalities();
    if (filtered.length === 0) {
        container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">✅</div>
        <p>No issues match your search</p>
      </div>
    `;
        pagination.style.display = 'none';
        return;
    }
    const totalPages = Math.max(1, Math.ceil(filtered.length / issuesState.pageSize));
    if (issuesState.page > totalPages) {
        issuesState.page = totalPages;
    }
    const startIndex = (issuesState.page - 1) * issuesState.pageSize;
    const endIndex = Math.min(startIndex + issuesState.pageSize, filtered.length);
    container.innerHTML = filtered.slice(startIndex, endIndex).map(abn => {
        const categories = ['all'];
        if (abn.severity === 'high')
            categories.push('high');
        if (abn.type === 'MISSING_HTTPONLY' || abn.type === 'MISSING_SECURE' || abn.type === 'LONG_SESSION_COOKIE') {
            categories.push('security');
        }
        if (abn.type === 'THIRD_PARTY_TRACKER') {
            categories.push('tracking', 'privacy');
        }
        if (abn.type === 'EXCESSIVE_LIFETIME' || abn.type === 'LARGE_PAYLOAD') {
            categories.push('privacy');
        }
        if (abn.type === 'SUSPICIOUS_ENCODING' || abn.type === 'UNUSUAL_TLD' || abn.type === 'DUPLICATE_COOKIE') {
            categories.push('suspicious');
        }
        return `
      <div class="abnormality-item ${abn.severity}" data-categories="${categories.join(',')}">
        <div class="abnormality-header">
          <div class="abnormality-name">${escapeHtml(abn.cookieName)}</div>
          <div class="issue-actions">
            <button class="issue-delete-btn" data-cookie-name="${escapeHtml(abn.cookieName)}" data-cookie-domain="${escapeHtml(abn.domain)}" ${abn.domain === 'multiple' ? 'disabled' : ''} title="${abn.domain === 'multiple' ? 'Cannot delete aggregated duplicate entries' : `Delete cookies for ${escapeHtml(abn.cookieName)} on ${escapeHtml(abn.domain)}`}">
              ❌
            </button>
            <div class="abnormality-severity ${abn.severity}">${abn.severity === 'high' ? 'risk' : abn.severity}</div>
          </div>
        </div>
        <div class="abnormality-domain">Domain: ${escapeHtml(abn.domain)}</div>
        <div class="abnormality-description">${escapeHtml(abn.description)}</div>
      </div>
    `;
    }).join('');
    pageInfo.textContent = `Showing ${startIndex + 1}-${endIndex} of ${filtered.length}`;
    prevBtn.disabled = issuesState.page <= 1;
    nextBtn.disabled = issuesState.page >= totalPages;
    pagination.style.display = filtered.length > issuesState.pageSize ? 'flex' : 'none';
    prevBtn.onclick = () => {
        if (issuesState.page > 1) {
            issuesState.page -= 1;
            updateIssuesView();
        }
    };
    nextBtn.onclick = () => {
        if (issuesState.page < totalPages) {
            issuesState.page += 1;
            updateIssuesView();
        }
    };
    attachIssueDeleteHandlers();
}

function getFilteredAbnormalities() {
    if (!allAbnormalities || allAbnormalities.length === 0) {
        return [];
    }
    let filtered = allAbnormalities;
    if (issuesState.category !== 'all') {
        filtered = filtered.filter(abn => {
            if (issuesState.category === 'high') {
                return abn.severity === 'high';
            }
            if (issuesState.category === 'security') {
                return abn.type === 'MISSING_HTTPONLY' || abn.type === 'MISSING_SECURE' || abn.type === 'LONG_SESSION_COOKIE';
            }
            if (issuesState.category === 'privacy') {
                return abn.type === 'THIRD_PARTY_TRACKER' || abn.type === 'EXCESSIVE_LIFETIME' || abn.type === 'LARGE_PAYLOAD';
            }
            if (issuesState.category === 'tracking') {
                return abn.type === 'THIRD_PARTY_TRACKER';
            }
            if (issuesState.category === 'suspicious') {
                return abn.type === 'SUSPICIOUS_ENCODING' || abn.type === 'UNUSUAL_TLD' || abn.type === 'DUPLICATE_COOKIE';
            }
            return true;
        });
    }
    if (issuesState.query) {
        filtered = filtered.filter(abn => {
            return matchesAnyPattern(abn.cookieName, issuesState.query) ||
                matchesAnyPattern(abn.domain, issuesState.query) ||
                matchesAnyPattern(abn.description, issuesState.query) ||
                matchesAnyPattern(abn.type, issuesState.query);
        });
    }
    const severityOrder = { high: 0, medium: 1, low: 2 };
    filtered.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    return filtered;
}

function attachIssueDeleteHandlers() {
    document.querySelectorAll('.issue-delete-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const target = e.currentTarget;
            if (target.disabled)
                return;
            const cookieName = target.getAttribute('data-cookie-name');
            const cookieDomain = target.getAttribute('data-cookie-domain');
            if (!cookieName || !cookieDomain)
                return;
            if (!confirm(`Delete all cookies named "${cookieName}" on ${cookieDomain}? This cannot be undone.`)) {
                return;
            }
            let deletedCount = 0;
            try {
                const matches = await chrome.cookies.getAll({
                    name: cookieName,
                    domain: cookieDomain
                });
                for (const match of matches) {
                    const url = `http${match.secure ? 's' : ''}://${match.domain}${match.path}`;
                    await chrome.cookies.remove({
                        url: url,
                        name: match.name
                    });
                    deletedCount++;
                }
                if (analysisData) {
                    analysisData.cookies = analysisData.cookies.filter(cookie => !(cookie.name === cookieName && cookie.domain === cookieDomain));
                    analysisData.totalCookies = Math.max(0, analysisData.totalCookies - deletedCount);
                    analysisData.domains = analysisData.cookies.reduce((acc, cookie) => {
                        acc[cookie.domain] = (acc[cookie.domain] || 0) + 1;
                        return acc;
                    }, {});
                    analysisData.abnormalities = analysisData.abnormalities.filter(abn => !(abn.cookieName === cookieName && abn.domain === cookieDomain));
                    let securityIssues = 0;
                    let privacyConcerns = 0;
                    let thirdPartyCount = 0;
                    analysisData.abnormalities.forEach(abn => {
                        if (abn.type === 'MISSING_HTTPONLY' || abn.type === 'MISSING_SECURE') {
                            securityIssues++;
                        }
                        if (abn.type === 'THIRD_PARTY_TRACKER') {
                            thirdPartyCount++;
                        }
                        if (abn.type === 'EXCESSIVE_LIFETIME' || abn.type === 'LARGE_PAYLOAD' || abn.type === 'SUSPICIOUS_ENCODING') {
                            privacyConcerns++;
                        }
                    });
                    analysisData.securityIssues = securityIssues;
                    analysisData.privacyConcerns = privacyConcerns;
                    analysisData.thirdPartyCount = thirdPartyCount;
                    await chrome.storage.local.set({ cookieAnalysis: analysisData });
                    allAbnormalities = analysisData.abnormalities;
                    allCookies = analysisData.cookies ? [...analysisData.cookies].sort((a, b) => a.name.localeCompare(b.name)) : [];
                    renderCookiesList(allCookies, allCookies.length);
                    displaySummary(analysisData);
                    displayDomains(analysisData.domains);
                    updateIssuesView();
                }
            }
            catch (error) {
                console.error('Error deleting cookie from issue:', error);
                alert('Failed to delete the cookie. Please try again.');
            }
        });
    });
}
function attachDomainEventListeners(container) {
    // Add checkbox listeners
    container.querySelectorAll('.domain-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            e.stopPropagation();
            const domain = e.target.getAttribute('data-domain');
            const domainItem = e.target.closest('.domain-item');
            if (e.target.checked) {
                selectedDomains.add(domain);
                domainItem.classList.add('selected');
            }
            else {
                selectedDomains.delete(domain);
                domainItem.classList.remove('selected');
            }
            updateSelectionToolbar();
        });
    });
    // Add click handlers for domain items (toggle checkbox)
    container.querySelectorAll('.domain-item').forEach(item => {
        item.addEventListener('click', (e) => {
            // Don't toggle if clicking on buttons
            if (e.target.classList.contains('info-domain-btn') ||
                e.target.classList.contains('delete-domain-btn') ||
                e.target.classList.contains('domain-checkbox')) {
                return;
            }
            const checkbox = item.querySelector('.domain-checkbox');
            checkbox.checked = !checkbox.checked;
            checkbox.dispatchEvent(new Event('change'));
        });
    });
    // Add click handlers for info buttons
    container.querySelectorAll('.info-domain-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const domain = e.target.getAttribute('data-domain');
            await openDomainCookiesTab(domain);
        });
    });
    // Add click handlers for delete buttons
    container.querySelectorAll('.delete-domain-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const domain = e.target.getAttribute('data-domain');
            await deleteCookiesByDomain(domain);
        });
    });
}
function updateSelectionToolbar() {
    const toolbar = document.querySelector('.domain-selection-toolbar');
    const selectedCount = document.getElementById('selectedCount');
    if (selectedDomains.size > 0) {
        toolbar.style.display = 'flex';
        selectedCount.textContent = selectedDomains.size.toString();
    }
    else {
        toolbar.style.display = 'none';
    }
}
async function deleteSelectedDomains() {
    if (selectedDomains.size === 0) {
        alert('No domains selected');
        return;
    }
    const domains = Array.from(selectedDomains);
    if (!confirm(`Delete all cookies from ${domains.length} selected domain${domains.length !== 1 ? 's' : ''}? This cannot be undone.`)) {
        return;
    }
    let totalDeleted = 0;
    for (const domain of domains) {
        try {
            const cookies = await chrome.cookies.getAll({ domain: domain });
            for (const cookie of cookies) {
                const url = `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`;
                await chrome.cookies.remove({
                    url: url,
                    name: cookie.name
                });
                totalDeleted++;
            }
            // Update analysis data
            if (analysisData && analysisData.domains) {
                delete analysisData.domains[domain];
                analysisData.abnormalities = analysisData.abnormalities.filter(abn => abn.domain !== domain);
            }
        }
        catch (error) {
            console.error(`Error deleting cookies from ${domain}:`, error);
        }
    }
    // Recalculate totals
    if (analysisData) {
        analysisData.totalCookies -= totalDeleted;
        let securityIssues = 0;
        let privacyConcerns = 0;
        analysisData.abnormalities.forEach(abn => {
            if (abn.type === 'MISSING_HTTPONLY' || abn.type === 'MISSING_SECURE') {
                securityIssues++;
            }
            if (abn.type === 'THIRD_PARTY_TRACKER' || abn.type === 'EXCESSIVE_LIFETIME') {
                privacyConcerns++;
            }
        });
        analysisData.securityIssues = securityIssues;
        analysisData.privacyConcerns = privacyConcerns;
        await chrome.storage.local.set({ cookieAnalysis: analysisData });
    }
    // Clear selection
    selectedDomains.clear();
    updateSelectionToolbar();
    // Update UI
    displaySummary(analysisData);
    displayAbnormalities(analysisData.abnormalities);
    displayDomains(analysisData.domains);
    alert(`Successfully deleted ${totalDeleted} cookie${totalDeleted !== 1 ? 's' : ''} from ${domains.length} domain${domains.length !== 1 ? 's' : ''}`);
}
function clearSelection() {
    selectedDomains.clear();
    // Uncheck all checkboxes
    document.querySelectorAll('.domain-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    // Remove selected class from all items
    document.querySelectorAll('.domain-item').forEach(item => {
        item.classList.remove('selected');
    });
    updateSelectionToolbar();
}
async function openDomainCookiesTab(domain) {
    // Fetch cookies for this domain
    const cookies = await chrome.cookies.getAll({ domain: domain });
    if (cookies.length === 0) {
        alert(`No cookies found for ${domain}`);
        return;
    }
    // Store the domain cookies data for the new tab
    await chrome.storage.local.set({
        domainCookiesView: {
            domain: domain,
            cookies: cookies,
            timestamp: Date.now()
        }
    });
    // Open the domain cookies page in a new tab
    chrome.tabs.create({
        url: chrome.runtime.getURL('domain-cookies.html')
    });
}
async function deleteCookiesByDomain(domain) {
    if (!confirm(`Delete all cookies from ${domain}? This cannot be undone.`)) {
        return;
    }
    let deletedCount = 0;
    try {
        // Get all cookies for this domain
        const cookies = await chrome.cookies.getAll({ domain: domain });
        // Delete each cookie
        for (const cookie of cookies) {
            const url = `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`;
            await chrome.cookies.remove({
                url: url,
                name: cookie.name
            });
            deletedCount++;
        }
        // Update the stored analysis data
        if (analysisData && analysisData.domains) {
            // Remove the domain from the domains object
            delete analysisData.domains[domain];
            // Remove abnormalities related to this domain
            analysisData.abnormalities = analysisData.abnormalities.filter(abn => abn.domain !== domain);
            // Recalculate counts
            const domainCookieCount = deletedCount;
            analysisData.totalCookies -= domainCookieCount;
            // Recalculate security and privacy issues
            let securityIssues = 0;
            let privacyConcerns = 0;
            analysisData.abnormalities.forEach(abn => {
                if (abn.type === 'MISSING_HTTPONLY' || abn.type === 'MISSING_SECURE') {
                    securityIssues++;
                }
                if (abn.type === 'THIRD_PARTY_TRACKER' || abn.type === 'EXCESSIVE_LIFETIME') {
                    privacyConcerns++;
                }
            });
            analysisData.securityIssues = securityIssues;
            analysisData.privacyConcerns = privacyConcerns;
            // Update storage
            await chrome.storage.local.set({ cookieAnalysis: analysisData });
            // Update the UI
            displaySummary(analysisData);
            displayAbnormalities(analysisData.abnormalities);
            displayDomains(analysisData.domains);
        }
        alert(`Successfully deleted ${deletedCount} cookie${deletedCount !== 1 ? 's' : ''} from ${domain}`);
    }
    catch (error) {
        console.error('Error deleting cookies:', error);
        alert('Failed to delete some cookies. Please try again.');
    }
}
function setupViewSwitcher() {
    const viewTabs = document.querySelectorAll('.view-tab');
    viewTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            viewTabs.forEach(t => t.classList.remove('active'));
            // Add active class to clicked tab
            tab.classList.add('active');
            // Get selected view
            const selectedView = tab.getAttribute('data-view');
            // Toggle views
            const homeView = document.getElementById('homeView');
            const issuesView = document.getElementById('issuesView');
            const cookiesView = document.getElementById('cookiesView');
            const domainsView = document.getElementById('domainsView');
            // Hide all views
            if (homeView)
                homeView.style.display = 'none';
            issuesView.style.display = 'none';
            if (cookiesView)
                cookiesView.style.display = 'none';
            domainsView.style.display = 'none';
            // Show selected view
            if (selectedView === 'home') {
                if (homeView)
                    homeView.style.display = 'block';
            }
            else if (selectedView === 'issues') {
                issuesView.style.display = 'block';
            }
            else if (selectedView === 'cookies') {
                if (cookiesView)
                    cookiesView.style.display = 'block';
            }
            else if (selectedView === 'domains') {
                domainsView.style.display = 'block';
            }
        });
    });
}
// Button handlers
document.getElementById('exportBtn').addEventListener('click', exportReport);
document.getElementById('clearCookiesBtn').addEventListener('click', clearProblematicCookies);
document.getElementById('scanAgainBtn').addEventListener('click', () => {
    window.close();
    chrome.action.openPopup();
});
// Domain selection toolbar buttons
document.getElementById('deleteSelectedBtn').addEventListener('click', deleteSelectedDomains);
document.getElementById('clearSelectionBtn').addEventListener('click', clearSelection);
async function exportReport() {
    if (!analysisData)
        return;
    const report = {
        scanTime: new Date().toISOString(),
        summary: {
            totalCookies: analysisData.totalCookies,
            thirdParty: analysisData.thirdPartyCount,
            securityIssues: analysisData.securityIssues,
            privacyConcerns: analysisData.privacyConcerns
        },
        abnormalities: analysisData.abnormalities,
        domains: analysisData.domains
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cookie-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}
async function clearProblematicCookies() {
    if (!analysisData || !confirm('This will delete cookies with security or privacy issues. Continue?')) {
        return;
    }
    const problematicCookies = analysisData.abnormalities
        .filter(abn => abn.severity === 'high' || abn.severity === 'medium')
        .map(abn => ({ name: abn.cookieName, domain: abn.domain }));
    let deletedCount = 0;
    for (const cookie of problematicCookies) {
        try {
            // Get all cookies matching this name and domain
            const matches = await chrome.cookies.getAll({
                name: cookie.name,
                domain: cookie.domain
            });
            for (const match of matches) {
                const url = `http${match.secure ? 's' : ''}://${match.domain}${match.path}`;
                await chrome.cookies.remove({
                    url: url,
                    name: match.name
                });
                deletedCount++;
            }
        }
        catch (error) {
            console.error('Error deleting cookie:', error);
        }
    }
    alert(`Deleted ${deletedCount} problematic cookies. Scan again to see updated results.`);
}
function showEmptyState() {
    const content = document.querySelector('.content');
    content.innerHTML = `
    <div class="empty-state">
      <div class="empty-state-icon"><img src="icons/icon48.png" alt="keksregal" style="width: 48px; height: 48px;"></div>
      <p style="font-size: 20px; margin-bottom: 10px;">No Analysis Data</p>
      <p style="color: var(--muted);">Please run a cookie scan first.</p>
      <button onclick="window.close(); chrome.action.openPopup();" style="margin-top: 20px;">
        Go to Scanner
      </button>
    </div>
  `;
}
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
function displayAIInsights(aiData) {
    // Insert AI insights section at the top of content
    const content = document.querySelector('.content');
    const aiSection = document.createElement('section');
    aiSection.id = 'aiInsights';
    aiSection.style.marginBottom = '40px';
    aiSection.innerHTML = `
    <h2>🤖 AI Analysis</h2>

    <div style="background: var(--header-gradient); color: white; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
      <h3 style="margin: 0 0 15px 0; font-size: 18px;">Overall Assessment</h3>
      <p style="margin: 0; font-size: 14px; line-height: 1.8; opacity: 0.95;">
        ${escapeHtml(aiData.assessment || 'No assessment available')}
      </p>
    </div>

    ${aiData.unusualPatterns ? `
      <div style="background: color-mix(in srgb, var(--warning) 18%, var(--panel)); border-left: 4px solid var(--warning); padding: 20px; border-radius: 4px; margin-bottom: 20px;">
        <h3 style="color: var(--warning); margin: 0 0 15px 0; font-size: 16px;">⚠️ Unusual Patterns Detected</h3>
        <p style="margin: 0; font-size: 14px; color: color-mix(in srgb, var(--warning) 70%, var(--text)); line-height: 1.6;">
          ${escapeHtml(aiData.unusualPatterns)}
        </p>
      </div>
    ` : ''}

    ${aiData.securityRisks && aiData.securityRisks.length > 0 ? `
      <div style="margin-bottom: 20px;">
        <h3 style="color: var(--danger); margin: 0 0 15px 0; font-size: 16px;">🔒 Top Security Risks</h3>
        <ul style="margin: 0; padding-left: 20px; list-style: none;">
          ${aiData.securityRisks.map(risk => `
            <li style="padding: 10px 0; border-bottom: 1px solid var(--border); color: var(--muted); font-size: 14px; line-height: 1.6;">
              <span style="color: var(--danger); font-weight: 600;">▸</span> ${escapeHtml(risk)}
            </li>
          `).join('')}
        </ul>
      </div>
    ` : ''}
  `;
    content.insertBefore(aiSection, content.firstChild);
}
function setupFilterTabs() {
    const filterTabs = document.querySelectorAll('.filter-tab');
    filterTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            filterTabs.forEach(t => t.classList.remove('active'));
            // Add active class to clicked tab
            tab.classList.add('active');
            // Get selected category
            const selectedCategory = tab.getAttribute('data-category');
            // Filter and re-render abnormalities
            filterAbnormalities(selectedCategory);
            // Scroll to abnormalities section
            document.getElementById('issuesView').scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        });
    });
}
function filterAbnormalities(category) {
    if (!allAbnormalities || allAbnormalities.length === 0) {
        return;
    }
    issuesState.category = category;
    issuesState.page = 1;
    updateIssuesView();
}
//# sourceMappingURL=report.js.map
