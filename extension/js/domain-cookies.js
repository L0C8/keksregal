"use strict";
// Domain cookies page script
let currentDomain = null;
let currentCookies = [];
let filteredCookies = [];
// Load domain cookies data when page loads
document.addEventListener('DOMContentLoaded', async () => {
    const data = await chrome.storage.local.get(['domainCookiesView']);
    if (!data.domainCookiesView) {
        showEmptyState();
        return;
    }
    currentDomain = data.domainCookiesView.domain;
    currentCookies = data.domainCookiesView.cookies;
    filteredCookies = currentCookies;
    // Display domain name
    document.getElementById('domainName').textContent = currentDomain;
    document.getElementById('cookieCount').textContent = `${currentCookies.length} cookie${currentCookies.length !== 1 ? 's' : ''}`;
    // Display summary
    displaySummary(currentCookies);
    // Display cookies
    displayCookies(currentCookies);
    // Setup search functionality
    setupSearch();
});
function displaySummary(cookies) {
    const stats = {
        total: cookies.length,
        secure: cookies.filter(c => c.secure).length,
        httpOnly: cookies.filter(c => c.httpOnly).length,
        session: cookies.filter(c => !c.expirationDate).length,
        persistent: cookies.filter(c => c.expirationDate).length
    };
    document.getElementById('totalCookies').textContent = stats.total.toString();
    document.getElementById('secureCookies').textContent = stats.secure.toString();
    document.getElementById('httpOnlyCookies').textContent = stats.httpOnly.toString();
    document.getElementById('sessionCookies').textContent = stats.session.toString();
    document.getElementById('persistentCookies').textContent = stats.persistent.toString();
}
function displayCookies(cookies) {
    const container = document.getElementById('cookiesContainer');
    if (cookies.length === 0) {
        container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon"><img src="icons/icon48.png" alt="keksregal" style="width: 48px; height: 48px;"></div>
        <p>No cookies found for this domain</p>
      </div>
    `;
        return;
    }
    // Sort cookies by name
    cookies.sort((a, b) => a.name.localeCompare(b.name));
    container.innerHTML = cookies.map(cookie => {
        const expiresDate = cookie.expirationDate
            ? new Date(cookie.expirationDate * 1000).toLocaleString()
            : 'Session';
        const valuePreview = cookie.value && cookie.value.length > 50
            ? cookie.value.substring(0, 50) + '...'
            : cookie.value || '';
        return `
      <div class="cookie-card" data-cookie-name="${escapeHtml(cookie.name)}" data-cookie-domain="${escapeHtml(cookie.domain)}">
        <div class="cookie-header">
          <div class="cookie-name-section">
            <div class="cookie-name">${escapeHtml(cookie.name)}</div>
            <div class="cookie-value-preview" onclick="showFullValue('${escapeHtml(cookie.value ? cookie.value.replace(/'/g, "\\'") : '')}')" title="Click to view full value">
              ${escapeHtml(valuePreview)}
            </div>
          </div>
          <button class="delete-cookie-btn" onclick="deleteSingleCookie('${escapeHtml(cookie.name)}', '${escapeHtml(cookie.domain)}', '${escapeHtml(cookie.path)}', ${cookie.secure})">
            Delete
          </button>
        </div>
        <div class="cookie-details">
          <div class="detail-item">
            <div class="detail-label">Domain</div>
            <div class="detail-value">${escapeHtml(cookie.domain)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Path</div>
            <div class="detail-value">${escapeHtml(cookie.path)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Expires</div>
            <div class="detail-value">${escapeHtml(expiresDate)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Size</div>
            <div class="detail-value">${cookie.value ? cookie.value.length : 0} bytes</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Secure</div>
            <div class="detail-value">
              <span class="flag-badge ${cookie.secure ? 'yes' : 'no'}">
                ${cookie.secure ? '✅ Yes' : '❌ No'}
              </span>
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">HttpOnly</div>
            <div class="detail-value">
              <span class="flag-badge ${cookie.httpOnly ? 'yes' : 'no'}">
                ${cookie.httpOnly ? '✅ Yes' : '❌ No'}
              </span>
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">SameSite</div>
            <div class="detail-value">${escapeHtml(cookie.sameSite || 'None')}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Host Only</div>
            <div class="detail-value">
              <span class="flag-badge ${cookie.hostOnly ? 'yes' : 'no'}">
                ${cookie.hostOnly ? '✅ Yes' : '❌ No'}
              </span>
            </div>
          </div>
        </div>
      </div>
    `;
    }).join('');
}
function showFullValue(value) {
    const modal = document.getElementById('valueModal');
    const modalValue = document.getElementById('modalCookieValue');
    modalValue.textContent = value;
    modal.style.display = 'block';
}
function closeValueModal() {
    document.getElementById('valueModal').style.display = 'none';
}
// Close modal when clicking outside of it
window.onclick = function (event) {
    const modal = document.getElementById('valueModal');
    if (event.target === modal) {
        closeValueModal();
    }
};
async function deleteSingleCookie(name, domain, path, secure) {
    if (!confirm(`Delete cookie "${name}"?`)) {
        return;
    }
    try {
        const url = `http${secure ? 's' : ''}://${domain}${path}`;
        await chrome.cookies.remove({
            url: url,
            name: name
        });
        // Refresh the display
        await refreshCookies();
        alert(`Cookie "${name}" deleted successfully`);
    }
    catch (error) {
        console.error('Error deleting cookie:', error);
        alert('Failed to delete cookie. Please try again.');
    }
}
async function deleteAllCookies() {
    if (!confirm(`Delete all ${currentCookies.length} cookies from ${currentDomain}? This cannot be undone.`)) {
        return;
    }
    let deletedCount = 0;
    try {
        for (const cookie of currentCookies) {
            const url = `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`;
            await chrome.cookies.remove({
                url: url,
                name: cookie.name
            });
            deletedCount++;
        }
        alert(`Successfully deleted ${deletedCount} cookie${deletedCount !== 1 ? 's' : ''}`);
        // Refresh the display
        await refreshCookies();
    }
    catch (error) {
        console.error('Error deleting cookies:', error);
        alert(`Deleted ${deletedCount} cookies before error occurred.`);
        await refreshCookies();
    }
}
async function refreshCookies() {
    if (!currentDomain)
        return;
    // Re-fetch cookies for the current domain
    const cookies = await chrome.cookies.getAll({ domain: currentDomain });
    currentCookies = cookies;
    // Update storage
    await chrome.storage.local.set({
        domainCookiesView: {
            domain: currentDomain,
            cookies: cookies,
            timestamp: Date.now()
        }
    });
    // Update display
    document.getElementById('cookieCount').textContent = `${cookies.length} cookie${cookies.length !== 1 ? 's' : ''}`;
    displaySummary(cookies);
    displayCookies(cookies);
    if (cookies.length === 0) {
        showEmptyState();
    }
}
function showEmptyState() {
    const content = document.querySelector('.content');
    content.innerHTML = `
    <div class="empty-state">
      <div class="empty-state-icon"><img src="icons/icon48.png" alt="keksregal" style="width: 48px; height: 48px;"></div>
      <p style="font-size: 20px; margin-bottom: 10px;">No Cookies Found</p>
      <p style="color: #666;">This domain has no cookies.</p>
    </div>
  `;
    const summary = document.getElementById('summary');
    const actions = document.querySelector('.actions');
    summary.style.display = 'none';
    actions.style.display = 'none';
}
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
async function deleteInsecureCookies() {
    // Find insecure cookies (missing Secure or HttpOnly flags)
    const insecureCookies = currentCookies.filter(cookie => !cookie.secure || !cookie.httpOnly);
    if (insecureCookies.length === 0) {
        alert('No insecure cookies found! All cookies have proper security flags.');
        return;
    }
    if (!confirm(`Delete ${insecureCookies.length} insecure cookie${insecureCookies.length !== 1 ? 's' : ''} (missing Secure or HttpOnly flags)? This cannot be undone.`)) {
        return;
    }
    let deletedCount = 0;
    try {
        for (const cookie of insecureCookies) {
            const url = `http${cookie.secure ? 's' : ''}://${cookie.domain}${cookie.path}`;
            await chrome.cookies.remove({
                url: url,
                name: cookie.name
            });
            deletedCount++;
        }
        alert(`Successfully deleted ${deletedCount} insecure cookie${deletedCount !== 1 ? 's' : ''}`);
        // Refresh the display
        await refreshCookies();
    }
    catch (error) {
        console.error('Error deleting cookies:', error);
        await refreshCookies();
    }
}
async function deleteCookiesByDateRange() {
    const beforeDateInput = document.getElementById('beforeDate').value;
    const afterDateInput = document.getElementById('afterDate').value;

    if (!beforeDateInput && !afterDateInput) {
        alert('Please select at least one date (before or after) to filter cookies.');
        return;
    }

    let cookiesToDelete = currentCookies;
    const beforeDate = beforeDateInput ? new Date(beforeDateInput).getTime() / 1000 : null;
    const afterDate = afterDateInput ? new Date(afterDateInput).getTime() / 1000 : null;

    // Filter cookies based on expiration date
    cookiesToDelete = currentCookies.filter(cookie => {
        // Session cookies (no expiration date) - treat as infinite future
        if (!cookie.expirationDate) {
            // Only delete session cookies if we're looking for cookies "after" a date
            // (since they effectively never expire)
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
            await chrome.cookies.remove({
                url: url,
                name: cookie.name
            });
            deletedCount++;
        }
        alert(`Successfully deleted ${deletedCount} cookie${deletedCount !== 1 ? 's' : ''}`);

        // Clear date inputs
        document.getElementById('beforeDate').value = '';
        document.getElementById('afterDate').value = '';

        // Refresh the display
        await refreshCookies();
    }
    catch (error) {
        console.error('Error deleting cookies:', error);
        alert(`Deleted ${deletedCount} cookies before error occurred.`);
        await refreshCookies();
    }
}

// Button handlers
document.getElementById('backBtn').addEventListener('click', () => {
    // Try to go back in history, otherwise close the tab
    if (window.history.length > 1) {
        window.history.back();
    }
    else {
        window.close();
    }
});
document.getElementById('deleteAllBtn').addEventListener('click', deleteAllCookies);
document.getElementById('deleteInsecureBtn').addEventListener('click', deleteInsecureCookies);
document.getElementById('deleteDateRangeBtn').addEventListener('click', deleteCookiesByDateRange);
document.getElementById('refreshBtn').addEventListener('click', refreshCookies);
// Search functionality
function setupSearch() {
    const domainSearchInput = document.getElementById('domainSearchInput');
    const cookieSearchInput = document.getElementById('cookieSearchInput');
    const clearDomainButton = document.getElementById('clearDomainSearch');
    const clearCookieButton = document.getElementById('clearCookieSearch');
    const searchResultsInfo = document.getElementById('searchResultsInfo');
    if (!domainSearchInput || !cookieSearchInput || !clearDomainButton || !clearCookieButton || !searchResultsInfo) {
        return;
    }
    // Convert wildcard pattern to regex
    function wildcardToRegex(pattern) {
        // Escape special regex characters except *
        const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
        // Replace * with .*
        const regexPattern = escaped.replace(/\*/g, '.*');
        return new RegExp(regexPattern, 'i');
    }
    // Check if text matches pattern (supports wildcards)
    function matchesPattern(text, pattern) {
        if (!pattern)
            return true;
        // If pattern contains *, use regex matching
        if (pattern.includes('*')) {
            const regex = wildcardToRegex(pattern);
            return regex.test(text);
        }
        // Otherwise, use simple includes
        return text.includes(pattern);
    }
    // Function to apply both filters
    function applyFilters() {
        const domainQuery = domainSearchInput.value.trim().toLowerCase();
        const cookieQuery = cookieSearchInput.value.trim().toLowerCase();
        // Start with all cookies
        let results = currentCookies;
        // Apply domain filter
        if (domainQuery) {
            results = results.filter(cookie => {
                return matchesPattern(cookie.domain.toLowerCase(), domainQuery);
            });
        }
        // Apply cookie name/value filter
        if (cookieQuery) {
            results = results.filter(cookie => {
                return (matchesPattern(cookie.name.toLowerCase(), cookieQuery) ||
                    matchesPattern(cookie.path.toLowerCase(), cookieQuery) ||
                    (cookie.value && matchesPattern(cookie.value.toLowerCase(), cookieQuery)));
            });
        }
        filteredCookies = results;
        // Show search results info
        if (domainQuery || cookieQuery) {
            const resultText = filteredCookies.length === 1 ? 'result' : 'results';
            let searchInfo = `Found ${filteredCookies.length} ${resultText}`;
            const filters = [];
            if (domainQuery)
                filters.push(`domain: "${domainQuery}"`);
            if (cookieQuery)
                filters.push(`cookie: "${cookieQuery}"`);
            if (filters.length > 0) {
                searchInfo += ` for ${filters.join(' and ')}`;
            }
            searchResultsInfo.textContent = searchInfo;
        }
        else {
            searchResultsInfo.textContent = '';
        }
        // Update display
        displayCookies(filteredCookies);
        displaySummary(filteredCookies);
    }
    // Domain search input handler
    domainSearchInput.addEventListener('input', (e) => {
        const query = e.target.value.trim();
        clearDomainButton.classList.toggle('visible', query.length > 0);
        applyFilters();
    });
    // Cookie search input handler
    cookieSearchInput.addEventListener('input', (e) => {
        const query = e.target.value.trim();
        clearCookieButton.classList.toggle('visible', query.length > 0);
        applyFilters();
    });
    // Clear domain search button
    clearDomainButton.addEventListener('click', () => {
        domainSearchInput.value = '';
        clearDomainButton.classList.remove('visible');
        domainSearchInput.focus();
        applyFilters();
    });
    // Clear cookie search button
    clearCookieButton.addEventListener('click', () => {
        cookieSearchInput.value = '';
        clearCookieButton.classList.remove('visible');
        cookieSearchInput.focus();
        applyFilters();
    });
    // Allow ESC key to clear searches
    domainSearchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            domainSearchInput.value = '';
            clearDomainButton.classList.remove('visible');
            applyFilters();
        }
    });
    cookieSearchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            cookieSearchInput.value = '';
            clearCookieButton.classList.remove('visible');
            applyFilters();
        }
    });
}
//# sourceMappingURL=domain-cookies.js.map
