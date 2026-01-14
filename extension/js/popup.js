// Popup script for keksregal extension
import { analyzeCookies } from './cookie-analysis.js';
document.getElementById('scanBtn').addEventListener('click', async () => {
    await scanCookies('all');
});
document.getElementById('scanCurrentBtn').addEventListener('click', async () => {
    await scanCookies('current');
});
document.getElementById('settingsLink').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
});
async function scanCookies(scope) {
    const statusDiv = document.getElementById('status');
    const statsDiv = document.getElementById('stats');
    const scanBtn = document.getElementById('scanBtn');
    const scanCurrentBtn = document.getElementById('scanCurrentBtn');
    // Disable buttons
    scanBtn.disabled = true;
    scanCurrentBtn.disabled = true;
    // Show loading status
    statusDiv.className = 'info';
    statusDiv.textContent = 'Analyzing cookies...';
    statsDiv.classList.remove('visible');
    try {
        let cookies;
        let scanContext = { scope: scope };
        if (scope === 'current') {
            // Get current tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            const url = new URL(tab.url);
            scanContext = { scope: scope, domain: url.hostname };
            // Get cookies for current domain
            cookies = await chrome.cookies.getAll({ domain: url.hostname });
        }
        else {
            // Get all cookies
            cookies = await chrome.cookies.getAll({});
        }
        // Analyze cookies
        const analysis = analyzeCookies(cookies, scanContext.domain ?? null);
        // Check if AI analysis is enabled
        const settings = await chrome.storage.local.get(['openaiApiKey', 'enableAI']);
        let aiAnalysis = null;
        if (settings.enableAI && settings.openaiApiKey) {
            statusDiv.textContent = 'Running AI analysis...';
            try {
                // Import AI analyzer
                const { AIAnalyzer } = await import('./ai-analyzer.js');
                const analyzer = new AIAnalyzer(settings.openaiApiKey);
                aiAnalysis = await analyzer.analyzeCookies(cookies, analysis);
            }
            catch (error) {
                console.error('AI analysis failed:', error);
                // Continue without AI analysis
            }
        }
        // Store results for the report page
        await chrome.storage.local.set({
            scanContext: scanContext,
            aiAnalysis: aiAnalysis,
            scanTime: new Date().toISOString()
        });
        // Update stats
        document.getElementById('totalCookies').textContent = analysis.totalCookies.toString();
        document.getElementById('thirdParty').textContent = analysis.thirdPartyCount.toString();
        document.getElementById('securityIssues').textContent = analysis.securityIssues.toString();
        document.getElementById('privacyConcerns').textContent = analysis.privacyConcerns.toString();
        statsDiv.classList.add('visible');
        // Show success message
        statusDiv.className = 'success';
        statusDiv.textContent = `Found ${analysis.totalCookies} cookies. ${analysis.abnormalities.length} issues detected.`;
        // Open results page after a short delay
        setTimeout(() => {
            chrome.tabs.create({ url: 'report.html' });
        }, 500);
    }
    catch (error) {
        statusDiv.className = 'error';
        statusDiv.textContent = 'Error: ' + error.message;
    }
    finally {
        // Re-enable buttons
        scanBtn.disabled = false;
        scanCurrentBtn.disabled = false;
    }
}
//# sourceMappingURL=popup.js.map
