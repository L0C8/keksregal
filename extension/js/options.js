"use strict";
// Options page script
document.addEventListener('DOMContentLoaded', async () => {
    // Load saved settings
    const settings = await chrome.storage.local.get(['openaiApiKey', 'enableAI']);
    if (settings.openaiApiKey) {
        document.getElementById('apiKey').value = settings.openaiApiKey;
    }
    document.getElementById('enableAI').checked = settings.enableAI !== false;
});
document.getElementById('saveBtn').addEventListener('click', async () => {
    const apiKey = document.getElementById('apiKey').value.trim();
    const enableAI = document.getElementById('enableAI').checked;
    const statusDiv = document.getElementById('status');
    try {
        // Validate API key format
        if (apiKey && !apiKey.startsWith('sk-')) {
            statusDiv.className = 'error';
            statusDiv.textContent = 'Invalid API key format. OpenAI keys start with "sk-"';
            return;
        }
        // Save settings
        await chrome.storage.local.set({
            openaiApiKey: apiKey,
            enableAI: enableAI
        });
        statusDiv.className = 'success';
        statusDiv.textContent = '✓ Settings saved successfully!';
        // Clear success message after 3 seconds
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 3000);
    }
    catch (error) {
        statusDiv.className = 'error';
        statusDiv.textContent = 'Error saving settings: ' + error.message;
    }
});
//# sourceMappingURL=options.js.map