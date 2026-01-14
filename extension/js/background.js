"use strict";
// Background service worker for keksregal
// Listen for extension installation
chrome.runtime.onInstalled.addListener(() => {
    console.log('keksregal extension installed');
});
// Optional: Add context menu item
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'analyzeCookies',
        title: 'Analyze Cookies for this Site',
        contexts: ['page']
    });
});
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'analyzeCookies') {
        // Open popup or analysis page
        chrome.action.openPopup();
    }
});
//# sourceMappingURL=background.js.map