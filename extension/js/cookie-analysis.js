export function analyzeCookies(cookies, currentDomain) {
    const analysis = {
        totalCookies: cookies.length,
        cookies: cookies,
        abnormalities: [],
        thirdPartyCount: 0,
        securityIssues: 0,
        privacyConcerns: 0,
        domains: {}
    };
    const duplicates = {};
    cookies.forEach(cookie => {
        // Track duplicates
        const key = cookie.name;
        duplicates[key] = (duplicates[key] || 0) + 1;
        // Track domains
        const domain = cookie.domain;
        analysis.domains[domain] = (analysis.domains[domain] || 0) + 1;
        // Check for third-party cookies
        const isThirdParty = currentDomain ? !domain.includes(currentDomain) && !currentDomain.includes(domain.replace(/^\./, '')) : false;
        if (isThirdParty) {
            analysis.thirdPartyCount++;
            analysis.abnormalities.push({
                type: 'THIRD_PARTY_TRACKER',
                severity: 'high',
                cookieName: cookie.name,
                domain: cookie.domain,
                description: `Third-party cookie from ${cookie.domain}`
            });
        }
        // Check for missing security flags
        if (!cookie.httpOnly) {
            analysis.securityIssues++;
            analysis.abnormalities.push({
                type: 'MISSING_HTTPONLY',
                severity: 'medium',
                cookieName: cookie.name,
                domain: cookie.domain,
                description: 'Missing HttpOnly flag - vulnerable to XSS attacks'
            });
        }
        if (!cookie.secure) {
            analysis.securityIssues++;
            analysis.abnormalities.push({
                type: 'MISSING_SECURE',
                severity: 'high',
                cookieName: cookie.name,
                domain: cookie.domain,
                description: 'Missing Secure flag - can be transmitted over HTTP'
            });
        }
        // Check for excessive lifetime
        if (cookie.expirationDate) {
            const lifetimeDays = (cookie.expirationDate - Date.now() / 1000) / (60 * 60 * 24);
            if (lifetimeDays > 365) {
                analysis.privacyConcerns++;
                analysis.abnormalities.push({
                    type: 'EXCESSIVE_LIFETIME',
                    severity: 'medium',
                    cookieName: cookie.name,
                    domain: cookie.domain,
                    description: `Cookie lifetime exceeds 1 year (${Math.round(lifetimeDays)} days)`
                });
            }
        }
        // Check for large cookies
        if (cookie.value && cookie.value.length > 4096) {
            analysis.privacyConcerns++;
            analysis.abnormalities.push({
                type: 'LARGE_PAYLOAD',
                severity: 'low',
                cookieName: cookie.name,
                domain: cookie.domain,
                description: `Large cookie size (${cookie.value.length} bytes)`
            });
        }
        // Check for suspicious encoding
        if (cookie.value && isSuspiciousEncoding(cookie.value)) {
            analysis.privacyConcerns++;
            analysis.abnormalities.push({
                type: 'SUSPICIOUS_ENCODING',
                severity: 'low',
                cookieName: cookie.name,
                domain: cookie.domain,
                description: 'Cookie contains suspicious encoding patterns'
            });
        }
    });
    // Check for duplicate cookies
    Object.entries(duplicates).forEach(([name, count]) => {
        if (count > 1) {
            analysis.abnormalities.push({
                type: 'DUPLICATE_COOKIE',
                severity: 'low',
                cookieName: name,
                domain: 'multiple',
                description: `Cookie "${name}" appears ${count} times`
            });
        }
    });
    return analysis;
}
function isSuspiciousEncoding(value) {
    if (!value || value.length < 50)
        return false;
    // Check for base64-like patterns
    const base64Pattern = /^[A-Za-z0-9+/=]+$/;
    if (base64Pattern.test(value) && value.length > 50) {
        return true;
    }
    // Check for unusual special characters
    const specialCharCount = (value.match(/[^A-Za-z0-9\s=\-_.]/g) || []).length;
    return specialCharCount > 10;
}
//# sourceMappingURL=cookie-analysis.js.map