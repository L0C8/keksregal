// AI-powered cookie analysis using OpenAI
export class AIAnalyzer {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.apiUrl = 'https://api.openai.com/v1/chat/completions';
    }
    async analyzeCookies(cookies, basicAnalysis) {
        if (!this.apiKey) {
            throw new Error('OpenAI API key not configured');
        }
        // Prepare cookie data for AI (anonymize sensitive values)
        const cookieData = cookies.map(cookie => ({
            name: cookie.name,
            domain: cookie.domain,
            path: cookie.path,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            sameSite: cookie.sameSite || 'unspecified',
            session: cookie.session,
            valueLength: cookie.value ? cookie.value.length : 0,
            expirationDays: cookie.expirationDate ?
                Math.round((cookie.expirationDate - Date.now() / 1000) / (60 * 60 * 24)) : undefined
        }));
        // Create analysis prompt
        const prompt = this.createPrompt(cookieData, basicAnalysis);
        try {
            const response = await fetch(this.apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`
                },
                body: JSON.stringify({
                    model: 'gpt-4o-mini',
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a cybersecurity expert specializing in web privacy and cookie security. Analyze cookie data for abnormalities, security issues, and privacy concerns.'
                        },
                        {
                            role: 'user',
                            content: prompt
                        }
                    ],
                    temperature: 0.7,
                    max_tokens: 1500
                })
            });
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error?.message || 'API request failed');
            }
            const data = await response.json();
            const aiResponse = data.choices[0].message.content;
            return this.parseAIResponse(aiResponse);
        }
        catch (error) {
            console.error('AI Analysis error:', error);
            throw error;
        }
    }
    createPrompt(cookieData, basicAnalysis) {
        return `Analyze the following browser cookies for abnormalities, security issues, and privacy concerns.

COOKIE DATA (${cookieData.length} cookies):
${JSON.stringify(cookieData.slice(0, 100), null, 2)}

${cookieData.length > 100 ? `\n(Note: Showing first 100 of ${cookieData.length} cookies)` : ''}

BASIC ANALYSIS RESULTS:
- Total Cookies: ${basicAnalysis.totalCookies}
- Third-Party Cookies: ${basicAnalysis.thirdPartyCount}
- Security Issues: ${basicAnalysis.securityIssues}
- Privacy Concerns: ${basicAnalysis.privacyConcerns}

TOP ISSUES DETECTED:
${basicAnalysis.abnormalities.slice(0, 10).map((abn) => `- [${abn.severity}] ${abn.cookieName} (${abn.domain}): ${abn.description}`).join('\n')}

Please provide:

1. OVERALL ASSESSMENT (2-3 sentences)
   - General privacy/security posture
   - Most concerning findings

2. UNUSUAL PATTERNS (if any)
   - Any abnormal cookie behavior not typical for normal websites
   - Suspicious naming patterns or unusual domains
   - Potential tracking or fingerprinting techniques

3. TOP SECURITY RISKS (3-5 items)
   - Specific cookies with security concerns
   - Why they're problematic
   - Potential impact

4. PRIVACY RECOMMENDATIONS (3-5 items)
   - Actionable steps to improve privacy
   - Which cookies to consider removing
   - Browser settings to adjust

Format your response in clear sections with headers. Be concise but specific.`;
    }
    parseAIResponse(response) {
        // Parse the AI response into structured data
        const sections = {
            assessment: '',
            unusualPatterns: '',
            securityRisks: [],
            recommendations: []
        };
        // Extract sections using simple text parsing
        const lines = response.split('\n');
        let currentSection = null;
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.includes('OVERALL ASSESSMENT') || trimmed.includes('Overall Assessment')) {
                currentSection = 'assessment';
            }
            else if (trimmed.includes('UNUSUAL PATTERNS') || trimmed.includes('Unusual Patterns')) {
                currentSection = 'unusual';
            }
            else if (trimmed.includes('SECURITY RISKS') || trimmed.includes('Security Risks')) {
                currentSection = 'security';
            }
            else if (trimmed.includes('RECOMMENDATIONS') || trimmed.includes('Recommendations')) {
                currentSection = 'recommendations';
            }
            else if (trimmed) {
                if (currentSection === 'assessment') {
                    sections.assessment += trimmed + ' ';
                }
                else if (currentSection === 'unusual') {
                    sections.unusualPatterns += trimmed + ' ';
                }
                else if (currentSection === 'security' && (trimmed.startsWith('-') || trimmed.match(/^\d+\./))) {
                    sections.securityRisks.push(trimmed.replace(/^[-\d.]\s*/, ''));
                }
                else if (currentSection === 'recommendations' && (trimmed.startsWith('-') || trimmed.match(/^\d+\./))) {
                    sections.recommendations.push(trimmed.replace(/^[-\d.]\s*/, ''));
                }
            }
        }
        return {
            fullResponse: response,
            assessment: sections.assessment.trim(),
            unusualPatterns: sections.unusualPatterns.trim(),
            securityRisks: sections.securityRisks,
            recommendations: sections.recommendations
        };
    }
}
//# sourceMappingURL=ai-analyzer.js.map