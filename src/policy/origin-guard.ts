/**
 * Sensitive Origin Blocklist & Sandbox Guard.
 * Blocks internal browser schemes, local file access, dangerous URL schemes,
 * banking/password-manager/auth endpoints, and localhost credential endpoints.
 */

export interface OriginGuardOptions {
  /** Additional user-defined origins or regexes to deny. */
  customBlockedOrigins?: ReadonlyArray<string | RegExp>;
  /** User-defined host/origin allowlist for overriding domain/auth heuristics (never overrides dangerous/browser schemes). */
  customAllowedOrigins?: ReadonlyArray<string | RegExp>;
}

export interface OriginSafetyResult {
  allowed: boolean;
  verdict: 'allow' | 'deny';
  triggeredRule?: string;
  reason?: string;
  normalizedOrigin?: string;
  isDangerousScheme?: boolean;
  isSensitiveOrigin?: boolean;
}

const DANGEROUS_SCHEME_REGEX =
  /^(?:javascript|vbscript):|^data:(?:text\/html|application\/xhtml\+xml|image\/svg\+xml)/i;

const BROWSER_SANDBOX_SCHEME_REGEX =
  /^(?:chrome|chrome-extension|edge|devtools|view-source|about|file|moz-extension):/i;

const CLOUD_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  '100.100.100.200',
]);

const PASSWORD_MANAGER_HOSTS = [
  /(?:^|\.)1password\.com$/i,
  /(?:^|\.)bitwarden\.com$/i,
  /(?:^|\.)lastpass\.com$/i,
  /(?:^|\.)dashlane\.com$/i,
  /(?:^|\.)keepersecurity\.com$/i,
  /(?:^|\.)nordpass\.com$/i,
  /(?:^|\.)roboform\.com$/i,
  /^pass\.proton\.me$/i,
];

const BANKING_PAYMENT_PATTERNS = [
  /(?:^|\.)(?:chase|bankofamerica|wellsfargo|citibank|capitalone|usbank|pnc|hsbc|barclays|schwab|fidelity|vanguard|paypal|venmo|wise|revolut)\.com$/i,
  /(?:^|\.)(?:bank|banking|onlinebanking)\./i,
];

const AUTH_SSO_HOSTS = [
  /^accounts\.google\.com$/i,
  /^login\.microsoftonline\.com$/i,
  /^login\.live\.com$/i,
  /^appleid\.apple\.com$/i,
  /(?:^|\.)auth0\.com$/i,
  /(?:^|\.)okta\.com$/i,
  /(?:^|\.)onelogin\.com$/i,
  /(?:^|\.)duosecurity\.com$/i,
];

const SENSITIVE_AUTH_PATH_REGEX =
  /(?:^|\/)(?:oauth2?|auth\/(?:login|token|callback)|signin|login|sso|reset-password|settings\/(?:security|tokens)|dashboard\/apikeys)(?:\/|$|\?)/i;

const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1', '0.0.0.0']);

const LOCALHOST_CREDENTIAL_PATH_REGEX =
  /(?:auth|login|signin|token|credential|credentials|secret|secrets|password|api[-_]?key|apikey|admin|\.env|vault|session|cookie)/i;

const URL_SCHEME_SCAN_REGEX =
  /\b(?:https?|chrome|chrome-extension|edge|devtools|view-source|about|file|javascript|vbscript|data):[^\s"'`<>)]+/gi;

function stripControlChars(input: string): string {
  return input.replace(/[\u0000-\u0020\u007F]/g, '').trim();
}

function matchesRuleList(
  candidate: string,
  rules?: ReadonlyArray<string | RegExp>,
): boolean {
  if (!rules || rules.length === 0) return false;
  const lower = candidate.toLowerCase();
  for (const rule of rules) {
    if (typeof rule === 'string') {
      const normalizedRule = normalizeOrigin(rule) ?? rule.toLowerCase();
      if (
        lower === normalizedRule.toLowerCase() ||
        lower.startsWith(normalizedRule.toLowerCase())
      ) {
        return true;
      }
    } else if (rule.test(candidate)) {
      return true;
    }
  }
  return false;
}

/**
 * Normalizes a URL string to its canonical origin (scheme + host + optional port).
 */
export function normalizeOrigin(rawUrl: string): string | null {
  const cleaned = stripControlChars(rawUrl);
  if (!cleaned) return null;
  try {
    const parsed = new URL(cleaned);
    if (parsed.origin && parsed.origin !== 'null') {
      return parsed.origin.toLowerCase();
    }
    return `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}`;
  } catch {
    return null;
  }
}

/**
 * Recursively extracts URL-like strings from tool arguments.
 */
export function extractUrlsFromArguments(args: Record<string, unknown>): string[] {
  const urls = new Set<string>();
  const urlKeys = new Set([
    'url',
    'targeturl',
    'href',
    'uri',
    'endpoint',
    'src',
    'link',
    'origin',
    'redirecturi',
    'callbackurl',
  ]);

  const visit = (node: unknown, keyHint?: string): void => {
    if (typeof node === 'string') {
      const trimmed = node.trim();
      if (!trimmed) return;

      if (
        keyHint &&
        urlKeys.has(keyHint.toLowerCase()) &&
        /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(stripControlChars(trimmed))
      ) {
        urls.add(trimmed);
      }

      const matches = trimmed.match(URL_SCHEME_SCAN_REGEX);
      if (matches) {
        for (const m of matches) {
          urls.add(m);
        }
      }

      // Also catch obfuscated `java\nscript:` or `data:text/html` at start of value
      const compact = stripControlChars(trimmed);
      if (DANGEROUS_SCHEME_REGEX.test(compact) || BROWSER_SANDBOX_SCHEME_REGEX.test(compact)) {
        urls.add(compact);
      }
      return;
    }

    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }

    if (typeof node === 'object' && node !== null) {
      for (const [k, v] of Object.entries(node)) {
        visit(v, k);
      }
    }
  };

  visit(args);
  return [...urls];
}

/**
 * Evaluates a single URL or origin against the Sensitive Origin Blocklist & Sandbox Guard.
 */
export function inspectOriginSafety(
  rawUrlOrOrigin: string,
  options: OriginGuardOptions = {},
): OriginSafetyResult {
  const compact = stripControlChars(rawUrlOrOrigin);
  if (!compact) {
    return { allowed: true, verdict: 'allow' };
  }

  // 1. Dangerous executable / injection URL schemes (never allowlistable)
  if (DANGEROUS_SCHEME_REGEX.test(compact)) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'dangerous-url-scheme',
      reason: `Blocked dangerous URL scheme in "${compact.slice(0, 64)}".`,
      isDangerousScheme: true,
    };
  }

  // 2. Privileged internal browser / local filesystem schemes (never allowlistable)
  if (BROWSER_SANDBOX_SCHEME_REGEX.test(compact)) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'sensitive-origin-blocklist',
      reason: `Blocked privileged browser/local origin "${compact.slice(0, 80)}".`,
      isSensitiveOrigin: true,
    };
  }

  // 3. Extensible user blocklist rules
  if (matchesRuleList(compact, options.customBlockedOrigins)) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'custom-blocked-origin',
      reason: `Origin "${compact}" matched user-configured blocklist rule.`,
      isSensitiveOrigin: true,
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(compact);
  } catch {
    return { allowed: true, verdict: 'allow' };
  }

  const normalizedOrigin = parsed.origin !== 'null' ? parsed.origin.toLowerCase() : undefined;
  const hostname = parsed.hostname.toLowerCase();
  const fullPath = `${parsed.pathname}${parsed.search}`.toLowerCase();

  // 4. Embedded credentials in URL (e.g., https://user:pass@host)
  if (parsed.username || parsed.password) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'url-embedded-credentials',
      reason: `Blocked URL containing embedded credentials for host "${hostname}".`,
      normalizedOrigin,
      isSensitiveOrigin: true,
    };
  }

  // 5. Cloud instance metadata endpoints
  if (CLOUD_METADATA_HOSTS.has(hostname)) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'sensitive-origin-blocklist',
      reason: `Blocked access to cloud metadata endpoint "${hostname}".`,
      normalizedOrigin,
      isSensitiveOrigin: true,
    };
  }

  // Allow custom user override for domain/auth heuristics (after schemes, credentials & metadata)
  if (
    matchesRuleList(compact, options.customAllowedOrigins) ||
    (normalizedOrigin && matchesRuleList(normalizedOrigin, options.customAllowedOrigins))
  ) {
    return {
      allowed: true,
      verdict: 'allow',
      normalizedOrigin,
    };
  }

  // 6. Localhost / loopback credential & secret endpoints
  if (LOCALHOST_HOSTS.has(hostname) && LOCALHOST_CREDENTIAL_PATH_REGEX.test(fullPath)) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'localhost-credential-endpoint',
      reason: `Blocked access to localhost credential/secret endpoint "${parsed.origin}${parsed.pathname}".`,
      normalizedOrigin,
      isSensitiveOrigin: true,
    };
  }

  // 7. Password managers
  if (PASSWORD_MANAGER_HOSTS.some((re) => re.test(hostname))) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'sensitive-origin-blocklist',
      reason: `Blocked access to password manager origin "${hostname}".`,
      normalizedOrigin,
      isSensitiveOrigin: true,
    };
  }

  // 8. Banking & payment providers
  if (
    BANKING_PAYMENT_PATTERNS.some((re) => re.test(hostname) || re.test(`${hostname}${parsed.pathname}`))
  ) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'sensitive-origin-blocklist',
      reason: `Blocked access to banking/payment origin "${hostname}".`,
      normalizedOrigin,
      isSensitiveOrigin: true,
    };
  }

  // 9. Auth / OAuth / SSO endpoints
  if (
    AUTH_SSO_HOSTS.some((re) => re.test(hostname)) ||
    SENSITIVE_AUTH_PATH_REGEX.test(fullPath)
  ) {
    return {
      allowed: false,
      verdict: 'deny',
      triggeredRule: 'sensitive-origin-blocklist',
      reason: `Blocked access to authentication/OAuth endpoint "${hostname}${parsed.pathname}".`,
      normalizedOrigin,
      isSensitiveOrigin: true,
    };
  }

  return {
    allowed: true,
    verdict: 'allow',
    normalizedOrigin,
  };
}
