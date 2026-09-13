import { scoreFinding } from "../risk-score";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
	id: string;
	ruleId: string;
	severity: Severity;
	title: string;
	description: string;
	filePath?: string;
	lineNumber?: number;
	snippet?: string;
	remediation: string;
	score?: number;
	riskFactors?: string[];
}

export interface ScanRule {
	id: string;
	pattern: RegExp;
	severity: Severity;
	title: string;
	description: string;
	remediation: string;
}

// GitHub Scanner Rules
// Common Supabase/AI backend credential patterns (checked per file path + content)
export const SUPABASE_FILE_PATTERNS = [
	/\.env(?:\.local|\.development|\.production)?$/i,
	/supabase\.ts$/i,
	/supabase[/\\]client/i,
	/lib[/\\]supabase/i,
	/[/\\]config\.ts$/i,
	/[/\\]config\.js$/i,
];

export function checkSupabaseCredentials(
	content: string,
	filePath: string,
): boolean {
	const hasSupabaseFile = SUPABASE_FILE_PATTERNS.some((p) => p.test(filePath));
	if (!hasSupabaseFile) return false;
	// Simple string-based detection for Supabase keys (avoids regex literal issues)
	const lower = content.toLowerCase();
	const indicators = [
		"supabase_anon_key",
		"supabase_service_role_key",
		"supabase_api_key",
		"sb_",
		"anon key",
		"service_role",
	];
	const hasIndicator = indicators.some((i) => lower.includes(i));
	if (!hasIndicator) return false;
	// Check for JWT-like patterns (base64 encoded)
	const jwtPattern =
		/[a-zA-Z0-9_-]{50,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/g;
	const hasJwt = jwtPattern.test(content);
	// Check for long base64-like strings that could be keys
	const longKeyPattern = /["'][a-zA-Z0-9_-]{40,}["']/g;
	const hasLongKey = longKeyPattern.test(content);
	return hasJwt || hasLongKey;
}

// ============== SUPABASE RLS RULES (OWASP A01:2021) ==============

function checkSupabaseRLSMissing(content: string, filePath: string): boolean {
	if (
		!/\.(sql|migration)$/i.test(filePath) &&
		!/supabase[/\\]/.test(filePath) &&
		!/migration/i.test(filePath)
	) {
		return false;
	}
	const hasCreateTable = /CREATE\s+TABLE/i.test(content);
	if (!hasCreateTable) return false;
	const hasRLSKeyword = /row\s*level\s*security|rls/i.test(content);
	if (hasRLSKeyword) {
		return !/ENABLE\s+ROW\s+LEVEL\s+SECURITY/i.test(content);
	}
	return true;
}

function checkOverlyPermissivePolicy(
	content: string,
	filePath: string,
): boolean {
	if (!/\.(sql|ts|tsx)$/i.test(filePath)) return false;
	return /FOR\s+ALL|USING\s*\(\s*true\s*\)|FOR\s+SELECT\s+TO\s+authenticated/i.test(
		content,
	);
}

function checkServiceRoleInClient(content: string, filePath: string): boolean {
	const isServerContext = /\+server\.ts$|api[/\\]|server[/\\]|\.server\./i.test(
		filePath,
	);
	const isBrowserCode = /\.(tsx?|jsx?|page\.tsx?|component\.tsx?)$/i.test(
		filePath,
	);
	if (isBrowserCode && !isServerContext) {
		return /service[_-]?role[_-]?key|serviceRoleKey|SUPABASE_SERVICE_ROLE/i.test(
			content,
		);
	}
	return false;
}

function checkMissingOwnership(content: string, filePath: string): boolean {
	if (!/\.(sql|ts|tsx)$/i.test(filePath)) return false;
	const policyPattern =
		/CREATE\s+POLICY[\s\S]+?USING\s*\([\s\S]+?auth\.uid\(\s*\)/gi;
	const matches = content.match(policyPattern) || [];
	for (const match of matches) {
		if (!/user_id|owner_id|profile_id|profileId/i.test(match)) {
			return true;
		}
	}
	return false;
}

function checkSupabaseRLS(content: string, filePath: string): Finding[] {
	const findings: Finding[] = [];

	if (checkSupabaseRLSMissing(content, filePath)) {
		findings.push({
			id: "SUPABASE-RLS001-rls",
			ruleId: "SUPABASE-RLS001",
			severity: "critical",
			title: "Supabase Table Without RLS Enabled (OWASP A01:2021)",
			description:
				"A database table appears to be created without Row Level Security (RLS) enabled. Without RLS, all authenticated users can access all rows.",
			filePath,
			remediation:
				"Enable RLS on all tables: ALTER TABLE table_name ENABLE ROW LEVEL SECURITY; Create policies for each operation.",
		});
	}

	if (checkOverlyPermissivePolicy(content, filePath)) {
		findings.push({
			id: "SUPABASE-RLS002-policy",
			ruleId: "SUPABASE-RLS002",
			severity: "high",
			title: "Overly Permissive Supabase RLS Policy (OWASP A01:2021)",
			description:
				"An RLS policy allows access to all authenticated users without proper row-level filtering.",
			filePath,
			remediation:
				"Create specific policies that filter by user ownership using auth.uid() = column_name pattern.",
		});
	}

	if (checkServiceRoleInClient(content, filePath)) {
		findings.push({
			id: "SUPABASE-RLS003-service",
			ruleId: "SUPABASE-RLS003",
			severity: "critical",
			title: "Supabase Service Role Key Exposed (OWASP A01:2021)",
			description:
				"Supabase service role key found in client-side code. This bypasses all RLS and grants full database access.",
			filePath,
			remediation:
				"Never use service role key in browser code. Use SUPABASE_ANON_KEY for client-side operations.",
		});
	}

	if (checkMissingOwnership(content, filePath)) {
		findings.push({
			id: "SUPABASE-RLS005-missing-ownership",
			ruleId: "SUPABASE-RLS005",
			severity: "high",
			title: "Missing User Ownership Check in Supabase Policy (OWASP A01:2021)",
			description:
				"RLS policy uses auth.uid() but does not filter by user ownership column.",
			filePath,
			remediation: "Add row ownership check: WHERE auth.uid() = user_id",
		});
	}

	return findings;
}

// ============== OWASP A01:2021 — BROKEN ACCESS CONTROL ==============
// IDOR: API route takes an id from URL/path without ownership check.
function checkIdorRoute(content: string, filePath: string): boolean {
	const isApiRoute = /[/\\]app[\\/]api[\\/][^"'\s]+[/\\]route\.(ts|tsx|js|jsx)/i.test(
		filePath,
	);
	if (!isApiRoute) return false;
	const usesParam = /params\.|req\.params|request\.params|URLSearchParams|searchParams|\.pathname|catch\s*\(\s*\{\s*params\b|\{\s*params\s*:\s*\{\s*id/i.test(
		content,
	);
	if (!usesParam) return false;
	const hasOwnershipCheck = /auth\.uid\(\)|getUser\(|getSession\(|verifyToken|authoriz|ownsThis|userId\s*===|currentUser\.id\s*===/i.test(
		content,
	);
	return !hasOwnershipCheck;
}

// ============== OWASP A02:2021 — CRYPTOGRAPHIC FAILURES ==============
// Use of broken hash algorithms (md5/sha1) for password or token storage.
function checkWeakHashing(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	const hasHash = /crypto\.createHash|require\(['"]crypto['"]\)|from\s+['"]crypto['"]|hashlib\./i.test(
		content,
	);
	if (!hasHash) return false;
	return /\bmd5\b|\bsha1\b/i.test(content);
}

// Plaintext password storage in a DB schema or migration file.
function checkPlaintextPasswordColumn(content: string, filePath: string): boolean {
	if (!/\.(sql|prisma|ts|tsx|js|jsx)$/i.test(filePath)) return false;
	const hasPasswordColumn = /(password|passwd|pwd)\s+(varchar|text|string|String)/i.test(
		content,
	);
	const hasHashingHint = /\b(bcrypt|argon2|scrypt|crypt)\b/i.test(content);
	return hasPasswordColumn && !hasHashingHint;
}

// ============== OWASP A04:2021 — INSECURE DESIGN ==============
// Hardcoded role check without server-side enforcement hint.
function checkHardcodedRoleCheck(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	return /role\s*[!=]==\s*['"](?:admin|root|superuser|owner)['"]/i.test(content);
}

// ============== OWASP A07:2021 — IDENTIFICATION & AUTH FAILURES ==============
// JWT signed without expiry ("expiresIn") claim or no exp validation.
function checkJwtMissingExpiry(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	const usesJwt =
		/jwt\.sign|jwt\.verify|jsonwebtoken|@nestjs\/jwt|fastify-jwt|express-jwt/i.test(
			content,
		);
	if (!usesJwt) return false;
	const hasExpiry = /expiresIn|exp\s*:|jwt\.options|jwtid|exp\s*\)/i.test(content);
	return !hasExpiry;
}

// Cookie set without Secure/HttpOnly/SameSite flags.
function checkInsecureCookie(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	const setsCookie = /res\.cookie\(|cookies\.set\(|setCookie\(|document\.cookie\s*=/i.test(
		content,
	);
	if (!setsCookie) return false;
	const hasFlags = /httpOnly\s*:\s*true|secure\s*:\s*true|sameSite\s*:\s*['"](?:lax|strict|none)['"]|SameSite\s*=\s*(?:Lax|Strict)/i.test(
		content,
	);
	return !hasFlags;
}

// ============== OWASP A08:2021 — SOFTWARE & DATA INTEGRITY FAILURES ==============
// Use of dangerous deserializers (node-serialize, eval, yaml.load).
function checkUnsafeDeserialization(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	return /require\(['"]node-serialize['"]\)|require\(['"]serialize-javascript['"]\)|yaml\.load\(|pickle\.loads|yaml\.unsafe_load|JSON\.parse\(\s*req\.body/i.test(
		content,
	);
}

// ============== OWASP A09:2021 — SECURITY LOGGING & MONITORING FAILURES ==============
// Auth route that returns success but has no logging hook nearby.
function checkAuthRouteWithoutLogging(content: string, filePath: string): boolean {
	if (!/[/\\]app[\\/]api[\\/](?:login|auth|signin|signup|register|reset-password|verify)/i.test(filePath)) {
		return false;
	}
	const hasLogger = /logger\.|pino\.|winston\.|console\.(info|warn|error|log)|sentry|captureMessage|breadcrumb/i.test(
		content,
	);
	return !hasLogger;
}

// ============== OWASP A10:2021 / 2025 — SSRF & EXCEPTIONAL CONDITIONS ==============
// User-controlled URL passed to fetch / axios / http without allowlist.
function checkPotentialSsrf(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	const fetchesUserUrl =
		/(?:fetch|axios\.(?:get|post|put|delete|request)|got\(|http\.get|https\.get)\s*\(\s*(?:req\.body|req\.query|req\.params|params\.|searchParams|userUrl|targetUrl|inputUrl|url)/i.test(
			content,
		);
	if (!fetchesUserUrl) return false;
	const hasAllowlist = /allowlist|allowList|allowedHosts|allowedDomains|isPrivateIp|ipRange|denyPrivate|validateUrl|safeUrl|isAllowedUrl/i.test(
		content,
	);
	return !hasAllowlist;
}

// Unhandled promise rejection / unsafe await that swallows errors.
function checkSwallowedErrors(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	return /\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)|\.catch\s*\(\s*\(\)\s*=>\s*null\s*\)/i.test(
		content,
	);
}

// ============== XSS PREVENTION (OWASP Cheat Sheet) ==============
// Use of Function() constructor or setTimeout/setInterval with string body.
function checkCodeInjectionSink(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	return /new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['"`]|setImmediate\s*\(\s*['"`]/i.test(
		content,
	);
}

// ============== SQL INJECTION PREVENTION (OWASP Cheat Sheet) ==============
// Prisma raw queries that interpolate parameters instead of using $queryRaw template.
function checkPrismaRawInjection(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	return /\$executeRaw\s*\(\s*[`'"][^`'"]*\$\{|Prisma\.sql\s*\(\s*[`'"][^`'"]*\bSELECT\b[^`'"]*\$\{/i.test(
		content,
	);
}

// ============== CRYPTO / SECRETS (hardening beyond existing rules) ==============
// Hardcoded fallback secret in process.env check (anti-pattern).
function checkHardcodedSecretFallback(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	return /process\.env\.[A-Z_]+\s*\|\|\s*['"][A-Za-z0-9_\-]{12,}['"]/i.test(content);
}

// ============== CSRF (OWASP Cheat Sheet) ==============
// Next.js / Express form handler that mutates state but never checks CSRF token.
function checkMutatingRouteWithoutCsrf(content: string, filePath: string): boolean {
	if (!/\.(ts|tsx|js|jsx)$/i.test(filePath)) return false;
	const isMutating =
		/export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b|router\.post\(|router\.put\(|router\.delete\(|router\.patch\(/i.test(
			content,
		);
	if (!isMutating) return false;
	const hasCsrf =
		/csrf|csrfToken|csurf|samesite-token|origin\s*===|verifyCsrf|x-csrf-token/i.test(
			content,
		);
	return !hasCsrf;
}

export const GITHUB_SCANNER_RULES: ScanRule[] = [
	{
		// Sentinel rule — never pattern-matched. The actual finding is
		// emitted by src/lib/scanners/known-cves.ts (scanKnownCves) which
		// is wired into src/lib/scanners/github.ts after the package.json
		// extraction step. Registered here so the ruleId shows up in
		// tooling / dashboards / tests that introspect GITHUB_SCANNER_RULES.
		id: "KNOWN_CVE",
		pattern: /(?!)/,
		severity: "high",
		title: "Known CVE Match (Sentinel-Bench top-100)",
		description:
			"A dependency declared in package.json matches a CVE in the Sentinel-Bench top-100 feed.",
		remediation: "Update the affected dependency to a patched version.",
	},
	{
		// Same — KEV variant. Severity bumped to critical.
		id: "KNOWN_CVE_KEV",
		pattern: /(?!)/,
		severity: "critical",
		title: "Known CVE Match — CISA KEV (Sentinel-Bench top-100)",
		description:
			"A dependency matches a CVE that appears on the CISA Known Exploited Vulnerabilities catalog.",
		remediation: "Patch immediately — this CVE is being exploited in the wild.",
	},
	{
		// Same — PoC variant. Severity critical when a public PoC exists.
		id: "KNOWN_CVE_WITH_POC",
		pattern: /(?!)/,
		severity: "critical",
		title: "Known CVE Match — Public PoC Available (Sentinel-Bench top-100)",
		description:
			"A dependency matches a CVE that has a publicly available proof-of-concept exploit.",
		remediation: "Patch immediately — exploit code is public and weaponization is trivial.",
	},
	{
		id: "SUPABASE001",
		pattern:
			/(?:SUPABASE|supabase)[_-]?(?:ANON|SERVICE[_-]?ROLE|KEY|URL)[^\n]{0,50}["'][a-zA-Z0-9_-]{20,}["']/gi,
		severity: "critical",
		title: "Exposed Supabase Credentials",
		description:
			"Hardcoded Supabase API keys or service role keys found in source code. This allows full database access bypassing RLS policies.",
		remediation:
			"Use environment variables: process.env.SUPABASE_KEY. Never commit Supabase anon/service keys to version control. Add .env to .gitignore and use a secrets manager for production.",
	},
	{
		id: "CSRF001",
		pattern:
			/(?:csrf|_csrf|xsrf|xsrf-token|csrftoken)[^\n]{0,50}?(?:missing|not.?found|no.?token|undefined|null)/gi,
		severity: "critical",
		title: "Missing CSRF Protection",
		description:
			"Potential missing CSRF protection detected. Forms or state-changing operations may be vulnerable to Cross-Site Request Forgery attacks. Found in 70% of vibe-coded apps.",
		remediation:
			"Implement CSRF tokens for all state-changing requests. Use the SameSite=Strict/Lax cookie attribute. Libraries like csurf (Express) or built-in framework CSRF protection can help.",
	},
	{
		id: "SUPPLY001",
		pattern:
			/(?:"dependencies"|'dependencies')[\s\S]{0,3000}?"(?!node_modules|npm|typescript|react|next|vite|webpack|eslint|prettier|tailwind|@)[a-zA-Z0-9@_+./-]{1,50}"[\s:]+["0-9^~>=<.-]+/gi,
		severity: "high",
		title: "Suspicious Package Name (Slopsquatting Risk)",
		description:
			"A package dependency name looks suspicious — it may be an AI-hallucinated package name (slopsquatting). Attackers can register these non-existent package names to inject malware when developers run npm install.",
		remediation:
			"Verify each dependency exists in the official npm registry (npmjs.com). Remove unknown packages. Use package-lock.json to lock versions. Consider using tools like npm-audit or Snyk to validate dependencies.",
	},
	{
		id: "ERRHAND001",
		pattern:
			/(?:stack[_-]?trace|stacktrace|error[_-]?stack|exception[_-]?trace)[^\n]{0,100}?(?:in|at|on|line)[^\n]{0,50}?\.(?:js|ts|tsx|jsx|py|rb|go|java|cs|php)/gi,
		severity: "high",
		title: "Exposed Stack Trace in Code",
		description:
			"Stack trace or debug error information found in source code. Exposing stack traces in production leaks framework version, internal paths, and code structure (OWASP A10:2025 - Mishandling of Exceptional Conditions).",
		remediation:
			"Remove stack traces from production code. Use structured error logging instead of printing errors directly. Implement global error handlers that return generic error messages to users.",
	},
	{
		id: "SEC-001",
		pattern:
			/(?:api[_-]?key|apikey|api_secret|apiSecret)[^\n]{0,50}["']?(sk-|pk-|AIza|ghp_|gho_|eyJ|_[A-Z])[a-zA-Z0-9]{20,}/gi,
		severity: "critical",
		title: "API Key Detected",
		description:
			"Potential API key or secret found in code. This could allow unauthorized access to services.",
		remediation:
			"Remove API keys from code immediately. Use environment variables instead: process.env.API_KEY",
	},
	{
		id: "SEC-002",
		pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi,
		severity: "critical",
		title: "Private Key Detected",
		description:
			"Private cryptographic key found in source code. This is a critical security risk.",
		remediation:
			"Remove private keys from code immediately. Store them securely in environment variables or a secrets manager.",
	},
	{
		id: "SEC-003",
		pattern: /\.env(?:\.local|\.development|\.production)?/gi,
		severity: "critical",
		title: ".env File Reference",
		description:
			"Reference to .env file detected. Verify it is not committed to the repository.",
		remediation:
			"Ensure .env files are in .gitignore and never committed. Use git-secrets or similar tools to prevent accidental commits.",
	},
	{
		id: "SEC-004",
		pattern: /(?:password|passwd|pwd|secret)[^\n]{0,30}["'][^"']{6,32}["']/gi,
		severity: "high",
		title: "Hardcoded Password",
		description:
			"Potential hardcoded password found. Credentials should never be in source code.",
		remediation:
			"Move passwords to environment variables: process.env.DB_PASSWORD or use a secrets manager.",
	},
	{
		id: "SEC-006",
		pattern: /\beval\s*\(/gi,
		severity: "high",
		title: "Eval Usage Detected",
		description:
			"Use of eval() detected. This can execute arbitrary code and is a major security risk.",
		remediation:
			"Replace eval() with safer alternatives. Use JSON.parse() for JSON, or restructure code to avoid dynamic execution.",
	},
	{
		id: "SEC-007",
		pattern: /console\.(log|debug|info|warn|error)\s*\(/gi,
		severity: "low",
		title: "Console Statement",
		description:
			"Debug console statement found in code. Should be removed before production.",
		remediation:
			"Remove console statements or use a logging library with proper log levels for production.",
	},
	{
		id: "SEC-008",
		pattern:
			/["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?(?:FROM|INTO|WHERE|TABLE).*?["'][+\s]/gi,
		severity: "critical",
		title: "SQL Injection Pattern",
		description:
			"Potential SQL injection vulnerability. User input may be concatenated directly into SQL queries.",
		remediation:
			"Use parameterized queries or an ORM. Never concatenate user input directly into SQL strings.",
	},
	{
		id: "SEC-009",
		pattern: /(?:innerHTML|dangerouslySetInnerHTML|document\.write\s*\()/gi,
		severity: "high",
		title: "XSS Vulnerability Pattern",
		description:
			"Potential XSS vulnerability. User input may be rendered without sanitization.",
		remediation:
			"Sanitize user input before rendering. Use textContent instead of innerHTML, or use a sanitization library like DOMPurify.",
	},
	{
		id: "SEC-010",
		pattern: /Access-Control-Allow-Origin[^\n]*[*:]/gi,
		severity: "high",
		title: "Permissive CORS Configuration",
		description:
			"CORS is configured to allow all origins (*). APIs allowing credentials with wildcard origin are vulnerable to cross-site request forgery. Wildcard origins also allow any website to make requests to your API (CWE-942: Permissive Cross-Domain Whitelist).",
		remediation:
			"Restrict CORS to specific trusted origins. Never use * with Access-Control-Allow-Credentials: true. Use environment variables to configure allowed origins: app.use(cors({ origin: process.env.ALLOWED_ORIGIN })).",
	},
	{
		id: "SEC-011",
		pattern:
			/__VUE__|Vue\.config\.devtools\s*=\s*true|vue-devtools|enableProdPreview|__VUE_OPTIONS_API__|__VUE_PROD_DEVTOOLS__/gi,
		severity: "high",
		title: "Vue Devtools or Debug Mode Enabled in Production",
		description:
			"Vue app exposes development tools or has debug mode enabled in production. __VUE__ global, Vue.config.devtools=true, or Vue Devtools integration found in code served to browsers, allowing attackers to inspect component state and potentially inject code.",
		remediation:
			"In Vue 3: set Vue.config.devtools = false in production. Ensure process.env.NODE_ENV === 'production' to disable all dev tools. Remove any __VUE_OPTIONS_API__ or __VUE_PROD_DEVTOOLS__ flags set to true.",
	},
	{
		id: "SEC-012",
		pattern:
			/__REACT_DEVTOOLS_GLOBAL_HOOK__|window\.__REDUX_DEVTOOLS_EXTENSION__|reduxDevtools|enableDevTools\s*[=:]/gi,
		severity: "high",
		title: "React/Redux DevTools Enabled in Production",
		description:
			"React DevTools or Redux DevTools global hook is exposed in production code. Attackers can use these to inspect component tree, state, and props of a live production application.",
		remediation:
			"Remove __REACT_DEVTOOLS_GLOBAL_HOOK__ references from production builds. Ensure devtools are only included in development builds. Use environment checks: if (process.env.NODE_ENV !== 'production') { /* devtools */ }",
	},
	{
		id: "SEC-013",
		pattern:
			/ng\.probe|enableDebugTools|\.productionMode\s*=\s*false|platformBrowser\.dynamic|BrowserModule\.withServerTransition|Angular\.module.*\.debug|provide\(.*Angular.*debug/i,
		severity: "high",
		title: "Angular Debug Tools Enabled in Production",
		description:
			"Angular debug tools or production mode disabled in code. ng.probe(), enableDebugTools(), or productionMode=false found, allowing attackers to access component injectors and manipulate application state.",
		remediation:
			"Ensure enableProdMode() is called in production builds to disable Angular debug tools. Remove any references to ng.probe or enableDebugTools from production code.",
	},
	{
		id: "SEC-014",
		pattern: /(\.git\/config|\.git\/HEAD|\.git\/index|\.git\/ORIG_HEAD)/gi,
		severity: "critical",
		title: "Exposed .git Directory or Metadata",
		description:
			"Reference to .git directory internals detected. If the .git directory is publicly accessible, attackers can download the entire source code, commit history, and potentially sensitive configuration. This is a critical information disclosure (CWE-552).",
		remediation:
			'Block access to the .git directory in your web server configuration. Ensure .git is not in the public document root. Use: nginx: location ~ /.git { deny all; } or Apache: <Directory ~ ".git"> Require all denied </Directory>',
	},
	{
		id: "SEC-015",
		pattern:
			/(?:debug\s*[=:]\s*true|DEBUG\s*[=:]\s*true|process\.env\.DEBUG|app\.use\(require\('express'\)\.logger|connect\.logger| Morgan|\.enable\('cors'\)|cors\s*\.\s*enabled|helmet\.csp\s*\.\s*disabled)/gi,
		severity: "high",
		title: "Debug Mode or Verbose Logging Enabled",
		description:
			"Debug mode, verbose logging, or security middleware disabled detected in code. Debug endpoints or verbose logging in production can leak sensitive request data, internal paths, and stack traces (OWASP A10:2025).",
		remediation:
			"Disable debug mode in production: process.env.NODE_ENV = 'production'. Remove verbose logging (Morgan, connect.logger) from production. Ensure helmet.js CSP and other security middleware are not disabled.",
	},
	{
		id: "SEC-016",
		pattern:
			/(\.env\.local|\.env\.development|\.env\.test|\.env\.production\.local)/gi,
		severity: "critical",
		title: "Local Environment File Reference",
		description:
			"Reference to local environment files (.env.local, .env.development) detected. These files may contain machine-specific credentials, API keys, or secrets that should never be committed. .env.local takes precedence over .env and is meant for machine-specific overrides.",
		remediation:
			"Ensure .env.local is in .gitignore. Never commit .env.local to version control. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) for production secrets.",
	},
	{
		id: "SEC-017",
		pattern:
			/(config\.ya?ml|config\.json)[^\n]{0,100}?(?:aws|secret|password|token|api[_-]?key|credential|private|db_)/gi,
		severity: "critical",
		title: "Configuration File May Contain Secrets",
		description:
			"A config.yml or config.json file is referenced near sensitive keywords (secret, password, token, api_key, aws, credential). Configuration files may be publicly accessible or committed to version control, leaking infrastructure secrets.",
		remediation:
			"Move all secrets from config files to environment variables. Ensure config files are in .gitignore. Use secret management systems for production deployments. Never hardcode credentials in config files.",
	},
	{
		id: "SEC-018",
		pattern:
			/(?:X-Content-Type-Options|x-content-type-options)[^\n]{0,50}?(?:noheader|missing|not.?set|none|false)/gi,
		severity: "medium",
		title: "X-Content-Type-Options Explicitly Disabled",
		description:
			"X-Content-Type-Options is explicitly set to an insecure value or disabled. Without nosniff, browsers may MIME-sniff responses and execute content as a different type, enabling XSS via content-type confusion attacks.",
		remediation:
			"Set X-Content-Type-Options: nosniff on all responses. Ensure this header is not removed or set to empty/0.",
	},
	{
		id: "SEC-019",
		pattern:
			/(?:process\.env\.|getenv\(|os\.environ|\$\{.*\})[^\n]{0,100}?(?:DEBUG|debug|verbose|log[_-]?level|log[_-]?enabled)/gi,
		severity: "low",
		title: "Debug Environment Variables Referenced",
		description:
			"Debug-related environment variables (DEBUG, VERBOSE, LOG_LEVEL) are referenced in code. While not directly harmful, debug flags in production can enable verbose logging that leaks sensitive information.",
		remediation:
			"Use structured logging with appropriate log levels. Ensure DEBUG=false and LOG_LEVEL=error/warn in production environments. Review logs before shipping.",
	},
	{
		id: "ERRHAND002",
		pattern:
			/(?:disableExpressErrorHandler|app\.use\(errorHandler\)|errorHandler\s*[=:]\s*false|process\.on\s*\(\s*['"]uncaughtException|process\.on\s*\(\s*['"]unhandledRejection)[^\n]{0,100}?(?:false|null|0|disabled|skip)/gi,
		severity: "high",
		title: "Global Exception Handler Disabled or Bypassed",
		description:
			"Global exception/error handlers are disabled, skipped, or set to no-op. Without proper error handling, uncaught exceptions crash the process and may expose stack traces, internal state, or configuration details to users (OWASP A10:2025).",
		remediation:
			"Always implement global error handlers that log details server-side and return generic error messages to users. Never set error handlers to false, null, or skip them in production.",
	},
	{
		id: "CORS002",
		pattern:
			/(?:Access-Control-Allow-Credentials\s*[=:]|credentials\s*[=:])[^\n]{0,50}?true[^\n]{0,50}?(?:Access-Control-Allow-Origin|origin)[^\n]{0,50}?\*/gi,
		severity: "critical",
		title: "CORS Allows Credentials with Wildcard Origin",
		description:
			"Access-Control-Allow-Credentials is set to true while Access-Control-Allow-Origin is *. This is a critical CORS misconfiguration — browsers will reject this combination, but if a workaround is used, it allows any website to send authenticated requests to your API (CWE-346).",
		remediation:
			"Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Use a specific origin string or implement dynamic origin validation: origin: (origin, cb) => cb(null, allowedOrigins.includes(origin))",
	},
	{
		id: "AUTH001",
		pattern:
			/(?:jwt\.sign|jwt\.verify|sign\(.*\)[:.]|jsonwebtoken)[^\n]{0,100}?(?:algorithm\s*[=:]|ALGORITHM)[^\n]{0,50}?(?:HS256|HS512|'none'|none|"none")/gi,
		severity: "critical",
		title: "JWT Algorithm Confusion or None Algorithm",
		description:
			"JWT (JSON Web Token) code uses a weak or misconfigured algorithm. Using 'none' algorithm allows attackers to forge tokens. Using symmetric keys (HS*) with asymmetric algorithms exposes the secret. This can lead to complete authentication bypass (CWE-347).",
		remediation:
			"Use RS256 or ES256 algorithm for JWTs. Never accept the 'none' algorithm. Never use HS256 with a public key. Validate algorithm matches expected type. Use a library like jose that prevents algorithm confusion attacks.",
	},
	{
		id: "RATE001",
		pattern:
			/(?:rateLimit|ratelimit|rate[_-]?limit|throttle|maxReq|max[_-]?requests)[^\n]{0,50}?(?:disabled|false|null|0|no[_-]?limit|unlimited|infinity)/gi,
		severity: "high",
		title: "Rate Limiting Explicitly Disabled",
		description:
			"Rate limiting is explicitly disabled or set to unlimited. Without rate limiting, endpoints are vulnerable to brute force attacks, API abuse, and denial of service (OWASP A04:2021/A07:2023).",
		remediation:
			"Enable rate limiting on all public endpoints, especially authentication, search, and data retrieval endpoints. Use libraries like express-rate-limit or a WAF. Set reasonable limits based on expected legitimate usage.",
	},

	// ============== SUPPLY CHAIN RULES (A03:2025 & A06:2021) ==============
	{
		id: "SUPPLY001-TYPO",
		pattern:
			/\b(reacct|reacect|reacxt|reactt|reakt|reajct|reavt|reacet|recat)\b[\s":]*[~^]?[0-9]/gi,
		severity: "high",
		title: "Typo-squatting Package Detected (Slopsquatting)",
		description:
			'A package name that looks like a typo of a popular library (e.g., "reacct" instead of "react"). Attackers register these look-alike packages to inject malware via typosquatting/slopsquatting attacks (OWASP A03:2025).',
		remediation:
			"Verify the package name is correct. Check npmjs.com to confirm the package exists with that exact name. Use exact versions and review package.json before npm install.",
	},
	{
		id: "SUPPLY002",
		pattern:
			/"(dependencies|devDependencies)"[\s\S]{0,5000}?"[a-z][a-z0-9_-]{2,30}"[\s:]+["'][^~][0-9]/gi,
		severity: "medium",
		title: "Unpinned Dependencies (Version Range Risk)",
		description:
			"Dependencies use version ranges (^, ~, >=) instead of exact versions. Attackers can publish malicious versions within the allowed range, leading to supply chain attacks (CWE-1104).",
		remediation:
			'Pin dependencies to exact versions in package.json. Use "1.2.3" instead of "^1.2.3". Regenerate package-lock.json and commit it. Consider using npm install --save-exact for new installs.',
	},
	{
		id: "SUPPLY003",
		pattern:
			/"(?:preinstall|postinstall|preuninstall|postuninstall|prepublish|postpublish|prepare|postprepare)"\s*:\s*"[^"]*\$\(|\$\{|`|;\s*(?:rm|wget|curl|npm|yarn)/gi,
		severity: "critical",
		title: "Shell Injection in npm Scripts",
		description:
			"npm lifecycle scripts contain potential shell injection patterns ($(...), `...`, or external curl/wget). Malicious packages can execute arbitrary code during npm install (OWASP A03:2025).",
		remediation:
			"Remove shell injection patterns from package.json scripts. Never use user input in scripts. If you must use external scripts, download and verify them first. Never pipe curl output directly to shell.",
	},
	{
		id: "SUPPLY004",
		pattern:
			/(?:_auth|_authToken|access-token|password)\s*=\s*["'][a-zA-Z0-9+/=]{20,}["']|registry[\s\n]*.*_auth\s*=/gi,
		severity: "critical",
		title: ".npmrc Contains Credentials",
		description:
			".npmrc file contains authentication credentials (_auth or registry _auth). If committed to version control, attackers can steal npm credentials and publish malicious packages under your account (OWASP A03:2025).",
		remediation:
			"Remove credentials from .npmrc. Use npm login with proper auth tokens stored securely. Set .npmrc to use environment variables: //registry.npmjs.org/:_authToken=${NPM_TOKEN}. Never commit .npmrc with credentials.",
	},
	{
		id: "SUPPLY005",
		pattern:
			/(?:package\.json)[\s\S]{0,200}?(?:"dependencies"|"scripts"|"engines")[\s\S]{0,500}?(?!(?:package-lock|yarn\.lock|pnpm-lock))"[a-z]/gi,
		severity: "medium",
		title: "Lock File Missing",
		description:
			"package.json exists but no lock file (package-lock.json, yarn.lock, or pnpm-lock.yaml) is detected. Without lock files, npm install can resolve dependencies to different versions, including malicious ones (CWE-1104).",
		remediation:
			"Run npm install to generate package-lock.json, or use yarn.lock / pnpm-lock.yaml. Commit the lock file. Use npm ci (not npm install) in CI/CD to ensure reproducible builds.",
	},
	{
		id: "DEP001",
		pattern:
			/"(?:lodash|moment|axios|express|qs|underscore|request|node-fetch)"\s*:\s*"[<>~^]?(?:0\.[0-9]|1\.[0-5]|4\.[0-9]|[0-3]\.)/gi,
		severity: "medium",
		title: "Known Vulnerable Package Version (CVE)",
		description:
			"A package with known CVEs is used in an outdated version. Common in AI-generated code that uses old templates. Known affected: lodash <4.17.21, moment <2.29.4, axios <1.6.0, express <4.18.0 (CWE-1104).",
		remediation:
			"Update to latest stable version: npm update <package>. Check npm audit for specific CVEs. Consider replacing deprecated packages with maintained alternatives.",
	},
	{
		id: "DEP002",
		pattern:
			/(?:NODE_ENV\s*=\s*development|process\.env\.NODE_ENV\s*!==\s*['"]production['"])[^\n]{0,200}?(?:devDependencies|devDep|development)[^\n]{0,100}?(?:build|compile|webpack|vite|rollup)/gi,
		severity: "medium",
		title: "Dev Dependencies in Production Build",
		description:
			"Build scripts reference NODE_ENV=development or include dev dependencies in the production bundle. Dev dependencies may contain debugging tools or vulnerabilities that should not ship to production (CWE-1104).",
		remediation:
			'Use NODE_ENV=production for production builds. Configure webpack/vite to exclude devDependencies. Use webpack DefinePlugin to replace process.env.NODE_ENV with "production".',
	},
	{
		id: "SUPPLY006",
		pattern:
			/\${{\s*secrets\.[A-Z_]+[^}]*}}[^\n]{0,200}?(?:echo|print|console\.log|write-output|Write-Host|Log-error)/gi,
		severity: "high",
		title: "GitHub Actions Secrets May Be Logged",
		description:
			"GitHub Actions workflow may log or expose secrets. The pattern ${{ secrets.* }} followed by echo/print statements can leak sensitive credentials to action logs (OWASP A03:2025).",
		remediation:
			"Never echo or log secret values in GitHub Actions. Use set -o noalog or add ::add-mask:: to mask secrets. Use environment variables instead of direct secret references in logs.",
	},
	{
		id: "SUPPLY007",
		pattern:
			/"(?:postinstall|preinstall|postpublish|postuninstall)"\s*:\s*"[^"]*(?:curl|wget|http|https):\/\/[a-z0-9.-]{5,}(?:\|[\s]*(?:sh|bash|powershell))?/gi,
		severity: "critical",
		title: "Malicious External Script in npm Lifecycle",
		description:
			"npm lifecycle script (postinstall, preinstall, etc.) fetches and executes external scripts from URLs. This is a common supply chain attack vector — the external server can serve different malicious code at any time (OWASP A03:2025).",
		remediation:
			"Remove external curl/wget scripts from npm lifecycle hooks. Download scripts to your repo and verify their integrity. Never pipe curl directly to sh. Use npmignore to exclude suspicious scripts.",
	},
	{
		id: "SUPPLY008",
		pattern:
			/(?:package\.json)[\s\S]{0,2000}?"(faker|mock-aws|aws-sdk-mock|fake-|mock-|test-utils)[\s":]*[~^]?[0-9]/gi,
		severity: "high",
		title: "Suspicious Test/Mock Package in Dependencies",
		description:
			"Dependencies include suspicious test or mock packages that may be typosquatting legitimate testing libraries or contain malicious code (OWASP A03:2025).",
		remediation:
			"Verify package names are correct. Check if the package is a known legitimate library. Remove suspicious packages. Use scoped packages (@testing-library/*) instead of generic names.",
	},
	{
		id: "SUPPLY009",
		pattern:
			/(?:package\.json)[\s\S]{0,1000}?(?:registry|registry-url|publishConfig)[\s\n]*[\s":]*https?:\/\/(?!registry\.npmjs\.org)[a-z0-9.-]{5,}/gi,
		severity: "high",
		title: "Non-default npm Registry",
		description:
			"package.json or .npmrc specifies a non-default npm registry (not registry.npmjs.org). Packages from alternative registries may not be audited and could contain malware (OWASP A03:2025).",
		remediation:
			"Verify the registry is trusted and official. Use only well-known registries. Consider using npm shrinkwrap to lock all dependency sources. Audit all packages from alternative registries manually.",
	},

	// ============== LOVABLE-SPECIFIC RULES ==============
	// AI coding tool: Lovable (AI builder with Supabase backend)
	{
		id: "LOVABLE001",
		pattern:
			/(?:createClient|supabase)[^\n]{0,100}?(?:SELECT|INSERT|UPDATE)[^\n]{0,50}?(?:from|table)[^\n]{0,30}?(?!--.*RLS|--.*row.?level|--.*security)/gi,
		severity: "high",
		title: "Lovable App: Supabase Without RLS Validation",
		description:
			"Supabase client used in a Lovable-generated app without visible RLS comment or validation. AI-generated apps often ship with Row Level Security disabled or policies not configured. 10.3% of Lovable apps have critical RLS flaws.",
		remediation:
			"Enable RLS on all tables: ALTER TABLE <name> ENABLE ROW LEVEL SECURITY. Create policies that verify auth.uid() matches the user ID in each row. Test that unauthenticated requests are blocked.",
	},
	{
		id: "LOVABLE002",
		pattern:
			/export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\([^)]*\)\s*\{(?![\s\S]{0,2500}?(?:auth\.getUser|getServerSession|getSession|verifyToken|cookies\(\)\.|authorize|requireAuth|clerkClient|locals\.user|event\.locals\.user))[\s\S]{0,2500}?(?:supabase\.from|db\.[a-zA-Z_]|prisma\.[a-zA-Z_]+|prisma\.\$queryRaw|sql\`)/i,
		severity: "high",
		title: "AI-Generated: Handler Accesses DB Without Auth Check",
		description:
			"API route handler (Lovable, Cursor, v0, Bolt-generated, etc.) calls the database but no auth.getUser/session/cookie verification appears in the handler body. AI coding tools frequently scaffold CRUD handlers and forget to gate them on authentication, exposing user data cross-tenant (OWASP A01:2021, CWE-862).",
		remediation:
			"Verify auth at the top of every handler: const { data: { user } } = await supabase.auth.getUser(); if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });. Use Next.js middleware.ts to protect sensitive route prefixes (e.g., /api/account/**).",
	},

	// ============== BOLT-SPECIFIC RULES ==============
	// AI coding tool: Bolt (SvelteKit builder from StackBlitz)
	{
		id: "BOLT001",
		pattern:
			/\+server\.ts[^\n]{0,200}?(?:locals\.|\.data\.|event\.)[^\n]{0,50}?(?!user|session|auth)/gi,
		severity: "high",
		title: "Bolt App: SvelteKit +server.ts Route Without Auth",
		description:
			"SvelteKit +server.ts route accesses server data or locals without checking if the user is authenticated. Bolt-generated SvelteKit apps often skip auth middleware on data routes (OWASP A01:2021).",
		remediation:
			"Add auth check to +server.ts routes: const session = await locals.auth(); if (!session) return json(401). Use hooks.server.ts to validate sessions before route handlers execute.",
	},
	{
		id: "BOLT002",
		pattern:
			/PUBLIC_[A-Z_]+(?:=|:\s*)['"][^\n]{0,50}?(?:sk-|pk-|eyJ|[a-f0-9]{32,}|\$\{|ai_|openai|anthropic|supabase)/gi,
		severity: "high",
		title: "Bolt App: Sensitive Env Variable With PUBLIC_ Prefix",
		description:
			"Bolt/SvelteKit apps prefix all env vars with PUBLIC_ assuming they are safe client-side. This pattern flags PUBLIC_ vars that look like secrets (API keys, JWTs, database credentials). Attackers can extract these from the browser.",
		remediation:
			"Move sensitive variables to server-only env vars (no PUBLIC_ prefix). In SvelteKit: use $env/static/private for secrets. NEVER put API keys, passwords, or JWTs in PUBLIC_ variables.",
	},

	// ============== CURSOR-SPECIFIC RULES ==============
	// AI coding tool: Cursor (AI pair programmer)
	{
		id: "CURSOR001",
		pattern:
			/export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\([^\n]{0,100}?\)[^\n]{0,50}?(?:Request|NextRequest)[^\n]{0,200}?(?:db\.|prisma\.|supabase|from\()[^\n]{0,100}?(?!session|auth|verifyToken|getSession|authorize)/gi,
		severity: "high",
		title: "Cursor App: Next.js API Route Without Auth Validation",
		description:
			"Next.js API route handles database operations without authentication validation. Cursor-generated apps often have loose API route protection that allows unauthenticated data access (OWASP A01:2021).",
		remediation:
			"Validate session/JWT in every API route: const token = req.headers.get(authorization); const user = await verifyToken(token); if (!user) return NextResponse.json({error: Unauthorized}, {status: 401});",
	},
	{
		id: "CURSOR002",
		pattern:
			/middleware\.ts[\s\S]{0,500}?export\s+(?:const|function)\s+(?:config|matcher|matches)[^\n]{0,50}?(?!auth|session|verify|protect|redirect)/gi,
		severity: "medium",
		title: "Cursor App: Next.js Middleware Without Auth Protection",
		description:
			"Next.js middleware.ts exists but lacks auth/session validation or has a weak matcher that does not protect sensitive routes. Cursor apps often create middleware without proper route protection.",
		remediation:
			"Configure middleware to protect sensitive routes: export const config = { matcher: [/dashboard/:path*, /api/protected/:path*] }; Add JWT/session verification in middleware to redirect unauthenticated users.",
	},

	// ============== V0-SPECIFIC RULES ==============
	// AI coding tool: v0 by Vercel
	{
		id: "V0001",
		pattern:
			/dangerouslySetInnerHTML(?![\s\S]{0,1000}?(?:DOMPurify|sanitize-html|xss(?:\.|\()|he\.escape|validator\.escape|escape-html|sanitizeHtml|browserSanitizer|rehype-sanitize))[\s\S]{0,500}?(?:\{|\()/i,
		severity: "high",
		title: "dangerouslySetInnerHTML Without Sanitization",
		description:
			"dangerouslySetInnerHTML is being set with content that has not been passed through DOMPurify.sanitize(), sanitize-html, xss, he.escape, validator.escape, or another HTML sanitizer. v0, Bolt, Cursor, and Lovable all commonly render AI-generated HTML or API-returned HTML directly into the DOM, enabling XSS (CWE-79, OWASP A03:2021).",
		remediation:
			"Always sanitize before rendering: import DOMPurify from 'dompurify'; const clean = DOMPurify.sanitize(dirtyHTML); <div dangerouslySetInnerHTML={{ __html: clean }} />. Never pass unsanitized user input or AI-generated HTML to dangerouslySetInnerHTML.",
	},
	{
		id: "V0002",
		pattern:
			/(?:useAuth|AuthContext|authContext|useSession|getSession)[^\n]{0,50}?(?:createContext|useState)[^\n]{0,100}?(?:app[/.\\]api|server\.(?:ts|js)|actions)/gi,
		severity: "high",
		title: "v0 App: Server Actions Without Auth Guard",
		description:
			"Auth context or hook defined in a v0 app but server actions/API routes access data without verifying auth. v0 often generates server actions that handle user data without checking authentication (OWASP A01:2021).",
		remediation:
			"Verify auth in every server action: import { auth } from @/auth; const session = await auth(); if (!session) throw new Error(Unauthorized);. Add auth checks before any data access in server actions.",
	},

	// ============== REPLIT-SPECIFIC RULES ==============
	// AI coding tool: Replit (browser-based IDE)
	{
		id: "REPLIT001",
		pattern:
			/(\.replit|replit\.toml)[\s\S]{0,500}?(?:secrets|config|env)[^\n]{0,50}?(?:api[_-]?key|token|password|secret|key)[^\n]{0,50}?=\s*["'][^\n"']{10,}/gi,
		severity: "critical",
		title: "Replit: Secrets Exposed in .replit Configuration",
		description:
			".replit or replit.toml file contains secrets (API keys, tokens, passwords) in the secrets/config section. Replit apps commonly expose secrets in configuration files that can be read by collaborators or scraped from public repls (CWE-552).",
		remediation:
			"Remove secrets from .replit. Use Replit built-in environment secrets via the Secrets tab (encrypted). Never commit API keys or passwords to .replit files that are shared or public.",
	},
	{
		id: "REPLIT002",
		pattern:
			/app\.(?:get|post|put|delete|patch)\s*\([^\n]{0,100}?,[^\n]{0,100}?(?:req|request)[^\n]{0,200}?(?:db|supabase|mongo|prisma)[^\n]{0,100}?(?!auth|verify|middleware|check)/gi,
		severity: "high",
		title: "Replit: Express Route Without Auth Middleware",
		description:
			"Express route in a Replit app handles database operations without auth middleware. Replit-generated Express apps often skip authentication on data routes (OWASP A01:2021).",
		remediation:
			"Add auth middleware to Express routes: const authMiddleware = require(./middleware/auth); app.get(/api/data, authMiddleware, handler). Create an auth middleware that validates JWT or session before allowing data access.",
	},

	// ============== VIBECODE-AI: FRAMEWORK-AGNOSTIC RULES ==============
	// These rules target anti-patterns common across AI coding tools (Cursor, v0,
	// Lovable, Bolt, Windsurf, Copilot, Replit Agent). They use content heuristics
	// rather than filename matching so they catch projects regardless of tool.

	{
		id: "VIBECODE-AI-SERVER-ACTION-001",
		pattern:
			/['"]use server['"](?![\s\S]{0,3000}?(?:auth\.getUser|getServerSession|getSession|verifyToken|cookies\(\)\.|requireAuth|clerkClient|locals\.user|event\.locals\.user))[\s\S]{0,3000}?(?:prisma\.[a-zA-Z_]+|supabase\.from|db\.[a-zA-Z_]|await\s+prisma|await\s+db\.)/i,
		severity: "high",
		title: "Next.js Server Action Without Auth Check",
		description:
			"A file marked with 'use server' (Next.js Server Action) reads from the database or fetches with environment secrets but no auth verification appears in the action body. AI coding tools love to scaffold server actions that mutate user data without checking ownership (OWASP A01:2021, CWE-862).",
		remediation:
			"Start every server action with: const { data: { user } } = await supabase.auth.getUser(); if (!user) throw new Error('Unauthorized');. Then check that the resource being mutated belongs to user.id before writing. Never trust the client-supplied id field.",
	},
	{
		id: "VIBECODE-AI-SECRET-CLIENT-001",
		pattern:
			/(?:NEXT_PUBLIC_|VITE_|REACT_APP_|VITE_PUBLIC_|PUBLIC_)([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_TOKEN|PRIVATE_KEY|AUTH))\s*[:=]\s*['"](?:sk_live_|pk_live_|sk_test_|pk_test_|sk-|pk-|gho_|ghp_|ghu_|ghr_|AIza[0-9A-Za-z_-]{20,}|xai-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}|[A-Fa-f0-9]{32,})/i,
		severity: "critical",
		title: "Secret Exposed in Client-Side Env Variable",
		description:
			"An env variable prefixed NEXT_PUBLIC_/VITE_/REACT_APP_/PUBLIC_ contains a value that looks like a secret (Stripe key, GitHub token, OpenAI/Anthropic/xAI key, JWT, or long hex/base64). Anything in these prefixes is bundled into the client and is fully extractable by anyone visiting the site. Vibe-coding tools frequently put real secrets here because they reach for the first working variable (CWE-798, OWASP A07:2021).",
		remediation:
			"Move the secret to a server-only env variable (no public prefix). In Next.js: drop the NEXT_PUBLIC_ prefix and read with process.env.NAME server-side only. In Vite/SvelteKit: use import.meta.env (server) or $env/static/private. Never expose API keys to the browser.",
	},
	{
		id: "VIBECODE-AI-LOW-EFFORT-001",
		pattern:
			/(?:\/\/|\/\*|<!--)\s*(?:TODO|FIXME|XXX|HACK)\s*(?::|-)?\s*(?:\badd\s+auth\b|\bsecurity\b|\bauth\b|\bauthenticate\b|\bprotect\b|\brate.?limit\b|\bvalidate\b|\binput.?validation\b|\bsanitize\b|\bcsp\b|\bcsrf\b|\bencrypt\b|\bhash\b|\bpassword\b)/i,
		severity: "high",
		title: "Security TODO/FIXME Left in Code",
		description:
			"A TODO/FIXME/XXX/HACK comment in code references auth, security, validation, sanitization, rate limiting, encryption, or password handling. Vibe-coding tools ship these comments as placeholders the user rarely addresses (CWE-546, OWASP A05:2025).",
		remediation:
			"Treat every security TODO as a finding, not a future task. Either implement the security control before merging, or open a tracked ticket with a deadline and do not deploy to production with the TODO unresolved.",
	},
	{
		id: "VIBECODE-AI-INPUT-001",
		pattern:
			/(?:prisma\.\$queryRaw|sql\.query|sequelize\.query|knex\.raw|connection\.query|client\.query|pool\.query)[\s\S]{0,200}?\$\{[^}]+\}/i,
		severity: "critical",
		title: "Raw SQL Query With Interpolated Variable",
		description:
			"A raw SQL query uses template-string interpolation (${var}) to splice a value into the statement instead of parameter binding ($1, ?, :name). This is classic SQL injection waiting to happen. AI coding tools assemble raw queries from user input because the prompt said 'look up user by id' without specifying parameterization (CWE-89, OWASP A03:2021).",
		remediation:
			"Use parameterized queries: prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}` (Prisma tagged template binds ${} safely). For other drivers, use bound parameters (pg: client.query('... WHERE id = $1', [id])). Never concatenate or template-interpolate user input into a SQL string.",
	},
	{
		id: "VIBECODE-AI-DEBUG-001",
		pattern:
			/console\.(?:log|debug|info|warn|table|dir)\s*\([^)]*(?:req\.body|request\.body|req\.headers|req\.cookies|req\.params|req\.query|body|password|token|secret|api[_-]?key|session|csrf|cookie)/i,
		severity: "high",
		title: "Sensitive Data Logged via console.*",
		description:
			"console.log/debug/info/warn/table/dir is being called with arguments that look like request bodies, passwords, tokens, secrets, API keys, sessions, CSRF tokens, or cookies. Vibe-coded handlers sprinkle logging to debug and ship them to production, where logs end up in Datadog/Sentry/CloudWatch and become a credential leak vector (CWE-532, OWASP A09:2021).",
		remediation:
			"Remove all console.* statements that log request data or secrets before deploying. If you need server-side observability, use a structured logger (pino/winston) with explicit field allowlists, and never log raw request bodies, tokens, or passwords.",
	},
	{
		id: "VIBECODE-AI-RATE-LIMIT-001",
		pattern:
			/(?:router|app)\.(?:post|put|delete|patch)\s*\(\s*['"]\/(?:api\/)?(?:login|signin|signup|register|forgot.?password|reset.?password|verify.?email|change.?password|auth\/)/i,
		severity: "medium",
		title: "Auth Route Without Detectable Rate Limit",
		description:
			"An authentication route (login, signup, password reset, etc.) is defined without any visible rate-limit, throttle, captcha, or attempt-limiting helper in the same file. Vibe-coded auth routes are unprotected by default, enabling credential stuffing and brute-force attacks (CWE-307, OWASP A04:2021).",
		remediation:
			"Apply rate limiting at the route or middleware level: rateLimit({ windowMs: 15*60*1000, max: 5 }) on /login, /signup, /forgot-password. Combine with CAPTCHA on /login after N failed attempts. Use middleware.ts to apply limits across all /api/auth/** routes.",
	},
];

export function scanContent(content: string, filePath: string): Finding[] {
	const findings: Finding[] = [];
	const lines = content.split("\n");

	function scoreAndPush(base: Omit<Finding, "score" | "riskFactors">, snippetOverride?: string): void {
		const { score, riskFactors } = scoreFinding(
			{ ...base, snippet: base.snippet ?? snippetOverride },
			{ content, filePath, snippet: base.snippet ?? snippetOverride },
		);
		findings.push({ ...base, snippet: base.snippet ?? snippetOverride, score, riskFactors });
	}

	// Run Supabase RLS checks
	findings.push(...checkSupabaseRLS(content, filePath));

	// Run Supabase credential check (requires file path context)
	if (checkSupabaseCredentials(content, filePath)) {
		scoreAndPush({
			id: `SUPABASE001-${findings.length}`,
			ruleId: "SUPABASE001",
			severity: "critical",
			title: "Exposed Supabase Credentials",
			description:
				"Hardcoded Supabase API keys or service role keys found in source code. This allows full database access bypassing RLS policies.",
			filePath,
			remediation:
				"Use environment variables: process.env.SUPABASE_KEY. Never commit Supabase anon/service keys to version control. Add .env to .gitignore and use a secrets manager for production.",
		});
	}

	// ---- OWASP Top 10 (2021 + 2025) + Cheat Sheets per-file detectors ----
	const owaspFileChecks: Array<{
		check: (c: string, p: string) => boolean;
		finding: Omit<Finding, "id" | "filePath" | "lineNumber" | "snippet">;
	}> = [
		{
			check: checkIdorRoute,
			finding: {
				ruleId: "A01-IDOR",
				severity: "high",
				title: "API Route With ID Parameter Without Ownership Check (OWASP A01:2021)",
				description:
					"API route reads an id from the request and uses it to load data, but no ownership check is visible. This pattern is the canonical IDOR (Insecure Direct Object Reference) — a user can read or mutate another user's data by guessing ids (CWE-639).",
				remediation:
					"After loading the resource, verify the caller owns it: const { data: { user } } = await supabase.auth.getUser(); if (record.user_id !== user.id) return new Response('Forbidden', { status: 403 });. For Next.js API routes, gate every handler with auth + ownership check or use row-level security on the underlying table.",
			},
		},
		{
			check: checkWeakHashing,
			finding: {
				ruleId: "A02-WEAK-HASH",
				severity: "high",
				title: "Weak Hash Algorithm (MD5/SHA1) for Crypto (OWASP A02:2021)",
				description:
					"Crypto code uses MD5 or SHA-1. These are collision-broken and unsuitable for password storage, token integrity, or digital signatures. Attackers can craft collisions and brute-force pre-images cheaply (CWE-327, CWE-916).",
				remediation:
					"For passwords: use bcrypt, scrypt, argon2 or PBKDF2 with high work factor. For digital signatures / integrity: use SHA-256 or SHA-3. For tokens / HMAC: use SHA-256 with a random key of at least 256 bits.",
			},
		},
		{
			check: checkPlaintextPasswordColumn,
			finding: {
				ruleId: "A02-PLAINTEXT-PWD",
				severity: "critical",
				title: "Password Column Without Hashing Hint (OWASP A02:2021)",
				description:
					"Schema or migration defines a password column with no sign of hashing (bcrypt/argon2/scrypt). If the app stores raw passwords there, a single DB leak exposes every credential (CWE-256, CWE-257).",
				remediation:
					"Never store plaintext passwords. Hash on write with bcrypt (cost ≥ 12) or argon2id. If migrating an existing table, force a password reset on next login.",
			},
		},
		{
			check: checkHardcodedRoleCheck,
			finding: {
				ruleId: "A04-HARDCODED-ROLE",
				severity: "medium",
				title: "Hardcoded Role String Comparison (OWASP A04:2021)",
				description:
					"Authorization code compares role against a hardcoded literal (admin/root). This is brittle and easy to bypass if the role label changes or if the same string is reused for unrelated checks (CWE-1188).",
				remediation:
					"Use a role/permission enum and centralize authorization checks (e.g., requireRole('admin')) instead of literal compares. Enforce in middleware, not just in the handler.",
			},
		},
		{
			check: checkJwtMissingExpiry,
			finding: {
				ruleId: "A07-JWT-NO-EXP",
				severity: "high",
				title: "JWT Without Expiry Claim (OWASP A07:2021)",
				description:
					"JWT is signed or verified without an explicit `expiresIn` / `exp` claim. Tokens live forever once issued, so stolen tokens grant permanent access and there is no automatic session rotation (CWE-613).",
				remediation:
					"Always set expiresIn when signing (e.g., jwt.sign(payload, secret, { expiresIn: '15m' })). On verify, require exp and reject tokens where exp is missing or in the past.",
			},
		},
		{
			check: checkInsecureCookie,
			finding: {
				ruleId: "A07-COOKIE-FLAGS",
				severity: "high",
				title: "Cookie Set Without HttpOnly/Secure/SameSite (OWASP A07:2021)",
				description:
					"A cookie is set without the HttpOnly, Secure, or SameSite flags. Such cookies are readable from JavaScript (XSS-stealable) and can leak over plaintext HTTP or in cross-site requests (CWE-1004, CWE-614, CWE-1275).",
				remediation:
					"Set httpOnly: true, secure: true, sameSite: 'lax' (or 'strict') on every auth or session cookie. For session middleware in Next.js/Express, configure these flags globally.",
			},
		},
		{
			check: checkUnsafeDeserialization,
			finding: {
				ruleId: "A08-UNSAFE-DESERIALIZE",
				severity: "critical",
				title: "Unsafe Deserialization (OWASP A08:2021)",
				description:
					"Code uses a known-unsafe deserializer (node-serialize, serialize-javascript, yaml.load, JSON.parse on req.body without validation). Crafted payloads can lead to remote code execution (CWE-502).",
				remediation:
					"Never deserialize untrusted input with code-executing parsers. Validate JSON Schema before JSON.parse. Use yaml.safeLoad / yaml.load with a custom safe schema. Avoid node-serialize entirely.",
			},
		},
		{
			check: checkAuthRouteWithoutLogging,
			finding: {
				ruleId: "A09-AUTH-NO-LOG",
				severity: "medium",
				title: "Auth Handler Without Security Logging (OWASP A09:2021)",
				description:
					"Login/signup/reset-password handler returns a result but has no logger, monitoring, or audit hook. Auth events are the highest-value events to log — without them, credential stuffing and account takeover are invisible (CWE-778).",
				remediation:
					"Log auth successes and failures with: timestamp, user id (when known), source IP, user agent, and reason. Forward to a SIEM or at minimum to durable structured logs.",
			},
		},
		{
			check: checkPotentialSsrf,
			finding: {
				ruleId: "A10-SSRF",
				severity: "high",
				title: "Server Fetches User-Controlled URL Without Allowlist (OWASP A10:2021)",
				description:
					"A handler reads a URL from the request and passes it to fetch/axios/http.get without validating the host. An attacker can point it at 169.254.169.254 (cloud metadata), localhost admin panels, or internal services (CWE-918).",
				remediation:
					"Resolve the host and reject private/loopback/link-local IPs (RFC1918, 127.0.0.0/8, 169.254.0.0/16, ::1). Use an explicit allowlist of trusted hosts. Disable HTTP redirects or revalidate after each hop.",
			},
		},
		{
			check: checkSwallowedErrors,
			finding: {
				ruleId: "A10-SWALLOWED-ERROR",
				severity: "low",
				title: "Empty Catch Block Silencing Errors (OWASP A10:2025)",
				description:
					"A `.catch(() => {})` or `.catch(() => null)` swallows every error silently. Failures that should surface — network errors, validation errors, auth errors — are invisible, masking real bugs and security regressions (CWE-703, OWASP A10:2025 — Mishandling of Exceptional Conditions).",
				remediation:
					"Log or rethrow caught errors. If you intentionally ignore a specific error, narrow the catch (e.g., check the error type) and leave a comment explaining why.",
			},
		},
		{
			check: checkCodeInjectionSink,
			finding: {
				ruleId: "XSS-CODE-INJECT",
				severity: "high",
				title: "Code Injection Sink: new Function / setTimeout-with-string (XSS Cheat Sheet)",
				description:
					"Code uses `new Function(...)`, `setTimeout('...', n)` or `setInterval('...', n)` with a string body. Strings are evaluated as JavaScript; an attacker who controls the string gets RCE or XSS in the browser (CWE-95, CWE-79).",
				remediation:
					"Pass function references instead of strings: setTimeout(handler, n). Avoid `new Function`. For dynamic code paths, use a whitelist lookup table rather than eval/Function.",
			},
		},
		{
			check: checkPrismaRawInjection,
			finding: {
				ruleId: "SQLI-PRISMA-RAW",
				severity: "critical",
				title: "Prisma $executeRaw / $queryRaw With String Interpolation (SQLi Cheat Sheet)",
				description:
					"`prisma.$executeRaw` / `Prisma.sql` is called with a template literal that interpolates a variable. Prisma cannot parameterize interpolated values, so user input lands directly in the SQL string (CWE-89).",
				remediation:
					"Use Prisma's tagged template form: `prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}``. Better still, use the Prisma Client API (prisma.user.findUnique) which always parameterizes.",
			},
		},
		{
			check: checkHardcodedSecretFallback,
			finding: {
				ruleId: "SECRET-FALLBACK",
				severity: "critical",
				title: "Environment Variable With Hardcoded Fallback Secret",
				description:
					"`process.env.X || 'long-string-literal'` provides a real-looking secret as a fallback. If the env var is unset in production (typo, missing .env), the app silently uses the hardcoded secret — which is now in the repo (CWE-798, CWE-547).",
				remediation:
					"Fail fast when a secret is missing: `if (!process.env.X) throw new Error('X is required')`. Never provide a default that looks like a real key.",
			},
		},
		{
			check: checkMutatingRouteWithoutCsrf,
			finding: {
				ruleId: "CSRF-MISSING",
				severity: "high",
				title: "State-Changing Handler Without CSRF Defense (CSRF Cheat Sheet)",
				description:
					"POST/PUT/PATCH/DELETE handler has no CSRF token check, no SameSite cookie enforcement, and no Origin/Referer validation. A malicious cross-origin page can trigger state changes on behalf of the logged-in user (CWE-352).",
				remediation:
					"Add a CSRF token check (double-submit cookie or synchronizer pattern), enforce SameSite=Strict/Lax on session cookies, and validate Origin/Referer against an allowlist.",
			},
		},
	];

	for (const owasp of owaspFileChecks) {
		if (owasp.check(content, filePath)) {
			scoreAndPush({
				id: `${owasp.finding.ruleId}-${findings.length}`,
				...owasp.finding,
				filePath,
			});
		}
	}

	for (const rule of GITHUB_SCANNER_RULES) {
		// Skip SUPABASE001 in the pattern loop since we handle it above
		if (rule.id === "SUPABASE001") continue;

		const matches = content.match(rule.pattern);
		if (matches) {
			for (const match of matches) {
				// Find line number
				let lineNumber: number | undefined;
				for (let i = 0; i < lines.length; i++) {
					if (lines[i].includes(match.substring(0, 50))) {
						lineNumber = i + 1;
						break;
					}
				}

				// Get snippet (line context)
				const snippet = lineNumber
					? lines.slice(Math.max(0, lineNumber - 2), lineNumber + 2).join("\n")
					: undefined;

				findings.push({
					id: `${rule.id}-${findings.length}`,
					ruleId: rule.id,
					severity: rule.severity,
					title: rule.title,
					description: rule.description,
					filePath,
					lineNumber,
					snippet,
					remediation: rule.remediation,
					...scoreFinding(
						{
							id: `${rule.id}-${findings.length}`,
							ruleId: rule.id,
							severity: rule.severity,
							title: rule.title,
							description: rule.description,
							filePath,
							lineNumber,
							snippet,
							remediation: rule.remediation,
						},
						{ content, filePath, snippet },
					),
				});
			}
		}
	}

	return findings;
}
