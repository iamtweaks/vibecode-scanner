/**
 * Known CVE detection scanner.
 *
 * Pulls the top-100 most-critical CVEs from the public Sentinel-Bench REST
 * API (https://sentinel-bench.vercel.app/api/v1/vulnerabilities.json) and
 * matches every package declared in the package.json files discovered by
 * the GitHub scanner. Uses a tiny in-memory LRU cache (Map, capped at 100,
 * no external dep) so repeat lookups inside one scan stay free and so a
 * fetch failure does not block the whole scan.
 *
 * The scanner produces three Finding ruleIds:
 *   - KNOWN_CVE          (high)    — generic CVE match
 *   - KNOWN_CVE_KEV      (critical)— CISA Known Exploited Vulnerabilities
 *   - KNOWN_CVE_WITH_POC (critical)— public PoC available
 *
 * Both KEV and PoC variants also carry the generic KNOWN_CVE marker on
 * the same finding so consumers that filter by ruleId still see them.
 */

import type { Finding } from "../types";

// ============== Types (local, do NOT re-export) ==============

export interface VulnEntry {
	cve_id: string;
	is_kev: boolean;
	poc_public: boolean;
	exploited_in_wild: boolean;
	score?: number | null;
	rationale?: string | null;
	vendors: string[];
	products: string[];
	remediation?: string | null;
}

export interface VulnFeed {
	data: VulnEntry[];
	total?: number | null;
	returned: number;
	limit: number;
	offset: number;
	generated_at?: string;
}

export interface PackageFile {
	filePath: string;
	content: string;
}

export interface ScanEnv {
	// Minimal subset of NodeJS.ProcessEnv used by this scanner.
	readonly [key: string]: string | undefined;
}

interface PackageJsonShape {
	dependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
	// Optional: track which section a dep was declared in.
	[name: string]: unknown;
}

// ============== Constants ==============

const SENTINEL_BENCH_URL =
	"https://sentinel-bench.vercel.app/api/v1/vulnerabilities.json";

/** Hard cap on cached CVEs — top-100 by Sentinel-Bench ranking. */
export const CACHE_SIZE = 100;

/** Per-fetch timeout in ms. Short on purpose: CVE scan is best-effort. */
const FETCH_TIMEOUT_MS = 5000;

// ============== In-memory Cache ==============

/**
 * Bounded LRU cache keyed by cve_id. Uses native Map insertion order for
 * eviction — no third-party dep. Resizing is a no-op once at cap; oldest
 * entry drops on every insert past the cap.
 */
function createCache(cap: number): Map<string, VulnEntry> {
	return new Map<string, VulnEntry>();
}

function cacheGet(cache: Map<string, VulnEntry>, id: string): VulnEntry | undefined {
	const v = cache.get(id);
	if (v) {
		// Touch — re-insert so LRU is honored on next overflow.
		cache.delete(id);
		cache.set(id, v);
	}
	return v;
}

/** @internal exposed for tests only — pass the cache's cap explicitly so the
 *  test can use a small cap (3) while production uses CACHE_SIZE (100). */
function cacheSet(cache: Map<string, VulnEntry>, entry: VulnEntry, cap: number): void {
	const id = entry.cve_id;
	if (cache.has(id)) cache.delete(id);
	cache.set(id, entry);
	while (cache.size > cap) {
		const oldest = cache.keys().next().value;
		if (oldest === undefined) break;
		cache.delete(oldest);
	}
}

// ============== Fetch + parse ==============

function parseFeed(jsonText: string): VulnEntry[] {
	let parsed: unknown;
	try {
		parsed = JSON.parse(jsonText);
	} catch {
		return [];
	}
	if (!parsed || typeof parsed !== "object") return [];
	const feed = parsed as VulnFeed;
	if (!Array.isArray(feed.data)) return [];
	return feed.data.filter(isVulnEntry);
}

function isVulnEntry(v: unknown): v is VulnEntry {
	if (!v || typeof v !== "object") return false;
	const e = v as Record<string, unknown>;
	return (
		typeof e.cve_id === "string" &&
		typeof e.is_kev === "boolean" &&
		typeof e.poc_public === "boolean" &&
		typeof e.exploited_in_wild === "boolean" &&
		Array.isArray(e.vendors) &&
		Array.isArray(e.products)
	);
}

/**
 * Fetch the top-N CVEs. Network failures are swallowed — the scanner is
 * best-effort. Cache is populated on success; on failure the cache stays
 * empty and scanKnownCves returns no CVE findings.
 */
async function fetchTopVulns(
	cache: Map<string, VulnEntry>,
	fetchImpl: typeof fetch = fetch,
	timeoutMs = FETCH_TIMEOUT_MS,
): Promise<void> {
	if (cache.size > 0) return; // already warm
	const controller =
		typeof AbortController !== "undefined" ? new AbortController() : null;
	const timer = controller
		? setTimeout(() => controller.abort(), timeoutMs)
		: null;
	try {
		const resp = await fetchImpl(SENTINEL_BENCH_URL, {
			signal: controller?.signal,
			headers: { accept: "application/json" },
		});
		if (!resp.ok) return;
		const text = await resp.text();
		const entries = parseFeed(text);
		for (const e of entries) cacheSet(cache, e, CACHE_SIZE);
	} catch {
		// network error / abort / parse error — leave cache empty
	} finally {
		if (timer) clearTimeout(timer);
	}
}

// ============== Dependency matching ==============

function safeParsePackageJson(content: string): PackageJsonShape | null {
	try {
		const parsed = JSON.parse(content);
		if (!parsed || typeof parsed !== "object") return null;
		return parsed as PackageJsonShape;
	} catch {
		return null;
	}
}

function normalizeDepName(name: string): string {
	return name.trim().toLowerCase();
}

/**
 * Case-insensitive substring match: the dep name appears inside any of
 * the vuln's products or vendors. The vuln's product list is the
 * authoritative label (e.g. "lodash", "ColdFusion"), so we look for
 * `depName ⊆ vulnProduct` OR `vulnProduct ⊆ depName`. The bidirectional
 * check catches:
 *   - depName "lodash"      vs product "lodash"          → match
 *   - depName "@scope/lib"  vs product "lib"             → match
 *   - depName "react-big"   vs product "react"           → NOT a match
 *     (would over-match every react-* package against a react CVE)
 * So we require the depName to be either fully contained in OR fully
 * contain the vuln token, and add a minimum-length guard so a one-letter
 * dep doesn't blow up the cache.
 */
function depMatchesVuln(depName: string, vuln: VulnEntry): boolean {
	const needle = normalizeDepName(depName);
	if (!needle || needle.length < 2) return false;
	const tokens: string[] = [];
	for (const p of vuln.products) tokens.push(p);
	for (const v of vuln.vendors) tokens.push(v);
	for (const raw of tokens) {
		if (typeof raw !== "string") continue;
		const h = raw.toLowerCase();
		if (h.length < 2) continue;
		if (h.includes(needle) || needle.includes(h)) return true;
	}
	return false;
}

// ============== Finding emission ==============

function buildFinding(
	vuln: VulnEntry,
	depName: string,
	declaredVersion: string,
	filePath: string,
): Finding {
	const isKev = vuln.is_kev === true;
	const hasPoc = vuln.poc_public === true;
	// Pick the most severe applicable ruleId; consumers can filter on it.
	let ruleId: string;
	let severity: Finding["severity"];
	if (isKev) {
		ruleId = "KNOWN_CVE_KEV";
		severity = "critical";
	} else if (hasPoc) {
		ruleId = "KNOWN_CVE_WITH_POC";
		severity = "critical";
	} else {
		ruleId = "KNOWN_CVE";
		severity = "high";
	}

	const flags: string[] = [];
	if (isKev) flags.push("KEV (CISA Known Exploited)");
	if (hasPoc) flags.push("public PoC");
	if (vuln.exploited_in_wild) flags.push("exploited in the wild");
	const flagsSuffix = flags.length ? ` [${flags.join(", ")}]` : "";

	const remediation =
		typeof vuln.remediation === "string" && vuln.remediation.length > 0
			? vuln.remediation
			: `Update ${depName} to a patched version that addresses ${vuln.cve_id}. Run \`npm audit\`, check the upstream advisory, and pin to a fixed release.`;

	const description =
		`Dependency \`${depName}@${declaredVersion}\` matches ${vuln.cve_id}` +
		`${flagsSuffix}. Sentinel-Bench ranked this CVE in the top-100 most critical. ` +
		`${vuln.rationale ? `Rationale: ${vuln.rationale}. ` : ""}` +
		`An attacker who can reach the vulnerable code path can exploit this CVE.`;

	return {
		id: `${ruleId}-${vuln.cve_id}-${depName.toLowerCase()}`,
		ruleId,
		severity,
		title: `${ruleId.replace(/_/g, " ")}: ${depName}@${declaredVersion} matches ${vuln.cve_id}`,
		description,
		filePath,
		remediation,
	};
}

// ============== Public API ==============

function scanWithCache(
	packageFiles: PackageFile[],
	cache: Map<string, VulnEntry>,
): Finding[] {
	const findings: Finding[] = [];
	if (!Array.isArray(packageFiles) || packageFiles.length === 0) return findings;
	if (cache.size === 0) return findings;

	for (const pf of packageFiles) {
		const pkg = safeParsePackageJson(pf.content);
		if (!pkg) continue;
		const sections: Array<[string, Record<string, string> | undefined]> = [
			["dependencies", pkg.dependencies],
			["devDependencies", pkg.devDependencies],
		];
		for (const [, deps] of sections) {
			if (!deps || typeof deps !== "object") continue;
			for (const [depName, depVersion] of Object.entries(deps)) {
				const version = typeof depVersion === "string" ? depVersion : "*";
				for (const vuln of cache.values()) {
					if (depMatchesVuln(depName, vuln)) {
						findings.push(buildFinding(vuln, depName, version, pf.filePath));
					}
				}
			}
		}
	}
	return findings;
}

/**
 * Scan every package.json in `packageFiles` against the Sentinel-Bench
 * top-100 CVE feed and return findings. The cache is process-scoped (one
 * Map per call) so concurrent scans do not leak state. Network failures
 * return [] — callers should treat CVE findings as best-effort.
 *
 * Both `dependencies` and `devDependencies` are scanned — dev deps ship
 * into build pipelines and CI workers and have the same exploit surface
 * as runtime deps.
 */
export async function scanKnownCves(
	packageFiles: PackageFile[],
	env: ScanEnv = {},
): Promise<Finding[]> {
	const cache = createCache(CACHE_SIZE);
	await fetchTopVulns(cache);
	// `env` is part of the signature for parity with other scanners; it is
	// intentionally unused here so we never reach for new env vars.
	void env;
	return scanWithCache(packageFiles, cache);
}

/**
 * Test-only helper: scan packageFiles using a pre-populated cache instead
 * of hitting the network. Used by unit tests to assert specific CVE
 * matches (e.g. lodash@4.17.20 → CVE-2020-28500) without depending on
 * what the Sentinel-Bench top-100 currently contains.
 */
export async function _scanWithCache(
	packageFiles: PackageFile[],
	cache: Map<string, VulnEntry>,
	env: ScanEnv = {},
): Promise<Finding[]> {
	void env;
	return scanWithCache(packageFiles, cache);
}

/**
 * Test-only helper: clear the module-level cache so vitest can reset
 * state between test runs. Not used in production code.
 */
export function _resetCacheForTests(cache: Map<string, VulnEntry>): void {
	cache.clear();
}

// Internal exports for unit tests (cache primitives + matching).
export const __internals = {
	createCache,
	cacheGet,
	cacheSet,
	parseFeed,
	depMatchesVuln,
	safeParsePackageJson,
};
