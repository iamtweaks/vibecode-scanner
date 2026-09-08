/**
 * Centralized CORS configuration for VibeChecker API routes.
 *
 * Security rationale (OWASP A01:2021 - Broken Access Control):
 * - We do NOT use `Access-Control-Allow-Origin: *`. A wildcard origin allows
 *   any third-party site to invoke our API with the user's cookies, which is
 *   unsafe once we ship authenticated endpoints. CORS is browser-enforced, so
 *   on the server we still validate the request; the header exists to tell
 *   the browser which JS origins are allowed to read the response.
 * - We echo the request's `Origin` header back ONLY when it matches a trusted
 *   allowlist. This keeps the response `Vary: Origin` so caches don't serve
 *   one tenant's CORS headers to another.
 * - In server-to-server calls (no Origin header), we skip the CORS header
 *   entirely because there is no browser to instruct.
 */

import type { NextRequest } from "next/server";

/**
 * Trusted origins for VibeChecker. The list must be updated when new
 * production or preview deployments are added.
 */
const ALLOWED_ORIGINS: readonly string[] = [
	// Production
	"https://vibe-checker-beta-umber.vercel.app",
	"https://vibecheck.dev",
	"https://www.vibecheck.dev",
	// Preview deployments follow this pattern on Vercel
	"https://vibe-checker-beta-git-main-iamtweaks.vercel.app",
	// Local development
	"http://localhost:3000",
	"http://127.0.0.1:3000",
	"http://localhost:3001",
] as const;

/**
 * Build CORS headers for a given request. If the request `Origin` is in the
 * allowlist we echo it back; otherwise we omit the header so the browser will
 * block the response. We always set `Vary: Origin` to prevent cache poisoning.
 */
export function getCorsHeaders(request?: NextRequest): Record<string, string> {
	const requestOrigin = request?.headers.get("origin") ?? "";
	const allowOrigin = ALLOWED_ORIGINS.includes(requestOrigin)
		? requestOrigin
		: "";

	const headers: Record<string, string> = {
		Vary: "Origin",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
		"Access-Control-Max-Age": "86400",
		// ponytail: token auth only (X-API-Key header), no cookies — never
		// advertise credentials. Avoids the wildcard+credentials footgun.
	};

	if (allowOrigin) {
		headers["Access-Control-Allow-Origin"] = allowOrigin;
	}

	return headers;
}

/**
 * Pre-configured headerset for OPTIONS preflight responses.
 * Same as getCorsHeaders() but always returns the allow-origin when an origin
 * is supplied, since preflight requests always carry an Origin header.
 */
export function getPreflightHeaders(
	request: NextRequest,
): Record<string, string> {
	return getCorsHeaders(request);
}
