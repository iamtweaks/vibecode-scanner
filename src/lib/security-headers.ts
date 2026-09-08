import { NextRequest, NextResponse } from 'next/server'

const DEFAULT_ALLOWED_ORIGINS = [
  'https://vibe-checker-beta-umber.vercel.app',
  'https://vibe-checker.69-6-206-26.sslip.io',
]

export const securityHeaders = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "img-src 'self' data: https:",
    "font-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "connect-src 'self' https://*.supabase.co https://api.github.com",
    "upgrade-insecure-requests",
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
} as const

export function applySecurityHeaders(response: NextResponse): NextResponse {
  for (const [header, value] of Object.entries(securityHeaders)) {
    response.headers.set(header, value)
  }
  return response
}

function parseAllowedOrigins(): string[] {
  const configured = process.env.ALLOWED_ORIGINS
    ?.split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)

  return configured?.length ? configured : DEFAULT_ALLOWED_ORIGINS
}

export function buildCorsHeaders(request: NextRequest, methods = 'GET, POST, OPTIONS'): HeadersInit {
  const origin = request.headers.get('origin')
  const allowedOrigins = parseAllowedOrigins()
  // ponytail: omit ACAO when no/invalid origin — server-to-server calls have
  // no browser to instruct, and falling back to a default origin leaks one
  // tenant's CORS grant to any cache that keyed on Origin.
  const allowedOrigin = origin && allowedOrigins.includes(origin) ? origin : undefined

  const headers: Record<string, string> = {
    ...securityHeaders,
    'Access-Control-Allow-Methods': methods,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  }
  if (allowedOrigin) {
    headers['Access-Control-Allow-Origin'] = allowedOrigin
  }
  return headers
}

export function jsonWithSecurity<T>(
  request: NextRequest,
  body: T,
  init: ResponseInit = {},
  methods?: string,
) {
  return NextResponse.json(body, {
    ...init,
    headers: {
      ...buildCorsHeaders(request, methods),
      ...(init.headers || {}),
    },
  })
}

export function isProduction() {
  return process.env.NODE_ENV === 'production'
}
