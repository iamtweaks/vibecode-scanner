/** @type {import('next').NextConfig} */
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
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
      'upgrade-insecure-requests',
    ].join('; '),
  },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  // ponytail: override Vercel's CDN-injected ACAO: * on prerendered/static
  // responses. API handlers set their own ACAO dynamically and win on those
  // routes. This only sticks for the homepage and other non-API static pages.
  { key: 'Access-Control-Allow-Origin', value: 'https://vibecode-checker.vercel.app' },
  { key: 'Vary', value: 'Origin' },
]

// A04 hardening: block common debug/tracing paths so they can never be
// exposed by accident in production. They 404 even if a route file is added.
const debugPathRewrites = [
  { source: '/debug/:path*', destination: '/404' },
  { source: '/_debug/:path*', destination: '/404' },
  { source: '/api/debug/:path*', destination: '/404' },
  { source: '/api/_debug/:path*', destination: '/404' },
  { source: '/trace/:path*', destination: '/404' },
  { source: '/api/trace/:path*', destination: '/404' },
  { source: '/actuator/:path*', destination: '/404' },
  { source: '/api/actuator/:path*', destination: '/404' },
]

const nextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ]
  },
  async rewrites() {
    return debugPathRewrites
  },
}

export default nextConfig
