# VibeChecker 🔍

**Free Vibe Coding Security Scanner & Solo Founder Tools**

[![Deploy with Dokploy](https://img.shields.io/badge/Deploy-Dokploy-blue)](https://dokploy.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> *Ship faster. Audit smarter.*

VibeChecker is a free security scanner designed for solo founders and developers building apps with vibe-coding tools (Lovable, Cursor, Bolt, v0, etc.). Find critical vulnerabilities before they become breaches.

## ✨ Features

### Security Scanner
- **GitHub Repository Scanner** - Scan public repos for exposed secrets, vulnerable patterns, and security misconfigurations
- **Website Scanner** - Analyze websites for missing security headers, exposed paths, and vulnerabilities
- **50+ Security Checks** - Coverage including OWASP Top 10 patterns
- **Instant Results** - Get actionable findings in seconds
- **No Signup Required** - Start scanning immediately, no account needed

### Solo Founder Tools (Coming Soon)
- Startup Cost Calculator
- Pricing Calculator
- Burn Rate Calculator
- Invoice Generator

## 🚀 Quick Start

### Local Development

```bash
# Clone the repository (note: GitHub repo was renamed to `vibecode-scanner` in Sep 2026)
git clone https://github.com/iamtweaks/vibecode-scanner.git
cd vibecode-scanner

# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Deploy with Dokploy

1. Connect your GitHub repository to [Dokploy](https://dokploy.com)
2. Configure the build settings:
   - **Build Command:** `npm run build`
   - **Node Version:** `20`
   - **Output Directory:** `standalone`
3. Add environment variables (if needed):
   - `GITHUB_TOKEN` - Optional, for higher GitHub API rate limits
4. Deploy!

## 📁 Project Structure

```
vibe-checker/
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── page.tsx           # Landing page
│   │   ├── layout.tsx        # Root layout
│   │   └── api/               # API routes
│   ├── components/            # React components
│   └── lib/                   # Utilities & scanners
├── docs/                      # Documentation
├── SPEC.md                    # MVP Specification
├── PRD.md                     # Product Requirements
├── ARCHITECTURE.md            # Technical Architecture
└── README.md
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [SPEC.md](SPEC.md) | MVP specification and feature details |
| [PRD.md](PRD.md) | Product requirements and vision |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Technical architecture and design |
| [docs/scan-rules.md](docs/scan-rules.md) | Security rules and detection patterns |

## 🛡️ Security Rules

### GitHub Scanner Rules

| Rule ID | Description | Severity |
|---------|-------------|----------|
| SEC-001 | API Key Detected | 🔴 Critical |
| SEC-002 | Private Key Detected | 🔴 Critical |
| SEC-003 | .env File Exposed | 🔴 Critical |
| SEC-004 | Hardcoded Password | 🟠 High |
| SEC-005 | Outdated Dependency | 🟡 Medium |
| SEC-006 | Eval Usage | 🟠 High |
| SEC-007 | Console.log Debug | 🟢 Low |
| SEC-008 | SQL Injection Pattern | 🔴 Critical |
| SEC-009 | XSS Vulnerability | 🟠 High |
| SEC-010 | CORS Misconfiguration | 🟡 Medium |

### Website Scanner Rules

| Rule ID | Description | Severity |
|---------|-------------|----------|
| WEB-001 | Missing CSP Header | 🟡 Medium |
| WEB-002 | Missing HSTS Header | 🟠 High |
| WEB-003 | X-Frame-Options Missing | 🟡 Medium |
| WEB-004 | .env File Accessible | 🔴 Critical |
| WEB-005 | .git Directory Accessible | 🟠 High |
| WEB-006 | Admin Panel Exposed | 🟠 High |
| WEB-007 | Debug Endpoints | 🟠 High |
| WEB-008 | Mixed Content | 🟡 Medium |

## 🌐 REST API

VibeChecker provides a REST API for programmatic access.

### Base URL

```
https://vibecheck.dev/api
```

### Endpoints

#### POST /scan

Perform a security scan on a GitHub repository or website.

**Request Headers**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | Must be `application/json` |
| `Authorization` | No | Bearer token for GitHub private repos |
| `X-API-Key` | No | API key for authenticated requests |

**Request Body**

```json
{
  "url": "https://github.com/user/repo",
  "type": "github"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | Target URL (GitHub repo or website) |
| `type` | string | Yes | Scan type: `"github"` or `"website"` |
| `apiKey` | string | No | GitHub token for private repos |

**Example Request**

```bash
curl -X POST https://vibecheck.dev/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://github.com/iamtweaks/vibecode-scanner",
    "type": "github"
  }'
```

**Success Response**

```json
{
  "success": true,
  "scanId": "550e8400-e29b-41d4-a716-446655440000",
  "type": "github",
  "targetUrl": "https://github.com/iamtweaks/vibecode-scanner",
  "status": "completed",
  "findings": [
    {
      "id": "sec-001",
      "ruleId": "SEC-001",
      "severity": "critical",
      "title": "API Key Detected",
      "description": "Potential API key found in source code",
      "filePath": "src/config.js",
      "lineNumber": 42,
      "snippet": "const API_KEY = 'ghp_xxxx'",
      "remediation": "Remove hardcoded secrets and use environment variables"
    }
  ],
  "severityCounts": {
    "critical": 1,
    "high": 0,
    "medium": 2,
    "low": 5,
    "info": 10
  },
  "scannedAt": "2026-05-12T17:10:00Z",
  "scannedFiles": 150,
  "scanDuration": 3200
}
```

#### GET /scan/:id

Retrieve a scan result by its ID.

**Example Request**

```bash
curl https://vibecheck.dev/api/scan/550e8400-e29b-41d4-a716-446655440000
```

**Success Response**

Same as POST response with `success: true`.

#### GET /scan

List recent scans (for debugging).

**Query Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | number | 10 | Max number of scans to return (max 100) |

**Example Request**

```bash
curl "https://vibecheck.dev/api/scan?limit=5"
```

### Response Format

All responses include a `success` boolean field indicating whether the request succeeded.

**Error Response**

```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "code": "RATE_LIMITED",
  "retryAfter": 30000
}
```

**Error Codes**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `URL_REQUIRED` | 400 | URL field is missing |
| `TYPE_REQUIRED` | 400 | Type field is missing |
| `INVALID_TYPE` | 400 | Type must be "github" or "website" |
| `INVALID_JSON` | 400 | Request body is not valid JSON |
| `INVALID_API_KEY` | 401 | API key is invalid |
| `RATE_LIMITED` | 429 | Too many requests |
| `REPO_NOT_FOUND` | 404 | GitHub repo not found or private |
| `GITHUB_RATE_LIMIT` | 429 | GitHub API rate limit exceeded |
| `SCAN_FAILED` | 500 | Scan processing failed |

### Rate Limits

- **20 requests per minute** per IP address
- **500ms** minimum interval between requests
- Rate limit info returned in headers:
  - `X-RateLimit-Remaining`: Requests remaining
  - `Retry-After`: Seconds until rate limit resets

### SDK Examples

**Node.js**

```javascript
const response = await fetch('https://vibecheck.dev/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'https://github.com/user/repo',
    type: 'github'
  })
})
const result = await response.json()
console.log(result.scanId)
```

**Python**

```python
import requests

response = requests.post('https://vibecheck.dev/api/scan', json={
    'url': 'https://github.com/user/repo',
    'type': 'github'
})
result = response.json()
print(result['scanId'])
```

## 💰 Pricing

| Feature | Free | Pro |
|---------|------|-----|
| Scans per day | 3 | Unlimited |
| GitHub Scanner | ✅ | ✅ |
| Website Scanner | ✅ | ✅ |
| OWASP Top 10 | Limited | Full |
| PDF Reports | - | ✅ |
| Scan History | - | ✅ |
| API Access | - | ✅ |
| **Price** | **Free** | **$19/mo** |

## 🔧 Development

### Tech Stack
- **Framework:** Next.js 14 (App Router)
- **Language:** TypeScript
- **Styling:** Tailwind CSS + shadcn/ui
- **Icons:** Lucide React

### Scripts

```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run start        # Start production server
npm run lint         # Run ESLint
npm run type-check   # Run TypeScript checks
```

### Environment Variables

```env
# Optional - for higher GitHub API rate limits
GITHUB_TOKEN=ghp_xxxx

# Not required for MVP
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Issues and PRs are welcome at [github.com/iamtweaks/vibecode-scanner/issues](https://github.com/iamtweaks/vibecode-scanner/issues).

**Best ways to contribute:**

- **Report a vulnerability scanner bug** — open an issue with the URL you scanned, the rule ID that fired (or didn't), and what you expected.
- **Suggest a new security check** — open an issue with the pattern you want detected (OWASP category, sample input that should trigger). If it's OWASP Top 10 related, label it `good-first-issue`.
- **Improve rule accuracy** — false positives waste everyone's time. Send a PR with the test case + the rule change.
- **UI / UX polish** — design improvements and a11y fixes are welcome via PR.
- **Docs** — typos, broken links, missing setup steps: send a PR.

**Don't open issues for:** deployment problems on your own fork (use Vercel/Dokploy support), reports about specific scanner results that should go to the site owner (use the scanner's report form, not this repo), or generic security questions (use OWASP / CERT directly).

Labels we use: `bug`, `enhancement`, `new-rule`, `docs`, `good-first-issue`, `a11y`.

## 🙏 Acknowledgments

- Inspired by [Notelon.ai](https://notelon.ai/) - The original vibe coding security scanner
- Built with Next.js, Tailwind CSS, and love
- Security rules based on OWASP Top 10 and industry best practices

## 💛 Donations / Sponsors

If VibeChecker helped you catch a vulnerability before shipping, donations are
welcome via Solana (mainnet):

```
8ZNN5bomP4SVfDthfcFgXBSoZAgtngZAcKscddhoPrGA
```

That's a personal Phantom wallet address (non-custodial — I hold the keys).
Verify the address matches exactly before sending; on-chain transactions
are irreversible. SPL tokens accepted (SOL, USDC, etc.).

---

**Made for solo founders who ship fast.** 🚀
