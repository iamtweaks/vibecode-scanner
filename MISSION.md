# MISSION — vibe-checker

> Scanner de seguridad gratuito orientado a founders y devs que shippean con herramientas de vibe-coding (Lovable, Cursor, Bolt, v0). Detecta secretos expuestos, secretos hardcodeados, headers faltantes y patrones OWASP Top 10 en repos públicos de GitHub y websites.

**Owner:** iamtweaks
**Date:** 2026-09-13

## Es

- Escanear repos públicos de GitHub en busca de secrets hardcodeados, archivos `.env` expuestos, dependencias vulnerables y patrones OWASP Top 10.
- Escanear websites públicos en busca de headers de seguridad faltantes (CSP, HSTS, X-Frame-Options), paths expuestos (`.env`, `.git`, admin panels) y debug endpoints.
- Devolver findings accionables con severidad, snippet, file:line y remediación concreta — sin ruido, sin PDF marketing.
- Ofrecer una API REST pública (`POST /scan`, `GET /scan/:id`, `GET /scan`) con rate limiting por IP.

## NO es

- **NO es un SAST / DAST que analiza código privado del usuario** — solo escanea lo que ya es público (repos públicos de GitHub y websites accesibles).
- **NO es un vulnerability scanner de infraestructura (nmap, port scan, pentest activo)** — el target es un repo URL o una website URL, no una IP ni un host con credenciales.
- **NO es un WAF / runtime protection / RASP** — no se deploya, no intercepta tráfico, no protege apps en producción.
- **NO es un dependency-only scanner (Snyk / Dependabot)** — los outdated deps son una de 50 reglas, no el producto.
- **NO es un SaaS pago con cuentas, planes Pro, billing, ni dashboard por organización** — el tier gratis es el producto; Pro/PDF/history son stretch, no core.
- **NO es un compliance scanner (SOC2, ISO 27001, HIPAA, PCI-DSS)** — los hallazgos son accionables por un dev, no evidencia de auditoría.
- **NO es un LLM-based "security copilot" ni chatbot** — los findings vienen de reglas determinísticas (regex + patterns), no de un modelo.
- **NO es "Startup Cost Calculator / Pricing Calculator / Burn Rate / Invoice Generator"** — esos ítems "Coming Soon" del README son stretch y no son parte del scanner; si entran, van en un producto separado.

## Reglas

- **Cero cuentas. Cero signup.** Cualquier feature que pida email, OAuth o login queda afuera del MVP.
- **Determinístico > LLM.** Cada finding debe mapear a un `ruleId` concreto con regex/pattern explícito; nada de "esto parece sospechoso porque el LLM dijo".
- **Solo blanco (no intrusivo).** No fuzzing activo, no brute force, no escaneo de puertos; solo GET sobre URLs públicas y clonación de repos públicos.
