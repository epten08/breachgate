/**
 * Intentionally Vulnerable API Client
 *
 * Vulnerabilities demonstrated:
 *   - Insecure HTTP base URL (CWE-319)
 *   - postMessage with wildcard origin (CWE-346)
 *   - innerHTML assignment from API response (CWE-79)
 *
 * DO NOT use patterns from this file in production.
 */

import { getStoredToken } from './auth'

// [VULN] Insecure HTTP — all API traffic is unencrypted
const BASE_URL = 'http://api.example.com'

export async function searchContent(query: string): Promise<string> {
  const token = getStoredToken()

  const response = await fetch(
    `${BASE_URL}/api/search?q=${encodeURIComponent(query)}`,
    {
      headers: { Authorization: `Bearer ${token}` },
    }
  )

  // Returns raw HTML from the server — injected via dangerouslySetInnerHTML in App.tsx
  const data = (await response.json()) as { html: string }
  return data.html
}

export async function fetchUserProfile(userId: string): Promise<Record<string, unknown>> {
  const token = getStoredToken()

  // [VULN] Insecure HTTP
  const response = await fetch(`${BASE_URL}/api/users/${userId}`, {
    headers: { Authorization: `Bearer ${token}` },
  })

  return response.json() as Promise<Record<string, unknown>>
}

// [VULN] Wildcard origin leaks postMessage data to any listening page
export function notifyWidget(payload: unknown): void {
  const iframe = document.getElementById('payment-widget') as HTMLIFrameElement | null
  if (iframe?.contentWindow) {
    iframe.contentWindow.postMessage(payload, '*')
  }
}

// [VULN] innerHTML assignment — if content comes from user input or the API, this is XSS
export function renderBanner(container: HTMLElement, htmlContent: string): void {
  container.innerHTML = htmlContent
}

// [VULN] eval() — arbitrary code execution if input is user-controlled
export function runAnalytics(analyticsScript: string): unknown {
  return eval(analyticsScript)
}
