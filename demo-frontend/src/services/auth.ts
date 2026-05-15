/**
 * Intentionally Vulnerable Auth Service
 *
 * Vulnerabilities demonstrated:
 *   - Hardcoded API credentials (CWE-798)
 *   - Auth tokens stored in localStorage (CWE-922)
 *   - Insecure HTTP endpoint for auth calls (CWE-319)
 *
 * DO NOT use patterns from this file in production.
 */

// [VULN] Hardcoded secrets — rotate immediately if real; store in env vars
const apiKey = 'sk_live_breachgate_demo_1234567890abcdef'
const clientSecret = 'client_secret_breachgate_demo_abcdef123456'

export interface User {
  username: string
  role: 'admin' | 'user' | 'guest'
}

export interface LoginResponse {
  token: string
  refreshToken: string
  role: string
}

// [VULN] Returns the auth token from localStorage — XSS can read this
export function getStoredToken(): string | null {
  return localStorage.getItem('token')
}

// [VULN] Role stored in localStorage — trivially tampered by an attacker
export function getCurrentUser(): User | null {
  const username = localStorage.getItem('username')
  const role = localStorage.getItem('user_role') as User['role'] | null
  if (!username || !role) return null
  return { username, role }
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  // [VULN] Insecure HTTP — credentials sent in plaintext over an unencrypted connection
  const response = await fetch('http://api.example.com/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
      'X-Client-Secret': clientSecret,
    },
    body: JSON.stringify({ username, password }),
  })

  const data = (await response.json()) as LoginResponse

  // [VULN] Auth tokens written to localStorage — readable by any script on the page
  localStorage.setItem('token', data.token)
  localStorage.setItem('auth_token', data.token)
  localStorage.setItem('username', username)
  localStorage.setItem('user_role', data.role)

  return data
}

export function logout(): void {
  localStorage.removeItem('token')
  localStorage.removeItem('auth_token')
  localStorage.removeItem('username')
  localStorage.removeItem('user_role')
}

// [VULN] Client-side admin check — server must enforce this, not the browser
export function isAdmin(): boolean {
  const user = getCurrentUser()
  if (user && user.role === 'admin') {
    return true
  }
  return false
}
