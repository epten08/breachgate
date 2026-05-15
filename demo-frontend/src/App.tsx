/**
 * BreachGate Vulnerable Frontend Demo
 *
 * This app intentionally contains the following vulnerabilities:
 *   1. Auth tokens stored in localStorage          (Semgrep: localstorage-auth-token)
 *   2. dangerouslySetInnerHTML with API content    (Semgrep: react-dangerous-html)
 *   3. Client-side role-based access control       (Semgrep: client-side-role-check)
 *   4. Insecure HTTP API calls                     (Semgrep: insecure-http-fetch)
 *   5. Hardcoded API credentials                   (Semgrep: hardcoded-secret-var, Gitleaks)
 *   6. eval() usage                                (Semgrep: eval-usage)
 *   7. postMessage with wildcard origin            (Semgrep: postmessage-wildcard-origin)
 *   8. innerHTML assignment from external data     (Semgrep: innerhtml-assignment)
 *
 * Run: breach-gate scan --frontend --frontend-path .
 */

import { useState } from 'react'
import { login, logout, getCurrentUser } from './services/auth'
import { searchContent, notifyWidget } from './services/api'
import { SearchResults } from './components/SearchResults'
import { AdminPanel } from './components/AdminPanel'
import './App.css'

export default function App() {
  const [username, setUsername] = useState('demo')
  const [password, setPassword] = useState('password')
  const [authStatus, setAuthStatus] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [searchHtml, setSearchHtml] = useState('')
  const [widgetMsg, setWidgetMsg] = useState('')

  const user = getCurrentUser()

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    try {
      // [VULN] login() writes token to localStorage — see src/services/auth.ts
      await login(username, password)
      setAuthStatus(`Logged in. Token is now in localStorage — open DevTools > Application to see it.`)
    } catch {
      setAuthStatus('Login failed (demo API is not running)')
    }
  }

  function handleLogout() {
    logout()
    setAuthStatus('Logged out')
  }

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault()
    try {
      // [VULN] Server returns raw HTML — rendered via dangerouslySetInnerHTML below
      const html = await searchContent(searchQuery)
      setSearchHtml(html)
    } catch {
      // Demo: API not running, inject a mock XSS payload to show the risk
      setSearchHtml(
        `<b>Results for: ${searchQuery}</b> <img src=x onerror="console.warn('[XSS demo] dangerouslySetInnerHTML executed attacker payload')" />`
      )
    }
  }

  function handleNotifyWidget() {
    // [VULN] postMessage wildcard — see src/services/api.ts
    notifyWidget({ action: 'refresh', data: widgetMsg })
    alert('Message sent to widget with origin="*" — any page can receive this')
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>BreachGate — Vulnerable Frontend Demo</h1>
        <p className="warning">
          ⚠️ This app contains intentional security vulnerabilities for scanning demos.
          DO NOT deploy this code.
        </p>
      </header>

      {/* ── VULNERABILITY 1 & 5: Insecure auth + localStorage token storage ── */}
      <section className="vuln-card">
        <div className="vuln-badge">VULN 1 + 5</div>
        <h2>Insecure Authentication</h2>
        <p>
          <code>login()</code> calls <code>http://</code> (unencrypted) and stores the token
          in <code>localStorage</code> — readable by any XSS payload on the page.
          The API client uses a hardcoded <code>sk_live_*</code> key.
        </p>
        {user ? (
          <div>
            <p>Logged in as <strong>{user.username}</strong> ({user.role})</p>
            <button onClick={handleLogout}>Logout</button>
          </div>
        ) : (
          <form onSubmit={handleLogin}>
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Password"
            />
            <button type="submit">Login</button>
          </form>
        )}
        {authStatus && <p className="status">{authStatus}</p>}
      </section>

      {/* ── VULNERABILITY 2: dangerouslySetInnerHTML XSS ── */}
      <section className="vuln-card">
        <div className="vuln-badge">VULN 2</div>
        <h2>Cross-Site Scripting via dangerouslySetInnerHTML</h2>
        <p>
          API response HTML is injected directly without sanitization.
          Try: <code>&lt;img src=x onerror=alert(1)&gt;</code>
        </p>
        <form onSubmit={handleSearch}>
          <input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search query..."
          />
          <button type="submit">Search</button>
        </form>
        {/* [VULN] dangerouslySetInnerHTML renders whatever the server (or demo) returns */}
        {searchHtml && <SearchResults htmlContent={searchHtml} />}
      </section>

      {/* ── VULNERABILITY 3: Client-side RBAC ── */}
      <section className="vuln-card">
        <div className="vuln-badge">VULN 3</div>
        <h2>Broken Access Control — Client-Side Role Check</h2>
        <p>
          Run <code>localStorage.setItem(&apos;user_role&apos;, &apos;admin&apos;)</code> in
          DevTools then refresh to bypass this gate.
        </p>
        <AdminPanel />
      </section>

      {/* ── VULNERABILITY 7: postMessage wildcard ── */}
      <section className="vuln-card">
        <div className="vuln-badge">VULN 7</div>
        <h2>postMessage with Wildcard Origin</h2>
        <p>
          <code>postMessage(data, &apos;*&apos;)</code> sends the message to any listening page.
          A malicious iframe can intercept this data.
        </p>
        <input
          value={widgetMsg}
          onChange={e => setWidgetMsg(e.target.value)}
          placeholder="Message to widget..."
        />
        <button onClick={handleNotifyWidget}>Send to Widget</button>
        <iframe id="payment-widget" title="Payment Widget" src="about:blank" style={{ display: 'none' }} />
      </section>
    </div>
  )
}
