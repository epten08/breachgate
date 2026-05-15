/**
 * Intentionally Vulnerable Admin Panel
 *
 * Vulnerability: Authorization enforced only in the browser.
 * An attacker can set localStorage.user_role = "admin" in DevTools and bypass
 * this gate entirely. Authorization must be enforced server-side.
 */

import { getCurrentUser } from '../services/auth'

export function AdminPanel() {
  const user = getCurrentUser()

  // [VULN] Client-side role check — trivially bypassed via DevTools
  if (user && user.role === 'admin') {
    return (
      <div className="admin-panel">
        <h3>Admin Controls</h3>
        <p>Sensitive admin content visible here — bypassed by setting localStorage.user_role = "admin"</p>
        <button>Delete All Users</button>
        <button>Export Database</button>
      </div>
    )
  }

  return (
    <div className="admin-panel admin-panel--denied">
      <p>Access denied. Set <code>localStorage.user_role = &quot;admin&quot;</code> in DevTools to bypass.</p>
    </div>
  )
}
