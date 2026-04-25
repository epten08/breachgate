# Multi-Role Scanning

Many APIs behave differently for different user roles. An IDOR vulnerability that only an authenticated user can trigger won't be found by an unauthenticated scan. Multi-role scanning runs dynamic and AI scanners once per configured role.

## When to Use It

Use multi-role scanning when your API has:
- Role-based access control (admin vs. regular user vs. anonymous)
- Endpoints that return different data based on the caller's identity
- Authorization checks that need to be tested from multiple perspectives

Static and container scanners run once (they don't depend on auth). Dynamic (ZAP) and AI scanners run once per role.

## Configuration

### Simple JWT + API Key Combo

```yaml
auth:
  type: jwt          # Default type for roles that don't specify one
  roles:
    - name: anonymous
      type: none     # No credentials

    - name: user
      token: ${USER_JWT}   # Regular user JWT

    - name: admin
      type: apikey
      apiKey: ${ADMIN_API_KEY}
      headerName: X-Admin-Key
```

### Session Cookie + Custom Headers

```yaml
auth:
  type: session
  roles:
    - name: guest
      type: none

    - name: member
      cookieName: session_id
      cookieValue: ${MEMBER_SESSION}
      headers:
        X-Membership-Tier: standard

    - name: premium
      cookieName: session_id
      cookieValue: ${PREMIUM_SESSION}
      headers:
        X-Membership-Tier: premium
```

### Dynamic Tokens via Pre-Scan Hook

If your tokens are short-lived (e.g., OAuth), use a pre-scan hook to fetch them:

```yaml
auth:
  type: jwt
  roles:
    - name: user
      preScan:
        command: scripts/get-token.sh
        args: [user]
        output: raw         # stdout is the raw token value

    - name: admin
      preScan:
        command: node
        args: [scripts/get-token.js, admin]
        output: json        # stdout is JSON
        tokenField: access_token
```

`scripts/get-token.js` would look like:

```js
const role = process.argv[2];
const token = await fetchToken(role);
console.log(JSON.stringify({ access_token: token }));
```

## What Happens During the Scan

1. Static and container scanners run once with the first role's credentials.
2. Dynamic (ZAP) and AI scanners run independently for each role.
3. Findings from each role are tagged with the role name (visible in reports).
4. The verdict considers findings across all roles.

## Reading Multi-Role Reports

Each finding in the JSON report includes a `role` field:

```json
{
  "title": "Broken Access Control",
  "endpoint": "GET /api/users/:id",
  "role": "user",
  "category": "Broken Access Control"
}
```

If a finding only appears for one role, that's a clue: the vulnerability may only be reachable with those credentials, or the fix may need to be role-specific.

## Environment Setup

Store credentials in `.env` and reference them with `${ENV_VAR}` in the config:

```bash
# .env
USER_JWT=eyJhbGciOiJIUzI1NiJ9...
ADMIN_API_KEY=sk_live_abc123
MEMBER_SESSION=sess_xyz789
PREMIUM_SESSION=sess_abc000
```

Never commit real credentials to your config file. The `${ENV_VAR}` syntax is interpolated at runtime.
