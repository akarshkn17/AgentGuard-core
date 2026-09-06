# Future Authentication Design for CLI and CI/CD

Authentication is intentionally **not implemented** in this build. Local scanning does not need authentication.

## Boundary rule

```text
agentguard-core       NEVER authenticates
agentguard-cli        local scan = no auth
agentguard-cli cloud  future optional client/auth module
GitHub CI local scan  no auth
GitHub CI upload      future workload identity / short-lived token
SaaS API              validates identity and tenant authorization
```

Do not add Entra ID, OAuth libraries, API keys, JWT validation, or cloud SDKs to `agentguard-core`.

## Human developer authentication later

When SaaS upload/registry features exist, add commands such as:

```text
agentguard login
agentguard auth status
agentguard logout
agentguard scan . --upload
agentguard upload agentguard-result.json
```

Preferred flow:

1. CLI starts OIDC/OAuth **Authorization Code + PKCE** where a browser is available, or **Device Authorization** for headless terminals.
2. Identity provider authenticates the user.
3. CLI receives short-lived access/refresh credentials scoped to the AgentGuard API.
4. Refresh credentials are stored in the operating-system credential store/keychain, not in `.agentguard.yml` or source control.
5. SaaS validates issuer, audience, expiry, tenant/user claims, and authorization at the API boundary.

The CLI should send only the short-lived access token to the platform. The scanner core must not see it.

## GitHub Actions authentication later

For SaaS result upload, prefer **GitHub OIDC workload identity** rather than static customer API keys:

```text
GitHub Actions job
  -> GitHub OIDC token (id-token: write)
  -> AgentGuard /token/exchange
  -> validate issuer/audience/repository/ref/environment
  -> short-lived AgentGuard workload token
  -> upload ScanResult / reports
```

Example future workflow permission:

```yaml
permissions:
  contents: read
  id-token: write
```

Platform-side trust policies should bind the workload to allowed repository/org/ref/environment claims. A production workflow should not accept arbitrary repositories simply because they can obtain a GitHub OIDC token.

### Fallback

If OIDC federation is not possible, use a revocable service credential stored in GitHub Environments/Secrets. Keep it narrowly scoped, rotate it, never echo it, and never put it into a CLI config committed with the repository.

## Why auth belongs above Core

A customer may want all of these at the same time:

- completely offline local scanning;
- CI scanning without sending source/results anywhere;
- authenticated upload of only the normalized result;
- future hosted scan jobs.

Keeping authentication in the adapter/platform layer supports every model without forking the scanner engine.
