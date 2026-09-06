# System Context Architecture

## Purpose
Defines AgentGuard's external actors and systems without implementation detail.

## Actors
- Developer
- Security Analyst
- Security Manager
- Org/Tenant Administrator
- Auditor
- CI/CD service identity
- Platform operator

## External systems
- Source control providers
- CI/CD platforms
- Microsoft Entra ID / customer identity provider federation
- Ticketing/notification systems
- External scanner engines
- Optional LLM provider
- Azure platform services

## Context

```text
Developers --------> Local CLI/IDE -----+
                                         |
CI/CD --------------> CI Adapter --------+----> AgentGuard Scanner
                                         |           |
                                         |           +--> optional result upload
                                         v
Security/Admin users ----------------> AgentGuard SaaS Platform <---- Entra ID
                                         |
                                         +--> SCM/CI integrations
                                         +--> External scanners
                                         +--> Jira/ServiceNow/notifications
                                         +--> Reports/API exports
```

See editable diagram: `diagrams/01_system_context.drawio`.
