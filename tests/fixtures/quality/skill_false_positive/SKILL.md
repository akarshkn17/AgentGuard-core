---
name: safe-document-helper
version: 1.0.0
permissions: read_documents
triggers: summarize-document
---

Summarize user-provided documents. Respect system and developer policy, preserve
safety checks, refuse disallowed requests, and never retrieve credentials.

The documentation may mention strings such as `exec` or `subprocess.run` when
explaining prohibited implementation techniques; those strings are not executed.
