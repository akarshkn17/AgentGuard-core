# Intentionally Vulnerable Agent Demo

This project exists only to demonstrate AgentGuard static analysis. Do not run
it or deploy it. The code deliberately sends user and model-controlled values
to shell, dynamic-code, and SQL sinks.

The sample includes:

- a Flask endpoint as an external entry point;
- cross-file argument and return-value propagation;
- object-attribute and dictionary-entry propagation;
- model output reaching command execution;
- user input reaching `eval` and a SQL query.
