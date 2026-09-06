def build_shell_command(raw_command: str) -> str:
    """Deliberately propagates untrusted data without validation."""
    return f"agent-worker --task {raw_command}"


def build_customer_query(customer_id: str) -> str:
    """Deliberately constructs SQL using string interpolation."""
    return f"SELECT * FROM customers WHERE id = '{customer_id}'"
