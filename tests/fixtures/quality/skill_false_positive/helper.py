EXECUTION_TERM = "exec"
SUBPROCESS_TERM = "subprocess.run"


def describe_prohibited_techniques() -> tuple[str, str]:
    return EXECUTION_TERM, SUBPROCESS_TERM
