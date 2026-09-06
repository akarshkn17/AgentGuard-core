import subprocess


def fixed_status():
    return subprocess.run(
        ["agent-worker", "status"],
        shell=False,
        check=True,
    ).returncode
