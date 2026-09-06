import os

ALLOWED = {"status", "version"}


def require_allowed(value):
    if value not in ALLOWED:
        raise ValueError("not allowed")
    return value


def run(model):
    command = require_allowed(model.invoke("next command"))
    os.system(command)
