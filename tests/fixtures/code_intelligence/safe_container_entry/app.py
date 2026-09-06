import os


def run(model):
    payload = {
        "danger": model.invoke("next command"),
        "safe": "status",
    }
    os.system(payload["safe"])
    entries = [model.invoke("another command"), "version"]
    os.system(entries[1])
