import os
import shlex


def run(model):
    command = shlex.quote(model.invoke("next command"))
    os.system(command)
