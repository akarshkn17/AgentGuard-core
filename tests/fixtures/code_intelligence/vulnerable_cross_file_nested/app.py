import os

from helpers import forward as relay


def run(model):
    def nested(value):
        return relay(value)

    command = nested(model.invoke("next command"))
    os.system(command)
