import os


def run(model):
    numeric_command = int(model.invoke("numeric command"))
    os.system(str(numeric_command))
