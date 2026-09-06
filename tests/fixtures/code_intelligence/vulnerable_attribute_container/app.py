import os


class Worker:
    def capture(self, model):
        self.payload = {
            "command": model.invoke("next command"),
            "safe": "status",
        }

    def execute(self):
        os.system(self.payload["command"])
        commands = [self.payload["command"], "status"]
        os.system(commands[0])


worker = Worker()
worker.capture(model)
worker.execute()
