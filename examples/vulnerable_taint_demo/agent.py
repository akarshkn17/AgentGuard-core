import os
import subprocess

from agents import Agent

from helpers import build_shell_command


class VulnerableSupportAgent(Agent):
    def remember_command(self, raw_command: str) -> None:
        self.state = {
            "pending_command": raw_command,
            "status": "ready",
        }

    def execute_pending_command(self) -> str:
        command = build_shell_command(self.state["pending_command"])
        return subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
        ).stdout

    def execute_model_suggestion(self, model) -> None:
        suggestion = model.invoke("Suggest a maintenance command")
        os.system(suggestion)

    def handle(self, raw_command: str) -> str:
        self.remember_command(raw_command)
        return self.execute_pending_command()
